package mastermigration

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
	"github.com/masterauguste/theatropolis/internal/webui"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func (s *Service) StageRestore(_ context.Context, archive []byte, passphrase string) (RestoreSummary, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return RestoreSummary{}, err
	}
	if len(archive) == 0 || len(archive) > maxArchiveBytes {
		return RestoreSummary{}, ErrInvalidArchive
	}
	if err := s.requireEmptyTarget(); err != nil {
		return RestoreSummary{}, err
	}
	stagePath := filepath.Join(s.StateDirectory, restoreDirectoryName)
	if _, err := os.Lstat(stagePath); err == nil {
		return RestoreSummary{}, ErrRestoreAlreadyReady
	} else if !errors.Is(err, os.ErrNotExist) {
		return RestoreSummary{}, err
	}
	manifest, payload, err := decryptArchive(archive, passphrase)
	if err != nil {
		return RestoreSummary{}, err
	}
	defer clear(payload)
	files, inner, err := decodeInnerArchive(payload, manifest.MigrationID)
	if err != nil {
		return RestoreSummary{}, err
	}
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		return RestoreSummary{}, fmt.Errorf("create migration restore stage: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stagePath)
		}
	}()

	currentAuth, err := readRegularFile(filepath.Join(s.StateDirectory, "web-auth.json"), 16<<20)
	if err != nil {
		return RestoreSummary{}, fmt.Errorf("read current administrator identity: %w", err)
	}
	mergedAuth, err := mergeUserIdentities(currentAuth, files["user-identities.json"])
	if err != nil {
		return RestoreSummary{}, err
	}
	delete(files, "user-identities.json")
	files["web-auth.json"] = mergedAuth

	for name, encoded := range files {
		path := filepath.Join(stagePath, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return RestoreSummary{}, err
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			return RestoreSummary{}, err
		}
	}
	marker := restoreMarker{Version: archiveVersion, MigrationID: inner.MigrationID, CreatedAt: inner.CreatedAt}
	markerBytes, _ := json.MarshalIndent(marker, "", "  ")
	if err := os.WriteFile(filepath.Join(stagePath, restoreMarkerName), markerBytes, 0o600); err != nil {
		return RestoreSummary{}, err
	}
	if err := validateStage(stagePath, s.Build); err != nil {
		return RestoreSummary{}, err
	}
	stateStore, err := proxynode.Open(filepath.Join(stagePath, "proxy-node-state.json"), s.Build)
	if err != nil {
		return RestoreSummary{}, err
	}
	state := stateStore.Snapshot()
	_ = stateStore.Close()
	registry, err := identity.OpenRegistry(filepath.Join(stagePath, "identities.json"))
	if err != nil {
		return RestoreSummary{}, err
	}
	keep = true
	return RestoreSummary{
		MigrationID: inner.MigrationID,
		Agents:      len(registry.Snapshot(s.now())), Users: migrationEndUserCount(state.Users), ProxyNodes: len(state.ProxyNodes),
	}, nil
}

func migrationEndUserCount(users []proxynode.User) int {
	count := 0
	for _, user := range users {
		if !proxynode.IsSystemAdministrator(user) {
			count++
		}
	}
	return count
}

func (s *Service) requireEmptyTarget() error {
	if s.ProxyNodes == nil || s.Identities == nil || s.Deployments == nil {
		return errors.New("Master migration storage is unavailable")
	}
	state := s.ProxyNodes.Snapshot()
	if migrationEndUserCount(state.Users) != 0 || len(state.ProxyNodes) != 0 || len(state.AppliedProxyNodes) != 0 {
		return ErrTargetNotEmpty
	}
	if len(s.Identities.Snapshot(s.now())) != 0 {
		return ErrTargetNotEmpty
	}
	records, err := s.Deployments.List(context.Background())
	if err != nil {
		return err
	}
	if len(records) != 0 {
		return ErrTargetNotEmpty
	}
	return nil
}

func decryptArchive(archive []byte, passphrase string) (outerManifest, []byte, error) {
	entries, err := readStoredZip(archive)
	if err != nil {
		return outerManifest{}, nil, err
	}
	if len(entries) != 2 || entries["manifest.json"] == nil || entries["payload.enc"] == nil {
		return outerManifest{}, nil, ErrInvalidArchive
	}
	var manifest outerManifest
	if err := decodeStrictJSON(entries["manifest.json"], &manifest); err != nil ||
		manifest.Version != archiveVersion || manifest.Cipher != "XChaCha20-Poly1305" || manifest.KDF != "Argon2id" ||
		manifest.KDFMemoryKiB != 64*1024 || manifest.KDFIterations != 3 || manifest.KDFParallelism != 4 {
		return outerManifest{}, nil, ErrInvalidArchive
	}
	salt, err := base64.RawURLEncoding.DecodeString(manifest.Salt)
	if err != nil || len(salt) != 32 {
		return outerManifest{}, nil, ErrInvalidArchive
	}
	nonce, err := base64.RawURLEncoding.DecodeString(manifest.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return outerManifest{}, nil, ErrInvalidArchive
	}
	ciphertext := entries["payload.enc"]
	digest := sha256.Sum256(ciphertext)
	expected, err := hex.DecodeString(manifest.PayloadSHA256)
	if err != nil || len(expected) != sha256.Size || subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return outerManifest{}, nil, ErrInvalidArchive
	}
	key := argon2.IDKey([]byte(passphrase), salt, manifest.KDFIterations, manifest.KDFMemoryKiB, manifest.KDFParallelism, chacha20poly1305.KeySize)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return outerManifest{}, nil, err
	}
	payload, err := aead.Open(nil, nonce, ciphertext, []byte(manifest.MigrationID))
	if err != nil {
		return outerManifest{}, nil, ErrInvalidPassphrase
	}
	return manifest, payload, nil
}

func decodeInnerArchive(payload []byte, migrationID string) (map[string][]byte, innerManifest, error) {
	entries, err := readStoredZip(payload)
	if err != nil {
		return nil, innerManifest{}, err
	}
	manifestBytes, ok := entries["manifest.json"]
	if !ok {
		return nil, innerManifest{}, ErrInvalidArchive
	}
	delete(entries, "manifest.json")
	var manifest innerManifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil || manifest.Version != archiveVersion || manifest.MigrationID != migrationID {
		return nil, innerManifest{}, ErrInvalidArchive
	}
	required := []string{"proxy-node-state.json", "proxy-node-accounting.sqlite", "identities.json", "outbound-pool.json", "user-identities.json"}
	for _, name := range required {
		if _, ok := entries[name]; !ok {
			return nil, innerManifest{}, ErrInvalidArchive
		}
	}
	if len(entries) != len(manifest.Files) {
		return nil, innerManifest{}, ErrInvalidArchive
	}
	for name, encoded := range entries {
		expectedText, ok := manifest.Files[name]
		if !ok {
			return nil, innerManifest{}, ErrInvalidArchive
		}
		expected, err := hex.DecodeString(expectedText)
		digest := sha256.Sum256(encoded)
		if err != nil || len(expected) != sha256.Size || subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
			return nil, innerManifest{}, ErrInvalidArchive
		}
	}
	return entries, manifest, nil
}

func mergeUserIdentities(current, imported []byte) ([]byte, error) {
	var currentDocument unifiedIdentityDocument
	if err := decodeStrictJSON(current, &currentDocument); err != nil || currentDocument.Version != 3 {
		return nil, errors.New("current Master administrator identity is not in the unified format")
	}
	var users userIdentityArchive
	if err := decodeStrictJSON(imported, &users); err != nil || users.Version != userIdentityVersion {
		return nil, ErrInvalidArchive
	}
	admins := []json.RawMessage{}
	usernames := map[string]struct{}{}
	for _, raw := range currentDocument.Identities {
		var header identityHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, err
		}
		if header.Role == "administrator" {
			admins = append(admins, append(json.RawMessage(nil), raw...))
			if header.LoginUsername != "" {
				usernames[strings.ToLower(header.LoginUsername)] = struct{}{}
			}
		}
	}
	if len(admins) != 1 {
		return nil, errors.New("current Master must contain exactly one administrator")
	}
	seenIDs := map[string]struct{}{}
	for _, raw := range users.Identities {
		var header identityHeader
		if err := json.Unmarshal(raw, &header); err != nil || header.Role != "user" || header.ID == "" {
			return nil, ErrInvalidArchive
		}
		if _, exists := seenIDs[header.ID]; exists {
			return nil, ErrInvalidArchive
		}
		seenIDs[header.ID] = struct{}{}
		if header.LoginUsername != "" {
			key := strings.ToLower(header.LoginUsername)
			if _, exists := usernames[key]; exists {
				return nil, errors.New("an imported user login conflicts with the new Master administrator")
			}
			usernames[key] = struct{}{}
		}
	}
	merged := unifiedIdentityDocument{Version: 3, Identities: append(admins, users.Identities...)}
	return json.MarshalIndent(merged, "", "  ")
}

func validateStage(path string, build proxynode.BuildInfo) error {
	if _, err := identity.OpenRegistry(filepath.Join(path, "identities.json")); err != nil {
		return fmt.Errorf("validate migrated identities: %w", err)
	}
	if _, err := pool.Open(filepath.Join(path, "outbound-pool.json")); err != nil {
		return fmt.Errorf("validate migrated pool: %w", err)
	}
	if _, err := deployment.NewDiskStore(filepath.Join(path, "deployments")); err != nil {
		return fmt.Errorf("validate migrated deployments: %w", err)
	}
	store, err := proxynode.Open(filepath.Join(path, "proxy-node-state.json"), build)
	if err != nil {
		return fmt.Errorf("validate migrated Proxy Nodes: %w", err)
	}
	if err := store.Close(); err != nil {
		return err
	}
	if err := webui.ValidateUnifiedWebAccessFile(filepath.Join(path, "web-auth.json")); err != nil {
		return fmt.Errorf("validate migrated user identities: %w", err)
	}
	return nil
}

// ApplyPendingRestore installs a fully validated staged restore before any
// runtime store is opened. The current administrator is already embedded in
// the staged web-auth document; browser sessions are intentionally retired.
func ApplyPendingRestore(stateDirectory string) (string, bool, error) {
	stagePath := filepath.Join(stateDirectory, restoreDirectoryName)
	markerBytes, err := readRegularFile(filepath.Join(stagePath, restoreMarkerName), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("inspect staged Master migration: %w", err)
	}
	var marker restoreMarker
	if err := decodeStrictJSON(markerBytes, &marker); err != nil || marker.Version != archiveVersion || marker.MigrationID == "" {
		return "", false, ErrInvalidArchive
	}
	backupPath := filepath.Join(stateDirectory, ".master-migration-backup-"+marker.MigrationID)
	if err := os.Mkdir(backupPath, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", false, err
	}
	// This is an idempotent forward transaction. The restore marker remains in
	// place until every rename succeeds, so a power loss or process termination
	// simply resumes the same installation on the next Master start.
	installTargets := []string{"proxy-node-state.json", "proxy-node-accounting.sqlite", "identities.json", "outbound-pool.json", "web-auth.json", "deployments"}
	for _, name := range installTargets {
		live := filepath.Join(stateDirectory, name)
		staged := filepath.Join(stagePath, name)
		backup := filepath.Join(backupPath, name)
		stagedExists, err := pathExists(staged)
		if err != nil {
			return "", false, err
		}
		if !stagedExists {
			// An earlier attempt already installed this target.
			if liveExists, statErr := pathExists(live); statErr != nil {
				return "", false, statErr
			} else if !liveExists {
				return "", false, fmt.Errorf("resume Master migration: %s is missing", name)
			}
			continue
		}
		backupExists, err := pathExists(backup)
		if err != nil {
			return "", false, err
		}
		liveExists, err := pathExists(live)
		if err != nil {
			return "", false, err
		}
		if backupExists && liveExists {
			return "", false, fmt.Errorf("resume Master migration: conflicting live and backup copies for %s", name)
		}
		if liveExists {
			if err := os.Rename(live, backup); err != nil {
				return "", false, err
			}
		}
		if err := os.Rename(staged, live); err != nil {
			return "", false, err
		}
	}
	for _, name := range []string{"web-sessions.json", "end-user-sessions.json", "end-user-auth.json"} {
		live := filepath.Join(stateDirectory, name)
		backup := filepath.Join(backupPath, name)
		liveExists, err := pathExists(live)
		if err != nil {
			return "", false, err
		}
		backupExists, err := pathExists(backup)
		if err != nil {
			return "", false, err
		}
		if liveExists && backupExists {
			return "", false, fmt.Errorf("resume Master migration: conflicting retired copies for %s", name)
		}
		if liveExists {
			if err := os.Rename(live, backup); err != nil {
				return "", false, err
			}
		}
	}
	if err := syncDirectory(stateDirectory); err != nil {
		return "", false, err
	}
	if err := os.Remove(filepath.Join(stagePath, restoreMarkerName)); err != nil {
		return "", false, err
	}
	if err := os.Remove(stagePath); err != nil {
		return "", false, err
	}
	if err := syncDirectory(stateDirectory); err != nil {
		return "", false, err
	}
	return backupPath, true, nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
