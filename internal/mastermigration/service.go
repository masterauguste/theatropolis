package mastermigration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/pool"
	"github.com/masterauguste/theatropolis/internal/proxynode"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	archiveVersion       = 1
	userIdentityVersion  = 1
	maxArchiveBytes      = 128 << 20
	maxArchiveFileBytes  = 96 << 20
	minimumPassphraseLen = 15
	restoreDirectoryName = ".master-migration-restore"
	restoreMarkerName    = "restore.json"
)

var (
	ErrTargetNotEmpty      = errors.New("migration restore requires a new Master with no fleet data")
	ErrInvalidArchive      = errors.New("invalid Master migration archive")
	ErrInvalidPassphrase   = errors.New("migration passphrase is invalid")
	ErrRestoreAlreadyReady = errors.New("a Master migration restore is already staged")
	ErrSnapshotBusy        = errors.New("Master data changed while the migration snapshot was being created")
)

type Service struct {
	StateDirectory string
	Version        string
	Build          proxynode.BuildInfo
	ProxyNodes     *proxynode.Store
	Identities     *identity.Registry
	Deployments    *deployment.DiskStore
	Pool           *pool.Registry
	Now            func() time.Time
}

type ExportResult struct {
	Filename string
	Data     []byte
}

type RestoreSummary struct {
	MigrationID string
	Agents      int
	Users       int
	ProxyNodes  int
}

type outerManifest struct {
	Version        int    `json:"version"`
	MigrationID    string `json:"migration_id"`
	CreatedAt      string `json:"created_at"`
	Cipher         string `json:"cipher"`
	KDF            string `json:"kdf"`
	KDFMemoryKiB   uint32 `json:"kdf_memory_kib"`
	KDFIterations  uint32 `json:"kdf_iterations"`
	KDFParallelism uint8  `json:"kdf_parallelism"`
	Salt           string `json:"salt"`
	Nonce          string `json:"nonce"`
	PayloadSHA256  string `json:"payload_sha256"`
}

type innerManifest struct {
	Version     int               `json:"version"`
	MigrationID string            `json:"migration_id"`
	CreatedAt   string            `json:"created_at"`
	Source      string            `json:"source_version"`
	Files       map[string]string `json:"files_sha256"`
}

type restoreMarker struct {
	Version     int    `json:"version"`
	MigrationID string `json:"migration_id"`
	CreatedAt   string `json:"created_at"`
}

type userIdentityArchive struct {
	Version    int               `json:"version"`
	Identities []json.RawMessage `json:"identities"`
}

type unifiedIdentityDocument struct {
	Version    int               `json:"version"`
	Identities []json.RawMessage `json:"identities"`
}

type identityHeader struct {
	ID            string `json:"id"`
	Role          string `json:"role"`
	LoginUsername string `json:"login_username"`
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) Export(ctx context.Context, passphrase string) (ExportResult, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return ExportResult{}, err
	}
	if s.ProxyNodes == nil || s.Identities == nil || s.Deployments == nil || s.Pool == nil {
		return ExportResult{}, errors.New("Master migration storage is unavailable")
	}
	migrationID, err := randomID()
	if err != nil {
		return ExportResult{}, err
	}
	createdAt := s.now()
	files, err := s.snapshotFiles(ctx)
	if err != nil {
		return ExportResult{}, err
	}
	inner, err := encodeInnerArchive(migrationID, createdAt, s.Version, files)
	if err != nil {
		return ExportResult{}, err
	}
	outer, err := encryptArchive(migrationID, createdAt, passphrase, inner)
	clear(inner)
	if err != nil {
		return ExportResult{}, err
	}
	return ExportResult{
		Filename: fmt.Sprintf("theatropolis-master-%s-%s.zip", createdAt.Format("20060102-150405"), migrationID),
		Data:     outer,
	}, nil
}

func (s *Service) snapshotFiles(ctx context.Context) (map[string][]byte, error) {
	// The stores have independent locks because normal topology, identity,
	// deployment, and user-plane work must not share one global mutex. Take two
	// complete snapshots and accept them only when every byte agrees. This gives
	// export a quiescent cross-store view without pausing the control plane for
	// the comparatively expensive encryption step.
	var previous map[string][]byte
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current, err := s.snapshotFilesOnce()
		if err != nil {
			return nil, err
		}
		if previous != nil && equalSnapshotFiles(previous, current) {
			return current, nil
		}
		previous = current
	}
	return nil, ErrSnapshotBusy
}

func (s *Service) snapshotFilesOnce() (map[string][]byte, error) {
	if err := s.requireNoTopologyTransaction(); err != nil {
		return nil, err
	}
	proxyState, accounting, err := s.ProxyNodes.MigrationSnapshot()
	if err != nil {
		return nil, err
	}
	identities, err := s.Identities.MigrationSnapshot()
	if err != nil {
		return nil, err
	}
	poolState, err := s.Pool.MigrationSnapshot()
	if err != nil {
		return nil, err
	}
	deployments, err := s.Deployments.MigrationSnapshot()
	if err != nil {
		return nil, err
	}
	users, err := exportUserIdentities(filepath.Join(s.StateDirectory, "web-auth.json"))
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"proxy-node-state.json":        proxyState,
		"proxy-node-accounting.sqlite": accounting,
		"identities.json":              identities,
		"outbound-pool.json":           poolState,
		"user-identities.json":         users,
	}
	for name, encoded := range deployments {
		files[filepath.ToSlash(filepath.Join("deployments", name))] = encoded
	}
	if err := s.requireNoTopologyTransaction(); err != nil {
		return nil, err
	}
	return files, nil
}

func (s *Service) requireNoTopologyTransaction() error {
	active, err := s.ProxyNodes.HasActiveTopologyTransaction()
	if err != nil {
		return fmt.Errorf("inspect active topology transaction: %w", err)
	}
	if active {
		return ErrSnapshotBusy
	}
	return nil
}

func equalSnapshotFiles(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for name, encoded := range left {
		if !bytes.Equal(encoded, right[name]) {
			return false
		}
	}
	return true
}

func exportUserIdentities(path string) ([]byte, error) {
	encoded, err := readRegularFile(path, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("read unified web identities: %w", err)
	}
	var document unifiedIdentityDocument
	if err := decodeStrictJSON(encoded, &document); err != nil || document.Version != 3 {
		return nil, fmt.Errorf("read unified web identities: unsupported identity document")
	}
	users := userIdentityArchive{Version: userIdentityVersion, Identities: []json.RawMessage{}}
	for _, raw := range document.Identities {
		var header identityHeader
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, fmt.Errorf("read unified web identities: %w", err)
		}
		if header.Role == "user" {
			users.Identities = append(users.Identities, append(json.RawMessage(nil), raw...))
		}
	}
	return json.MarshalIndent(users, "", "  ")
}

func encodeInnerArchive(migrationID string, createdAt time.Time, source string, files map[string][]byte) ([]byte, error) {
	manifest := innerManifest{
		Version: archiveVersion, MigrationID: migrationID, CreatedAt: createdAt.Format(time.RFC3339),
		Source: source, Files: make(map[string]string, len(files)),
	}
	for name, contents := range files {
		digest := sha256.Sum256(contents)
		manifest.Files[name] = hex.EncodeToString(digest[:])
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files)+1)
	names = append(names, "manifest.json")
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names[1:])
	entries := make([]zipEntry, 0, len(names))
	for _, name := range names {
		contents := manifestBytes
		if name != "manifest.json" {
			contents = files[name]
		}
		entries = append(entries, zipEntry{name: name, data: contents})
	}
	output, err := writeStoredZip(entries)
	if err != nil {
		return nil, err
	}
	if len(output) > maxArchiveBytes {
		return nil, errors.New("Master migration archive exceeds the size limit")
	}
	return output, nil
}

func encryptArchive(migrationID string, createdAt time.Time, passphrase string, payload []byte) ([]byte, error) {
	salt := make([]byte, 32)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	const memory = 64 * 1024
	const iterations = 3
	const parallelism = 4
	key := argon2.IDKey([]byte(passphrase), salt, iterations, memory, parallelism, chacha20poly1305.KeySize)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, payload, []byte(migrationID))
	digest := sha256.Sum256(ciphertext)
	manifest := outerManifest{
		Version: archiveVersion, MigrationID: migrationID, CreatedAt: createdAt.Format(time.RFC3339),
		Cipher: "XChaCha20-Poly1305", KDF: "Argon2id", KDFMemoryKiB: memory,
		KDFIterations: iterations, KDFParallelism: parallelism,
		Salt: base64.RawURLEncoding.EncodeToString(salt), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		PayloadSHA256: hex.EncodeToString(digest[:]),
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return writeStoredZip([]zipEntry{{name: "manifest.json", data: manifestBytes}, {name: "payload.enc", data: ciphertext}})
}

func validatePassphrase(passphrase string) error {
	if len([]rune(passphrase)) < minimumPassphraseLen || len(passphrase) > 512 {
		return fmt.Errorf("%w: use 15 to 512 characters", ErrInvalidPassphrase)
	}
	return nil
}

func randomID() (string, error) {
	value := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("path is not a safe regular file or exceeds the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func cleanArchiveName(name string) bool {
	return name != "" && !strings.HasPrefix(name, "/") && filepath.ToSlash(filepath.Clean(name)) == name && !strings.HasPrefix(name, "../")
}
