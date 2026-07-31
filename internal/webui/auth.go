package webui

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// accessFileVersion is retained for the legacy access-key document format.
	accessFileVersion      = 1
	adminAccessFileVersion = 2
	accessFileMaxBytes     = 8 << 10
	sessionFileVersion     = 1
	sessionFileMaxBytes    = 128 << 10

	credentialBytes         = 32
	encodedCredentialLength = 43

	argon2IDVersion      = argon2.Version
	argon2MemoryKiB      = 64 * 1024
	argon2Iterations     = 3
	argon2Parallelism    = 4
	passwordSaltBytes    = 16
	passwordHashBytes    = 32
	passwordMaxBytes     = 512
	passwordMinRunes     = 15
	passwordMaxRunes     = 128
	passwordDocumentType = "password"

	DefaultSessionIdleTimeout     = 30 * time.Minute
	DefaultSessionAbsoluteTimeout = 12 * time.Hour
	defaultSessionPersistInterval = time.Minute
	DefaultLoginFailureLimit      = 10
	DefaultLoginFailureWindow     = time.Minute
	defaultMaxSessions            = 64

	SessionCookieName = "__Host-theatropolis_session"
	CSRFHeaderName    = "X-CSRF-Token"
)

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrLoginRateLimited     = errors.New("too many login attempts")

	// The production process loads one AccessManager, but this package-wide
	// gate also protects against accidentally loading more than one. Argon2id
	// verification never queues: a concurrent attempt is rejected instead of
	// retaining an unbounded request body and goroutine.
	globalPasswordKDFGate = make(chan struct{}, 1)
)

// CredentialMode identifies the one credential format accepted by an
// AccessManager. A manager never accepts both formats at once.
type CredentialMode uint8

const (
	LegacyAccessKey CredentialMode = iota + 1
	UsernamePassword
)

type legacyAccessDocument struct {
	Version         int    `json:"version"`
	AccessKeySHA256 string `json:"access_key_sha256"`
}

type passwordAccessDocument struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	Username      string `json:"username"`
	Algorithm     string `json:"algorithm"`
	Argon2Version int    `json:"argon2_version"`
	MemoryKiB     uint32 `json:"memory_kib"`
	Iterations    uint32 `json:"iterations"`
	Parallelism   uint8  `json:"parallelism"`
	Salt          string `json:"salt"`
	PasswordHash  string `json:"password_hash"`
}

// Session contains the plaintext browser credentials returned at login or
// successful authentication. ExpiresAt is the absolute session expiration;
// the server separately enforces the shorter sliding idle timeout.
type Session struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

type memorySession struct {
	csrfSecret        [credentialBytes]byte
	createdAt         time.Time
	lastSeenAt        time.Time
	absoluteExpiresAt time.Time
}

type sessionDocument struct {
	Version           int                `json:"version"`
	CredentialBinding string             `json:"credential_binding_sha256"`
	Sessions          []persistedSession `json:"sessions"`
}

type persistedSession struct {
	TokenSHA256       string    `json:"token_sha256"`
	CSRFSecret        string    `json:"csrf_secret"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
}

type loginFailureLimiter struct {
	windowStartedAt time.Time
	attempts        int
}

type passwordDeriver func(password, salt []byte) [passwordHashBytes]byte

// AccessManager authenticates the persisted operator credential and owns
// ephemeral browser sessions. It never retains plaintext passwords, access
// keys, or session tokens.
type AccessManager struct {
	mode CredentialMode

	accessKeyDigest [sha256.Size]byte
	usernameDigest  [sha256.Size]byte
	passwordSalt    [passwordSaltBytes]byte
	passwordHash    [passwordHashBytes]byte
	derivePassword  passwordDeriver
	passwordKDFGate chan struct{}

	mu          sync.Mutex
	lifecycleMu sync.Mutex
	sessions    map[[sha256.Size]byte]*memorySession
	failures    loginFailureLimiter

	activityPersisting  bool
	activityPersistedAt time.Time
	activityInterval    time.Duration
	persistSnapshotHook func(map[[sha256.Size]byte]*memorySession) error

	sessionIdleTimeout     time.Duration
	sessionAbsoluteTimeout time.Duration
	loginFailureLimit      int
	loginFailureWindow     time.Duration
	maxSessions            int
	now                    func() time.Time
	random                 io.Reader
	sessionPath            string
	credentialBinding      [sha256.Size]byte
}

// InitializeAccess creates a legacy v1 access-key file. It remains available
// so existing installations and their explicit migration path keep working.
// New installations should use InitializeAdminAccess.
func InitializeAccess(path string) (plaintextKey string, err error) {
	if err := validateAccessPath(path); err != nil {
		return "", err
	}

	var key [credentialBytes]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return "", fmt.Errorf("generate operator access key: %w", err)
	}
	defer clear(key[:])

	digest := sha256.Sum256(key[:])
	document, err := marshalAccessDocument(legacyAccessDocument{
		Version:         accessFileVersion,
		AccessKeySHA256: base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		return "", err
	}
	if err := createAccessFile(path, document); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key[:]), nil
}

// InitializeAdminAccess creates a v2 single-admin username/password file
// without replacing an existing path.
func InitializeAdminAccess(path, username string, password []byte) error {
	return initializeAdminAccessWithPasswordDeriver(
		path,
		username,
		password,
		deriveArgon2idPassword,
		rand.Reader,
	)
}

// ReplaceAdminAccess atomically replaces a regular, safely permissioned
// credential file with a v2 username/password file. On Unix, its ownership and
// 0600/0640 mode are preserved.
func ReplaceAdminAccess(path, username string, password []byte) error {
	return replaceAdminAccessWithPasswordDeriver(
		path,
		username,
		password,
		deriveArgon2idPassword,
		rand.Reader,
	)
}

// The injectable helpers keep package tests fast while exercising exactly the
// same schema, policy, file handling, and login paths as production.
func initializeAdminAccessWithPasswordDeriver(
	path, username string,
	password []byte,
	derive passwordDeriver,
	random io.Reader,
) error {
	if err := validateAccessPath(path); err != nil {
		return err
	}
	document, err := newPasswordAccessDocument(username, password, derive, random)
	if err != nil {
		return err
	}
	encoded, err := marshalAccessDocument(document)
	if err != nil {
		return err
	}
	return createAccessFile(path, encoded)
}

func replaceAdminAccessWithPasswordDeriver(
	path, username string,
	password []byte,
	derive passwordDeriver,
	random io.Reader,
) error {
	if err := validateAccessPath(path); err != nil {
		return err
	}
	if derive == nil {
		return errors.New("password derivation function is required")
	}
	if random == nil {
		return errors.New("credential random source is required")
	}

	existing, existingInfo, err := openVerifiedAccessFile(path)
	if err != nil {
		return err
	}
	if err := existing.Close(); err != nil {
		return fmt.Errorf("close existing access file: %w", err)
	}

	document, err := newPasswordAccessDocument(username, password, derive, random)
	if err != nil {
		return err
	}
	encoded, err := marshalAccessDocument(document)
	if err != nil {
		return err
	}

	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary access file: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()

	if err := preserveAccessFileMetadata(temp, existingInfo); err != nil {
		return err
	}
	if err := writeAndSyncAccessFile(temp, encoded); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary access file: %w", err)
	}

	currentInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("reinspect access file before replacement: %w", err)
	}
	if currentInfo.Mode()&os.ModeSymlink != 0 ||
		!currentInfo.Mode().IsRegular() ||
		!os.SameFile(existingInfo, currentInfo) {
		return errors.New("access file changed before it could be replaced")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace access file: %w", err)
	}
	committed = true
	if err := syncParentDirectory(path); err != nil {
		return err
	}
	return nil
}

func newPasswordAccessDocument(
	username string,
	password []byte,
	derive passwordDeriver,
	random io.Reader,
) (passwordAccessDocument, error) {
	if err := validateAdminUsername(username); err != nil {
		return passwordAccessDocument{}, err
	}
	if len(password) > passwordMaxBytes {
		return passwordAccessDocument{}, fmt.Errorf(
			"password must not exceed %d bytes",
			passwordMaxBytes,
		)
	}
	passwordCopy := append([]byte(nil), password...)
	defer clear(passwordCopy)
	if err := validateAdminPassword(username, passwordCopy, true); err != nil {
		return passwordAccessDocument{}, err
	}
	if derive == nil {
		return passwordAccessDocument{}, errors.New("password derivation function is required")
	}
	if random == nil {
		return passwordAccessDocument{}, errors.New("credential random source is required")
	}

	var salt [passwordSaltBytes]byte
	if _, err := io.ReadFull(random, salt[:]); err != nil {
		return passwordAccessDocument{}, fmt.Errorf("generate password salt: %w", err)
	}
	defer clear(salt[:])

	hash := derive(passwordCopy, salt[:])
	defer clear(hash[:])

	return passwordAccessDocument{
		Version:       adminAccessFileVersion,
		Type:          passwordDocumentType,
		Username:      username,
		Algorithm:     "argon2id",
		Argon2Version: argon2IDVersion,
		MemoryKiB:     argon2MemoryKiB,
		Iterations:    argon2Iterations,
		Parallelism:   argon2Parallelism,
		Salt:          base64.RawURLEncoding.EncodeToString(salt[:]),
		PasswordHash:  base64.RawURLEncoding.EncodeToString(hash[:]),
	}, nil
}

func marshalAccessDocument(document any) ([]byte, error) {
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode access file: %w", err)
	}
	return append(encoded, '\n'), nil
}

func validateAccessPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("access file path is required")
	}
	return nil
}

func createAccessFile(path string, document []byte) (err error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create access file: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure access file: %w", err)
	}
	if err := writeAndSyncAccessFile(file, document); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close access file: %w", err)
	}
	if err := syncParentDirectory(path); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeAndSyncAccessFile(file *os.File, document []byte) error {
	written, err := file.Write(document)
	if err != nil {
		return fmt.Errorf("write access file: %w", err)
	}
	if written != len(document) {
		return fmt.Errorf("write access file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync access file: %w", err)
	}
	return nil
}

func syncParentDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open access file directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync access file directory: %w", err)
	}
	return nil
}

func preserveAccessFileMetadata(file *os.File, existing os.FileInfo) error {
	mode := existing.Mode().Perm()
	if runtime.GOOS != "windows" && mode != 0o600 && mode != 0o640 {
		return errors.New("access file permissions must be 0600 or 0640")
	}
	if runtime.GOOS != "windows" {
		uid, gid, ok := unixOwnership(existing)
		if !ok {
			return errors.New("cannot determine access file ownership")
		}
		if err := file.Chown(uid, gid); err != nil {
			return fmt.Errorf("preserve access file ownership: %w", err)
		}
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("preserve access file permissions: %w", err)
	}
	return nil
}

func unixOwnership(info os.FileInfo) (uid, gid int, ok bool) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0, 0, false
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, 0, false
	}
	uidField := value.FieldByName("Uid")
	gidField := value.FieldByName("Gid")
	if !uidField.IsValid() || !gidField.IsValid() ||
		!uidField.CanUint() || !gidField.CanUint() {
		return 0, 0, false
	}
	return int(uidField.Uint()), int(gidField.Uint()), true
}

// LoadAccess loads either a strict legacy v1 access-key document or a strict
// v2 username/password document and creates an empty in-memory session manager.
func LoadAccess(path string) (*AccessManager, error) {
	return loadAccessWithPasswordDeriver(path, deriveArgon2idPassword)
}

// LoadAccessWithSessions loads operator credentials and restores browser
// sessions from a separate owner-only state file.
func LoadAccessWithSessions(path, sessionPath string) (*AccessManager, error) {
	return loadAccessWithPasswordDeriverAndSessions(
		path,
		sessionPath,
		deriveArgon2idPassword,
	)
}

func loadAccessWithPasswordDeriver(path string, derive passwordDeriver) (*AccessManager, error) {
	return loadAccessWithPasswordDeriverAndSessions(path, "", derive)
}

func loadAccessWithPasswordDeriverAndSessions(
	path, sessionPath string,
	derive passwordDeriver,
) (*AccessManager, error) {
	if err := validateAccessPath(path); err != nil {
		return nil, err
	}
	if derive == nil {
		return nil, errors.New("password derivation function is required")
	}

	file, _, err := openVerifiedAccessFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	encoded, err := io.ReadAll(io.LimitReader(file, accessFileMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read access file: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > accessFileMaxBytes {
		return nil, errors.New("access file is empty or exceeds the size limit")
	}

	fields, err := decodeAccessFields(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode access file: %w", err)
	}
	var version int
	if err := decodeRequiredAccessField(fields, "version", &version); err != nil {
		return nil, fmt.Errorf("decode access file: %w", err)
	}

	manager := newAccessManager()
	manager.credentialBinding = sha256.Sum256(encoded)
	switch version {
	case accessFileVersion:
		if err := loadLegacyCredential(manager, fields); err != nil {
			return nil, fmt.Errorf("decode access file: %w", err)
		}
	case adminAccessFileVersion:
		if err := loadPasswordCredential(manager, fields, derive); err != nil {
			return nil, fmt.Errorf("decode access file: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported access file version %d", version)
	}
	if strings.TrimSpace(sessionPath) != "" {
		manager.sessionPath = filepath.Clean(sessionPath)
		if err := manager.loadSessions(); err != nil {
			return nil, fmt.Errorf("load web sessions: %w", err)
		}
	}
	return manager, nil
}

func openVerifiedAccessFile(path string) (*os.File, os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect access file: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, nil, errors.New("access file must be a regular file, not a symbolic link")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open access file: %w", err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("inspect open access file: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		_ = file.Close()
		return nil, nil, errors.New("access file changed while it was being opened")
	}
	if runtime.GOOS != "windows" &&
		fileInfo.Mode().Perm() != 0o600 &&
		fileInfo.Mode().Perm() != 0o640 {
		_ = file.Close()
		return nil, nil, errors.New("access file permissions must be 0600 or 0640")
	}
	return file, fileInfo, nil
}

func decodeAccessFields(encoded []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	first, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := first.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("access document must be a JSON object")
	}

	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("access document contains a non-string field name")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, fmt.Errorf("access document contains duplicate field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	last, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := last.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("access document is not terminated")
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("access document contains trailing JSON")
		}
		return nil, err
	}
	return fields, nil
}

func decodeRequiredAccessField(fields map[string]json.RawMessage, name string, target any) error {
	value, ok := fields[name]
	if !ok {
		return fmt.Errorf("access document is missing %s", name)
	}
	if err := json.Unmarshal(value, target); err != nil {
		return fmt.Errorf("access document contains invalid %s: %w", name, err)
	}
	return nil
}

func requireExactAccessFields(fields map[string]json.RawMessage, required ...string) error {
	allowed := make(map[string]struct{}, len(required))
	for _, name := range required {
		allowed[name] = struct{}{}
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("access document is missing %s", name)
		}
	}
	for name := range fields {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("access document contains unknown field %q", name)
		}
	}
	return nil
}

func loadLegacyCredential(manager *AccessManager, fields map[string]json.RawMessage) error {
	if err := requireExactAccessFields(fields, "version", "access_key_sha256"); err != nil {
		return err
	}
	var document legacyAccessDocument
	if err := decodeRequiredAccessField(fields, "version", &document.Version); err != nil {
		return err
	}
	if err := decodeRequiredAccessField(fields, "access_key_sha256", &document.AccessKeySHA256); err != nil {
		return err
	}
	digest, err := decodeCanonicalBase64(document.AccessKeySHA256, sha256.Size)
	if err != nil {
		return errors.New("access file contains an invalid access-key digest")
	}
	defer clear(digest)

	manager.mode = LegacyAccessKey
	copy(manager.accessKeyDigest[:], digest)
	return nil
}

func loadPasswordCredential(
	manager *AccessManager,
	fields map[string]json.RawMessage,
	derive passwordDeriver,
) error {
	if err := requireExactAccessFields(
		fields,
		"version",
		"type",
		"username",
		"algorithm",
		"argon2_version",
		"memory_kib",
		"iterations",
		"parallelism",
		"salt",
		"password_hash",
	); err != nil {
		return err
	}

	var document passwordAccessDocument
	for _, field := range []struct {
		name   string
		target any
	}{
		{"version", &document.Version},
		{"type", &document.Type},
		{"username", &document.Username},
		{"algorithm", &document.Algorithm},
		{"argon2_version", &document.Argon2Version},
		{"memory_kib", &document.MemoryKiB},
		{"iterations", &document.Iterations},
		{"parallelism", &document.Parallelism},
		{"salt", &document.Salt},
		{"password_hash", &document.PasswordHash},
	} {
		if err := decodeRequiredAccessField(fields, field.name, field.target); err != nil {
			return err
		}
	}

	if document.Type != passwordDocumentType ||
		document.Algorithm != "argon2id" ||
		document.Argon2Version != argon2IDVersion ||
		document.MemoryKiB != argon2MemoryKiB ||
		document.Iterations != argon2Iterations ||
		document.Parallelism != argon2Parallelism {
		return errors.New("access file contains unsupported password parameters")
	}
	if err := validateAdminUsername(document.Username); err != nil {
		return fmt.Errorf("access file contains invalid username: %w", err)
	}
	salt, err := decodeCanonicalBase64(document.Salt, passwordSaltBytes)
	if err != nil {
		return errors.New("access file contains an invalid password salt")
	}
	defer clear(salt)
	hash, err := decodeCanonicalBase64(document.PasswordHash, passwordHashBytes)
	if err != nil {
		return errors.New("access file contains an invalid password hash")
	}
	defer clear(hash)

	manager.mode = UsernamePassword
	manager.usernameDigest = sha256.Sum256([]byte(document.Username))
	copy(manager.passwordSalt[:], salt)
	copy(manager.passwordHash[:], hash)
	manager.derivePassword = derive
	manager.passwordKDFGate = globalPasswordKDFGate
	return nil
}

func decodeCanonicalBase64(encoded string, expectedBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil ||
		len(decoded) != expectedBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, errors.New("invalid base64url value")
	}
	return decoded, nil
}

func (m *AccessManager) loadSessions() error {
	info, err := os.Lstat(m.sessionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect session file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("session file must be a regular file, not a symbolic link")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return errors.New("session file permissions must be 0600")
	}
	file, err := os.Open(m.sessionPath)
	if err != nil {
		return fmt.Errorf("open session file: %w", err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, sessionFileMaxBytes+1))
	if err != nil {
		return fmt.Errorf("read session file: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > sessionFileMaxBytes {
		return errors.New("session file is empty or exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document sessionDocument
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode session file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("session file contains trailing JSON")
	}
	if document.Version != sessionFileVersion {
		return fmt.Errorf("unsupported session file version %d", document.Version)
	}
	binding, err := decodeCanonicalBase64(document.CredentialBinding, sha256.Size)
	if err != nil {
		return errors.New("session file contains an invalid credential binding")
	}
	defer clear(binding)
	if subtle.ConstantTimeCompare(binding, m.credentialBinding[:]) != 1 {
		return m.persistSessionsLocked()
	}
	if len(document.Sessions) > m.maxSessions {
		return errors.New("session file contains too many sessions")
	}
	now := m.currentTime()
	for _, stored := range document.Sessions {
		tokenDigest, err := decodeCanonicalBase64(stored.TokenSHA256, sha256.Size)
		if err != nil {
			return errors.New("session file contains an invalid token digest")
		}
		csrfSecret, err := decodeCanonicalBase64(stored.CSRFSecret, credentialBytes)
		if err != nil {
			clear(tokenDigest)
			return errors.New("session file contains an invalid CSRF secret")
		}
		var digest [sha256.Size]byte
		var csrf [credentialBytes]byte
		copy(digest[:], tokenDigest)
		copy(csrf[:], csrfSecret)
		clear(tokenDigest)
		clear(csrfSecret)
		if _, duplicate := m.sessions[digest]; duplicate {
			return errors.New("session file contains a duplicate token digest")
		}
		session := &memorySession{
			csrfSecret:        csrf,
			createdAt:         stored.CreatedAt.UTC(),
			lastSeenAt:        stored.LastSeenAt.UTC(),
			absoluteExpiresAt: stored.AbsoluteExpiresAt.UTC(),
		}
		if session.createdAt.IsZero() ||
			session.lastSeenAt.Before(session.createdAt) ||
			!session.absoluteExpiresAt.After(session.createdAt) {
			return errors.New("session file contains invalid timestamps")
		}
		if !m.sessionExpiredLocked(session, now) {
			m.sessions[digest] = session
		}
	}
	m.activityPersistedAt = now
	return nil
}

func (m *AccessManager) persistSessionsLocked() error {
	return m.persistSessionSnapshot(m.sessions)
}

func (m *AccessManager) persistSessionSnapshot(
	sessions map[[sha256.Size]byte]*memorySession,
) error {
	if m.persistSnapshotHook != nil {
		return m.persistSnapshotHook(sessions)
	}
	if m.sessionPath == "" {
		return nil
	}
	document := sessionDocument{
		Version:           sessionFileVersion,
		CredentialBinding: base64.RawURLEncoding.EncodeToString(m.credentialBinding[:]),
		Sessions:          make([]persistedSession, 0, len(sessions)),
	}
	for digest, session := range sessions {
		document.Sessions = append(document.Sessions, persistedSession{
			TokenSHA256:       base64.RawURLEncoding.EncodeToString(digest[:]),
			CSRFSecret:        base64.RawURLEncoding.EncodeToString(session.csrfSecret[:]),
			CreatedAt:         session.createdAt.UTC(),
			LastSeenAt:        session.lastSeenAt.UTC(),
			AbsoluteExpiresAt: session.absoluteExpiresAt.UTC(),
		})
	}
	sort.Slice(document.Sessions, func(left, right int) bool {
		return document.Sessions[left].TokenSHA256 < document.Sessions[right].TokenSHA256
	})
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode session file: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > sessionFileMaxBytes {
		return errors.New("session file exceeds the size limit")
	}
	directory := filepath.Dir(m.sessionPath)
	temp, err := os.CreateTemp(directory, "."+filepath.Base(m.sessionPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary session file: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary session file: %w", err)
	}
	if _, err := temp.Write(encoded); err != nil {
		return fmt.Errorf("write session file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("synchronize session file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close session file: %w", err)
	}
	if err := os.Rename(tempPath, m.sessionPath); err != nil {
		return fmt.Errorf("replace session file: %w", err)
	}
	committed = true
	return syncParentDirectory(m.sessionPath)
}

func cloneSessions(sessions map[[sha256.Size]byte]*memorySession) map[[sha256.Size]byte]*memorySession {
	copyMap := make(map[[sha256.Size]byte]*memorySession, len(sessions))
	for digest, session := range sessions {
		copySession := *session
		copyMap[digest] = &copySession
	}
	return copyMap
}

func newAccessManager() *AccessManager {
	return &AccessManager{
		sessions:               make(map[[sha256.Size]byte]*memorySession),
		sessionIdleTimeout:     DefaultSessionIdleTimeout,
		sessionAbsoluteTimeout: DefaultSessionAbsoluteTimeout,
		loginFailureLimit:      DefaultLoginFailureLimit,
		loginFailureWindow:     DefaultLoginFailureWindow,
		maxSessions:            defaultMaxSessions,
		activityInterval:       defaultSessionPersistInterval,
		now:                    time.Now,
		random:                 rand.Reader,
	}
}

// Mode returns the only credential mode accepted by this manager.
func (m *AccessManager) Mode() CredentialMode {
	return m.mode
}

// Login verifies the credential for this manager's mode and creates a new
// in-memory session. For LegacyAccessKey, username must be empty and password
// carries the legacy access key. V2 verifies every normal-shaped username with
// exactly one Argon2id derivation, including unknown usernames.
func (m *AccessManager) Login(username, password string) (Session, error) {
	now := m.currentTime()
	if err := m.reserveLoginAttempt(now); err != nil {
		return Session{}, err
	}

	authenticated := false
	switch m.mode {
	case LegacyAccessKey:
		authenticated = username == "" && m.matchesAccessKey(password)
	case UsernamePassword:
		passwordShapeValid := false
		if len(password) <= passwordMaxBytes {
			passwordCopy := []byte(password)
			passwordShapeValid = validateAdminPassword("", passwordCopy, false) == nil
			clear(passwordCopy)
		}
		if validateAdminUsername(username) == nil && passwordShapeValid {
			if !m.acquirePasswordKDF() {
				return Session{}, ErrLoginRateLimited
			}
			authenticated = func() bool {
				defer m.releasePasswordKDF()
				return m.matchesUsernamePassword(username, password)
			}()
		}
	}
	if !authenticated {
		return Session{}, ErrAuthenticationFailed
	}

	var token [credentialBytes]byte
	var csrf [credentialBytes]byte
	if _, err := io.ReadFull(m.random, token[:]); err != nil {
		return Session{}, fmt.Errorf("generate session token: %w", err)
	}
	defer clear(token[:])
	if _, err := io.ReadFull(m.random, csrf[:]); err != nil {
		return Session{}, fmt.Errorf("generate CSRF token: %w", err)
	}
	defer clear(csrf[:])

	tokenDigest := sha256.Sum256(token[:])
	absoluteExpiresAt := now.Add(m.sessionAbsoluteTimeout)
	session := &memorySession{
		csrfSecret:        csrf,
		createdAt:         now,
		lastSeenAt:        now,
		absoluteExpiresAt: absoluteExpiresAt,
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	previousSessions := cloneSessions(m.sessions)
	m.failures = loginFailureLimiter{}
	m.purgeExpiredSessionsLocked(now)
	if len(m.sessions) >= m.maxSessions {
		m.evictOldestSessionLocked()
	}
	m.sessions[tokenDigest] = session
	if err := m.persistSessionsLocked(); err != nil {
		m.sessions = previousSessions
		m.mu.Unlock()
		return Session{}, fmt.Errorf("persist browser session: %w", err)
	}
	m.activityPersistedAt = now
	m.mu.Unlock()

	return Session{
		Token:     base64.RawURLEncoding.EncodeToString(token[:]),
		CSRFToken: base64.RawURLEncoding.EncodeToString(csrf[:]),
		ExpiresAt: absoluteExpiresAt,
	}, nil
}

func (m *AccessManager) reserveLoginAttempt(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loginFailureLimit <= 0 || m.loginFailureWindow <= 0 {
		return ErrLoginRateLimited
	}
	windowExpired := m.failures.windowStartedAt.IsZero() ||
		now.Before(m.failures.windowStartedAt) ||
		!now.Before(m.failures.windowStartedAt.Add(m.loginFailureWindow))
	if windowExpired {
		m.failures = loginFailureLimiter{windowStartedAt: now}
	}
	if m.failures.attempts >= m.loginFailureLimit {
		return ErrLoginRateLimited
	}
	m.failures.attempts++
	return nil
}

func (m *AccessManager) acquirePasswordKDF() bool {
	if m.passwordKDFGate == nil {
		return false
	}
	select {
	case m.passwordKDFGate <- struct{}{}:
		return true
	default:
		return false
	}
}

func (m *AccessManager) releasePasswordKDF() {
	<-m.passwordKDFGate
}

func (m *AccessManager) matchesUsernamePassword(username, password string) bool {
	candidateUsername := sha256.Sum256([]byte(username))
	usernameMatches := subtle.ConstantTimeCompare(
		m.usernameDigest[:],
		candidateUsername[:],
	)

	passwordCopy := []byte(password)
	defer clear(passwordCopy)
	candidateHash := m.derivePassword(passwordCopy, m.passwordSalt[:])
	defer clear(candidateHash[:])
	passwordMatches := subtle.ConstantTimeCompare(
		m.passwordHash[:],
		candidateHash[:],
	)
	return usernameMatches&passwordMatches == 1
}

func deriveArgon2idPassword(password, salt []byte) [passwordHashBytes]byte {
	derived := argon2.IDKey(
		password,
		salt,
		argon2Iterations,
		argon2MemoryKiB,
		argon2Parallelism,
		passwordHashBytes,
	)
	defer clear(derived)
	var hash [passwordHashBytes]byte
	copy(hash[:], derived)
	return hash
}

func validateAdminUsername(username string) error {
	if len(username) == 0 || len(username) > 64 {
		return errors.New("username must contain between 1 and 64 ASCII characters")
	}
	for index := 0; index < len(username); index++ {
		character := username[index]
		alphanumeric := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if alphanumeric {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return errors.New("username must match [a-z0-9][a-z0-9._-]{0,63}")
	}
	return nil
}

func validateAdminPassword(username string, password []byte, rejectWeak bool) error {
	if len(password) > passwordMaxBytes {
		return fmt.Errorf("password must not exceed %d bytes", passwordMaxBytes)
	}
	if !utf8.Valid(password) {
		return errors.New("password must be valid UTF-8")
	}
	runeCount := utf8.RuneCount(password)
	if runeCount < passwordMinRunes || runeCount > passwordMaxRunes {
		return fmt.Errorf(
			"password must contain between %d and %d Unicode characters",
			passwordMinRunes,
			passwordMaxRunes,
		)
	}
	for _, character := range string(password) {
		if unicode.IsControl(character) {
			return errors.New("password must not contain control characters")
		}
	}
	if rejectWeak && obviousWeakPassword(username, string(password)) {
		return errors.New("password is too common or too closely related to the username")
	}
	return nil
}

func obviousWeakPassword(username, password string) bool {
	lowerPassword := strings.ToLower(password)
	if strings.TrimSpace(password) == "" {
		return true
	}
	var (
		firstRune rune
		repeated  = true
	)
	for index, character := range password {
		if index == 0 {
			firstRune = character
			continue
		}
		if character != firstRune {
			repeated = false
			break
		}
	}
	if repeated {
		return true
	}
	switch lowerPassword {
	case "123456789012345",
		"passwordpassword",
		"password123456",
		"qwertyuiopasdfgh",
		"letmeinletmein",
		"changemechangeme",
		"adminadminadmin",
		"correct horse battery staple",
		"correcthorsebatterystaple",
		"theatropolistheatropolis":
		return true
	}
	if len(username) < 3 {
		return false
	}
	for _, derived := range []string{
		username,
		username + username,
		username + "123",
		username + "123456",
		username + "password",
		"password" + username,
	} {
		if lowerPassword == derived {
			return true
		}
	}
	return false
}

// Authenticate verifies a session token, refreshes its idle deadline, and
// returns the CSRF token needed when rendering protected forms.
func (m *AccessManager) Authenticate(sessionToken string) (Session, error) {
	tokenDigest, valid := credentialDigest(sessionToken)
	now := m.currentTime()

	m.mu.Lock()
	session, exists := m.sessions[tokenDigest]
	if valid != 1 || !exists {
		m.mu.Unlock()
		return Session{}, ErrAuthenticationFailed
	}
	if m.sessionExpiredLocked(session, now) {
		m.mu.Unlock()
		return Session{}, ErrAuthenticationFailed
	}
	m.touchSessionLocked(session, now)
	result := Session{
		Token:     sessionToken,
		CSRFToken: base64.RawURLEncoding.EncodeToString(session.csrfSecret[:]),
		ExpiresAt: session.absoluteExpiresAt,
	}
	persist := m.scheduleActivityPersistenceLocked(now)
	m.mu.Unlock()
	if persist {
		go m.persistSessionActivity()
	}
	return result, nil
}

// AuthorizeCSRF verifies both the session token and its synchronizer CSRF
// secret in constant time. A failed CSRF check does not extend the session.
func (m *AccessManager) AuthorizeCSRF(sessionToken, csrfToken string) bool {
	tokenDigest, tokenValid := credentialDigest(sessionToken)
	candidateCSRF, csrfValid := decodeCredential(csrfToken)
	defer clear(candidateCSRF[:])
	now := m.currentTime()

	m.mu.Lock()
	session, exists := m.sessions[tokenDigest]
	if tokenValid != 1 || !exists {
		m.mu.Unlock()
		return false
	}
	if m.sessionExpiredLocked(session, now) {
		m.mu.Unlock()
		return false
	}
	matches := subtle.ConstantTimeCompare(session.csrfSecret[:], candidateCSRF[:]) & csrfValid
	if matches != 1 {
		m.mu.Unlock()
		return false
	}
	m.touchSessionLocked(session, now)
	persist := m.scheduleActivityPersistenceLocked(now)
	m.mu.Unlock()
	if persist {
		go m.persistSessionActivity()
	}
	return true
}

// Logout removes a session when the supplied token is well formed.
func (m *AccessManager) Logout(sessionToken string) error {
	tokenDigest, valid := credentialDigest(sessionToken)
	if valid != 1 {
		return nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	previousSessions := cloneSessions(m.sessions)
	delete(m.sessions, tokenDigest)
	if err := m.persistSessionsLocked(); err != nil {
		m.sessions = previousSessions
		return fmt.Errorf("persist browser logout: %w", err)
	}
	return nil
}

// InvalidateAllSessions revokes every browser session, for example after a
// synchronized live credential reload.
func (m *AccessManager) InvalidateAllSessions() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	previousSessions := cloneSessions(m.sessions)
	clear(m.sessions)
	if err := m.persistSessionsLocked(); err != nil {
		m.sessions = previousSessions
		return fmt.Errorf("persist session invalidation: %w", err)
	}
	return nil
}

// NewSessionCookie returns the host-only cookie used by the public HTTPS
// handler. ExpiresAt should be Session.ExpiresAt.
func NewSessionCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// DeleteSessionCookie expires the browser's session cookie immediately.
func DeleteSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (m *AccessManager) matchesAccessKey(accessKey string) bool {
	candidate, valid := decodeCredential(accessKey)
	defer clear(candidate[:])
	digest := sha256.Sum256(candidate[:])
	return subtle.ConstantTimeCompare(m.accessKeyDigest[:], digest[:])&valid == 1
}

func credentialDigest(encoded string) ([sha256.Size]byte, int) {
	decoded, valid := decodeCredential(encoded)
	defer clear(decoded[:])
	return sha256.Sum256(decoded[:]), valid
}

func decodeCredential(encoded string) ([credentialBytes]byte, int) {
	var credential [credentialBytes]byte
	if len(encoded) != encodedCredentialLength {
		return credential, 0
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != credentialBytes {
		clear(decoded)
		return credential, 0
	}
	copy(credential[:], decoded)
	canonical := base64.RawURLEncoding.EncodeToString(decoded)
	clear(decoded)
	if subtle.ConstantTimeCompare([]byte(canonical), []byte(encoded)) != 1 {
		clear(credential[:])
		return credential, 0
	}
	return credential, 1
}

func (m *AccessManager) purgeExpiredSessionsLocked(now time.Time) {
	for digest, session := range m.sessions {
		if m.sessionExpiredLocked(session, now) {
			delete(m.sessions, digest)
		}
	}
}

func (m *AccessManager) evictOldestSessionLocked() {
	var oldestDigest [sha256.Size]byte
	var oldest *memorySession
	for digest, session := range m.sessions {
		if oldest == nil ||
			session.lastSeenAt.Before(oldest.lastSeenAt) ||
			(session.lastSeenAt.Equal(oldest.lastSeenAt) &&
				session.createdAt.Before(oldest.createdAt)) {
			oldestDigest = digest
			oldest = session
		}
	}
	if oldest != nil {
		delete(m.sessions, oldestDigest)
	}
}

func (m *AccessManager) sessionExpiredLocked(session *memorySession, now time.Time) bool {
	return !now.Before(session.absoluteExpiresAt) ||
		!now.Before(session.lastSeenAt.Add(m.sessionIdleTimeout))
}

func (m *AccessManager) touchSessionLocked(session *memorySession, now time.Time) {
	if now.After(session.lastSeenAt) {
		session.lastSeenAt = now
	}
}

func (m *AccessManager) scheduleActivityPersistenceLocked(now time.Time) bool {
	if m.sessionPath == "" || m.activityInterval <= 0 || m.activityPersisting {
		return false
	}
	if !m.activityPersistedAt.IsZero() &&
		now.Before(m.activityPersistedAt.Add(m.activityInterval)) {
		return false
	}
	m.activityPersisting = true
	return true
}

// persistSessionActivity coalesces sliding-idle updates without keeping the
// request-path session mutex held during filesystem I/O. lifecycleMu prevents
// an older activity snapshot from overwriting a concurrent login or logout.
func (m *AccessManager) persistSessionActivity() {
	m.lifecycleMu.Lock()
	m.mu.Lock()
	snapshot := cloneSessions(m.sessions)
	m.mu.Unlock()
	err := m.persistSessionSnapshot(snapshot)
	now := m.currentTime()
	m.mu.Lock()
	m.activityPersisting = false
	if err == nil {
		m.activityPersistedAt = now
	}
	m.mu.Unlock()
	m.lifecycleMu.Unlock()
	if err != nil {
		slog.Error("persist browser session activity", "error", err)
	}
}

func (m *AccessManager) currentTime() time.Time {
	if m.now == nil {
		return time.Now().UTC()
	}
	return m.now().UTC()
}
