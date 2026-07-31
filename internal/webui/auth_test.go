package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAdminUsername = "admin"
	testAdminPassword = "Saffron!Orbit-73-Cedar&Glass"
)

func TestInitializeAccessCreatesExclusiveLegacyDigestOnlyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	accessKey, err := InitializeAccess(path)
	if err != nil {
		t.Fatalf("InitializeAccess() error = %v", err)
	}
	decodedKey, err := base64.RawURLEncoding.DecodeString(accessKey)
	if err != nil || len(decodedKey) != credentialBytes {
		t.Fatalf("InitializeAccess() returned malformed key %q", accessKey)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), accessKey) {
		t.Fatal("access file contains the plaintext access key")
	}
	var document legacyAccessDocument
	if err := json.Unmarshal(stored, &document); err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(decodedKey)
	if document.Version != accessFileVersion ||
		document.AccessKeySHA256 != base64.RawURLEncoding.EncodeToString(expectedDigest[:]) {
		t.Fatalf("unexpected persisted access document: %+v", document)
	}

	assertNewFileMode(t, path)
	before := append([]byte(nil), stored...)
	if _, err := InitializeAccess(path); err == nil {
		t.Fatal("second InitializeAccess() unexpectedly replaced the file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed exclusive initialization changed the existing access file")
	}

	manager, err := LoadAccess(path)
	if err != nil {
		t.Fatalf("LoadAccess() error = %v", err)
	}
	if manager.Mode() != LegacyAccessKey {
		t.Fatalf("Mode() = %v, want LegacyAccessKey", manager.Mode())
	}
	if _, err := manager.Login("", accessKey); err != nil {
		t.Fatalf("Login() with initialized key error = %v", err)
	}
	if _, err := manager.Login("admin", accessKey); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("legacy Login() accepted a nonempty username: %v", err)
	}
}

func TestInitializeAdminAccessCreatesExclusiveV2HashOnlyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	password := []byte(testAdminPassword)
	if err := initializeAdminAccessWithPasswordDeriver(
		path,
		testAdminUsername,
		password,
		fastTestPasswordDeriver,
		bytes.NewReader(bytes.Repeat([]byte{0x5a}, passwordSaltBytes)),
	); err != nil {
		t.Fatalf("initializeAdminAccessWithPasswordDeriver() error = %v", err)
	}

	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, password) {
		t.Fatal("v2 access file contains the plaintext password")
	}
	var document passwordAccessDocument
	if err := json.Unmarshal(stored, &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != adminAccessFileVersion ||
		document.Type != passwordDocumentType ||
		document.Username != testAdminUsername ||
		document.Algorithm != "argon2id" ||
		document.Argon2Version != argon2IDVersion ||
		document.MemoryKiB != argon2MemoryKiB ||
		document.Iterations != argon2Iterations ||
		document.Parallelism != argon2Parallelism {
		t.Fatalf("unexpected persisted admin document: %+v", document)
	}
	if salt, err := decodeCanonicalBase64(document.Salt, passwordSaltBytes); err != nil {
		t.Fatalf("invalid persisted salt: %v", err)
	} else {
		clear(salt)
	}
	if hash, err := decodeCanonicalBase64(document.PasswordHash, passwordHashBytes); err != nil {
		t.Fatalf("invalid persisted hash: %v", err)
	} else {
		clear(hash)
	}
	assertNewFileMode(t, path)

	before := append([]byte(nil), stored...)
	if err := initializeAdminAccessWithPasswordDeriver(
		path,
		"other",
		[]byte("another correct horse battery"),
		fastTestPasswordDeriver,
		bytes.NewReader(bytes.Repeat([]byte{0x6b}, passwordSaltBytes)),
	); err == nil {
		t.Fatal("second initialization unexpectedly replaced the file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed exclusive initialization changed the existing access file")
	}

	manager, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver)
	if err != nil {
		t.Fatal(err)
	}
	manager.passwordKDFGate = make(chan struct{}, 1)
	if manager.Mode() != UsernamePassword {
		t.Fatalf("Mode() = %v, want UsernamePassword", manager.Mode())
	}
	if _, err := manager.Login(testAdminUsername, testAdminPassword); err != nil {
		t.Fatalf("Login() with initialized password error = %v", err)
	}
}

func TestAdminInitializationUsesFreshSalt(t *testing.T) {
	t.Parallel()

	firstPath := filepath.Join(t.TempDir(), "first.json")
	secondPath := filepath.Join(t.TempDir(), "second.json")
	for _, path := range []string{firstPath, secondPath} {
		if err := initializeAdminAccessWithPasswordDeriver(
			path,
			testAdminUsername,
			[]byte(testAdminPassword),
			fastTestPasswordDeriver,
			nilSafeRandomReader{},
		); err != nil {
			t.Fatal(err)
		}
	}

	first := readPasswordDocument(t, firstPath)
	second := readPasswordDocument(t, secondPath)
	if first.Salt == second.Salt {
		t.Fatal("separate password files reused a salt")
	}
}

func TestAdminCredentialValidation(t *testing.T) {
	t.Parallel()

	validUsernames := []string{
		"a",
		"admin",
		"a.b_c-9",
		"a" + strings.Repeat("9", 63),
	}
	for _, username := range validUsernames {
		if err := validateAdminUsername(username); err != nil {
			t.Errorf("validateAdminUsername(%q) error = %v", username, err)
		}
	}
	invalidUsernames := []string{
		"",
		"Admin",
		"-admin",
		"admin user",
		"admín",
		"a" + strings.Repeat("9", 64),
	}
	for _, username := range invalidUsernames {
		if err := validateAdminUsername(username); err == nil {
			t.Errorf("validateAdminUsername(%q) unexpectedly succeeded", username)
		}
	}

	validPasswords := [][]byte{
		[]byte(testAdminPassword),
		[]byte("  spaces stay exact  "),
		[]byte("准确马电池订书钉密码短语足够长"),
		[]byte(strings.Repeat("🔐", passwordMaxRunes-1) + "🔑"),
	}
	for _, password := range validPasswords {
		if err := validateAdminPassword(testAdminUsername, password, true); err != nil {
			t.Errorf("validateAdminPassword(%q) error = %v", password, err)
		}
	}
	invalidPasswords := [][]byte{
		[]byte(strings.Repeat("x", passwordMinRunes-1)),
		[]byte(strings.Repeat("x", passwordMaxRunes+1)),
		append([]byte("long enough pass"), 0),
		{0xff, 0xfe, 0xfd},
		[]byte("passwordpassword"),
		[]byte("123456789012345"),
		[]byte("correct horse battery staple"),
		[]byte("correcthorsebatterystaple"),
		[]byte("theatropolispassword"),
		[]byte(strings.Repeat(" ", passwordMinRunes)),
		[]byte(strings.Repeat("x", passwordMinRunes)),
	}
	for _, password := range invalidPasswords {
		if err := validateAdminPassword("theatropolis", password, true); err == nil {
			t.Errorf("validateAdminPassword(%q) unexpectedly succeeded", password)
		}
	}
}

func TestProductionArgon2idRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.json")
	password := []byte(testAdminPassword)
	if err := InitializeAdminAccess(path, testAdminUsername, password); err != nil {
		t.Fatalf("InitializeAdminAccess() error = %v", err)
	}
	manager, err := LoadAccess(path)
	if err != nil {
		t.Fatalf("LoadAccess() error = %v", err)
	}
	if manager.Mode() != UsernamePassword {
		t.Fatalf("Mode() = %v, want UsernamePassword", manager.Mode())
	}
	if _, err := manager.Login(testAdminUsername, testAdminPassword); err != nil {
		t.Fatalf("Login() with production Argon2id error = %v", err)
	}
}

func TestPasswordVerificationUsesExactBytes(t *testing.T) {
	t.Parallel()

	const exactPassword = "  exact Unicode 密码 phrase  "
	manager, username := newTestAdminAccessManagerWithPassword(t, exactPassword)
	if _, err := manager.Login(username, exactPassword); err != nil {
		t.Fatalf("Login(exact) error = %v", err)
	}
	if _, err := manager.Login(username, strings.TrimSpace(exactPassword)); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Login(trimmed) error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestLoadAccessRejectsMalformedLegacyDocuments(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("test access key"))
	encodedDigest := base64.RawURLEncoding.EncodeToString(digest[:])
	tests := map[string]string{
		"not object":        `[]`,
		"unknown field":     `{"version":1,"access_key_sha256":"` + encodedDigest + `","extra":true}`,
		"duplicate version": `{"version":1,"version":1,"access_key_sha256":"` + encodedDigest + `"}`,
		"missing version":   `{"access_key_sha256":"` + encodedDigest + `"}`,
		"missing digest":    `{"version":1}`,
		"wrong version":     `{"version":3,"access_key_sha256":"` + encodedDigest + `"}`,
		"invalid digest":    `{"version":1,"access_key_sha256":"not-a-digest"}`,
		"padded digest":     `{"version":1,"access_key_sha256":"` + encodedDigest + `="}`,
		"trailing JSON":     `{"version":1,"access_key_sha256":"` + encodedDigest + `"} {}`,
		"empty":             ``,
	}

	for name, contents := range tests {
		name, contents := name, contents
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "access.json")
			writeAccessTestFile(t, path, []byte(contents))
			if _, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver); err == nil {
				t.Fatal("LoadAccess() unexpectedly accepted malformed legacy JSON")
			}
		})
	}
}

func TestLoadAccessRejectsMalformedV2Documents(t *testing.T) {
	t.Parallel()

	base := validTestPasswordDocument()
	tests := map[string]func(map[string]any){
		"unknown field": func(document map[string]any) {
			document["extra"] = true
		},
		"missing username": func(document map[string]any) {
			delete(document, "username")
		},
		"mixed legacy field": func(document map[string]any) {
			document["access_key_sha256"] = strings.Repeat("A", encodedCredentialLength)
		},
		"wrong type": func(document map[string]any) {
			document["type"] = "access-key"
		},
		"wrong algorithm": func(document map[string]any) {
			document["algorithm"] = "argon2i"
		},
		"wrong Argon2 version": func(document map[string]any) {
			document["argon2_version"] = argon2IDVersion - 1
		},
		"smaller memory": func(document map[string]any) {
			document["memory_kib"] = argon2MemoryKiB / 2
		},
		"larger memory": func(document map[string]any) {
			document["memory_kib"] = argon2MemoryKiB * 2
		},
		"wrong iterations": func(document map[string]any) {
			document["iterations"] = argon2Iterations + 1
		},
		"wrong parallelism": func(document map[string]any) {
			document["parallelism"] = argon2Parallelism + 1
		},
		"invalid username": func(document map[string]any) {
			document["username"] = "Admin"
		},
		"padded salt": func(document map[string]any) {
			document["salt"] = document["salt"].(string) + "="
		},
		"short salt": func(document map[string]any) {
			document["salt"] = base64.RawURLEncoding.EncodeToString(make([]byte, passwordSaltBytes-1))
		},
		"short hash": func(document map[string]any) {
			document["password_hash"] = base64.RawURLEncoding.EncodeToString(make([]byte, passwordHashBytes-1))
		},
		"fractional memory": func(document map[string]any) {
			document["memory_kib"] = 65536.5
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := passwordDocumentMap(t, base)
			mutate(document)
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "access.json")
			writeAccessTestFile(t, path, encoded)
			if _, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver); err == nil {
				t.Fatal("LoadAccess() unexpectedly accepted malformed v2 JSON")
			}
		})
	}

	t.Run("duplicate field", func(t *testing.T) {
		t.Parallel()
		encoded, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		encoded = bytes.Replace(
			encoded,
			[]byte(`"username":"admin"`),
			[]byte(`"username":"admin","username":"other"`),
			1,
		)
		path := filepath.Join(t.TempDir(), "access.json")
		writeAccessTestFile(t, path, encoded)
		if _, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver); err == nil {
			t.Fatal("LoadAccess() accepted duplicate v2 field")
		}
	})

	t.Run("trailing JSON", func(t *testing.T) {
		t.Parallel()
		encoded, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, []byte(" {}")...)
		path := filepath.Join(t.TempDir(), "access.json")
		writeAccessTestFile(t, path, encoded)
		if _, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver); err == nil {
			t.Fatal("LoadAccess() accepted trailing v2 JSON")
		}
	})
}

func TestLoadAccessRejectsOversizedDocument(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	writeAccessTestFile(t, path, bytes.Repeat([]byte(" "), accessFileMaxBytes+1))
	if _, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver); err == nil {
		t.Fatal("LoadAccess() accepted an oversized access document")
	}
}

func TestLoadAndReplaceRejectInsecureFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix file permission bits")
	}
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	if _, err := InitializeAccess(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccess(path); err == nil {
		t.Fatal("LoadAccess() accepted a group/world-readable access file")
	}
	if err := replaceAdminAccessWithPasswordDeriver(
		path,
		testAdminUsername,
		[]byte(testAdminPassword),
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	); err == nil {
		t.Fatal("ReplaceAdminAccess() accepted a group/world-readable access file")
	}
}

func TestLoadAccessAcceptsRootOwnedGroupReadableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix file permission bits")
	}
	t.Parallel()

	path := filepath.Join(t.TempDir(), "web-auth.json")
	if _, err := InitializeAccess(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccess(path); err != nil {
		t.Fatalf("LoadAccess() rejected mode 0640: %v", err)
	}
}

func TestLoadAndReplaceRejectSymbolicLink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "access.json")
	if _, err := InitializeAccess(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "access-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := LoadAccess(link); err == nil {
		t.Fatal("LoadAccess() accepted a symbolic link")
	}
	if err := replaceAdminAccessWithPasswordDeriver(
		link,
		testAdminUsername,
		[]byte(testAdminPassword),
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	); err == nil {
		t.Fatal("ReplaceAdminAccess() accepted a symbolic link")
	}
}

func TestReplaceAdminAccessIsAtomicAndPreservesMetadata(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "web-auth.json")
	legacyKey, err := InitializeAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeUID, beforeGID, beforeOwnershipOK := unixOwnership(beforeInfo)

	if err := replaceAdminAccessWithPasswordDeriver(
		path,
		testAdminUsername,
		[]byte(testAdminPassword),
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	); err != nil {
		t.Fatalf("ReplaceAdminAccess() error = %v", err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
		t.Fatalf(
			"replacement mode = %o, want preserved %o",
			afterInfo.Mode().Perm(),
			beforeInfo.Mode().Perm(),
		)
	}
	if runtime.GOOS != "windows" && beforeOwnershipOK {
		afterUID, afterGID, afterOwnershipOK := unixOwnership(afterInfo)
		if !afterOwnershipOK || afterUID != beforeUID || afterGID != beforeGID {
			t.Fatalf(
				"replacement ownership = %d:%d (known %v), want %d:%d",
				afterUID,
				afterGID,
				afterOwnershipOK,
				beforeUID,
				beforeGID,
			)
		}
	}

	manager, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver)
	if err != nil {
		t.Fatal(err)
	}
	manager.passwordKDFGate = make(chan struct{}, 1)
	if manager.Mode() != UsernamePassword {
		t.Fatalf("Mode() = %v, want UsernamePassword", manager.Mode())
	}
	if _, err := manager.Login(testAdminUsername, testAdminPassword); err != nil {
		t.Fatalf("new password Login() error = %v", err)
	}
	if _, err := manager.Login("", legacyKey); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("legacy key remained valid after replacement: %v", err)
	}
}

func TestFailedReplaceLeavesOldCredentialUntouched(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "access.json")
	key, err := InitializeAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceAdminAccessWithPasswordDeriver(
		path,
		testAdminUsername,
		[]byte(testAdminPassword),
		fastTestPasswordDeriver,
		alwaysErrorReader{},
	); err == nil {
		t.Fatal("ReplaceAdminAccess() unexpectedly succeeded with a failed random source")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("failed replacement changed the old credential file")
	}
	manager, err := LoadAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Login("", key); err != nil {
		t.Fatalf("old credential stopped working after failed replacement: %v", err)
	}
}

func TestWrongUsernameAndPasswordUseOneKDFAndGenericFailure(t *testing.T) {
	t.Parallel()

	path := createTestAdminAccessFile(t, testAdminPassword)
	var calls atomic.Int32
	countingDeriver := func(password, salt []byte) [passwordHashBytes]byte {
		calls.Add(1)
		return fastTestPasswordDeriver(password, salt)
	}
	manager, err := loadAccessWithPasswordDeriver(path, countingDeriver)
	if err != nil {
		t.Fatal(err)
	}
	manager.passwordKDFGate = make(chan struct{}, 1)

	if _, err := manager.Login("unknown", testAdminPassword); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong username error = %v, want generic authentication failure", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("wrong username invoked KDF %d times, want 1", got)
	}
	if _, err := manager.Login(testAdminUsername, "wrong password phrase indeed"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("wrong password error = %v, want generic authentication failure", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("wrong password cumulative KDF calls = %d, want 2", got)
	}
}

func TestPasswordKDFGateIsNonblockingAndBounded(t *testing.T) {
	t.Parallel()

	path := createTestAdminAccessFile(t, testAdminPassword)
	started := make(chan struct{})
	release := make(chan struct{})
	blockingDeriver := func(password, salt []byte) [passwordHashBytes]byte {
		close(started)
		<-release
		return fastTestPasswordDeriver(password, salt)
	}
	manager, err := loadAccessWithPasswordDeriver(path, blockingDeriver)
	if err != nil {
		t.Fatal(err)
	}
	manager.passwordKDFGate = make(chan struct{}, 1)

	firstResult := make(chan error, 1)
	go func() {
		_, err := manager.Login(testAdminUsername, testAdminPassword)
		firstResult <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first login never entered the password KDF")
	}

	if _, err := manager.Login(testAdminUsername, testAdminPassword); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("concurrent Login() error = %v, want ErrLoginRateLimited", err)
	}
	close(release)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first Login() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first login did not finish after KDF release")
	}
}

func TestLoginAttemptReservationIsAtomic(t *testing.T) {
	t.Parallel()

	manager := newAccessManager()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	var accepted atomic.Int32
	var limited atomic.Int32
	var group sync.WaitGroup
	for attempt := 0; attempt < 50; attempt++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := manager.reserveLoginAttempt(now); err == nil {
				accepted.Add(1)
			} else if errors.Is(err, ErrLoginRateLimited) {
				limited.Add(1)
			}
		}()
	}
	group.Wait()
	if got := accepted.Load(); got != DefaultLoginFailureLimit {
		t.Fatalf("accepted reservations = %d, want %d", got, DefaultLoginFailureLimit)
	}
	if got := limited.Load(); got != 50-DefaultLoginFailureLimit {
		t.Fatalf("limited reservations = %d, want %d", got, 50-DefaultLoginFailureLimit)
	}
}

func TestGlobalLoginAttemptLimiterTemporarilyLocksThenResets(t *testing.T) {
	t.Parallel()

	manager, username, password := newTestAdminAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	for attempt := 0; attempt < manager.loginFailureLimit; attempt++ {
		if _, err := manager.Login(username, "wrong password phrase indeed"); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("failed Login() attempt %d error = %v", attempt+1, err)
		}
	}
	if _, err := manager.Login(username, password); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatalf("valid Login() while limiter active error = %v, want ErrLoginRateLimited", err)
	}

	now = now.Add(manager.loginFailureWindow)
	if _, err := manager.Login(username, password); err != nil {
		t.Fatalf("valid Login() after window expiry error = %v", err)
	}
	if _, err := manager.Login(username, "wrong password phrase indeed"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("successful login did not reset limiter: %v", err)
	}
}

func TestSessionAuthenticationIdleExpiryCSRFAndLogout(t *testing.T) {
	t.Parallel()

	manager, username, password := newTestAdminAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.sessionIdleTimeout = 10 * time.Minute
	manager.sessionAbsoluteTimeout = time.Hour

	session, err := manager.Login(username, password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if len(session.Token) != encodedCredentialLength ||
		len(session.CSRFToken) != encodedCredentialLength {
		t.Fatalf("Login() returned malformed session: %+v", session)
	}
	if want := now.Add(time.Hour); !session.ExpiresAt.Equal(want) {
		t.Fatalf("session ExpiresAt = %v, want %v", session.ExpiresAt, want)
	}

	authenticated, err := manager.Authenticate(session.Token)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated != session {
		t.Fatalf("Authenticate() = %+v, want %+v", authenticated, session)
	}
	if _, err := manager.Authenticate("not-a-session"); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate(invalid) error = %v, want ErrAuthenticationFailed", err)
	}
	if manager.AuthorizeCSRF(session.Token, "not-a-csrf-token") {
		t.Fatal("AuthorizeCSRF() accepted an invalid token")
	}
	if !manager.AuthorizeCSRF(session.Token, session.CSRFToken) {
		t.Fatal("AuthorizeCSRF() rejected valid credentials")
	}

	now = now.Add(9 * time.Minute)
	if _, err := manager.Authenticate(session.Token); err != nil {
		t.Fatalf("Authenticate() before idle expiry error = %v", err)
	}
	now = now.Add(9 * time.Minute)
	if _, err := manager.Authenticate(session.Token); err != nil {
		t.Fatalf("Authenticate() after idle refresh error = %v", err)
	}
	now = now.Add(10 * time.Minute)
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate() at idle expiry error = %v, want ErrAuthenticationFailed", err)
	}

	replacement, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	manager.Logout(replacement.Token)
	if _, err := manager.Authenticate(replacement.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate() after logout error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestSessionActivityPersistenceDoesNotBlockAuthentication(t *testing.T) {
	t.Parallel()

	manager, username, password := newTestAdminAccessManager(t)
	session, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	manager.sessionPath = "activity-persistence-enabled-for-test"
	manager.activityInterval = time.Nanosecond
	manager.activityPersistedAt = time.Time{}
	manager.persistSnapshotHook = func(map[[sha256.Size]byte]*memorySession) error {
		close(started)
		<-release
		close(finished)
		return nil
	}

	if _, err := manager.Authenticate(session.Token); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("activity persistence did not start")
	}

	authenticated := make(chan error, 1)
	go func() {
		_, err := manager.Authenticate(session.Token)
		authenticated <- err
	}()
	select {
	case err := <-authenticated:
		if err != nil {
			t.Fatalf("concurrent Authenticate() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication blocked on session persistence")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("activity persistence did not finish")
	}
}

func TestPersistentSessionSurvivesManagerRestartAndLogout(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	accessPath := filepath.Join(directory, "access.json")
	sessionPath := filepath.Join(directory, "web-sessions.json")
	if err := initializeAdminAccessWithPasswordDeriver(
		accessPath,
		testAdminUsername,
		[]byte(testAdminPassword),
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	); err != nil {
		t.Fatal(err)
	}
	// Sessions are reloaded with the real clock inside
	// loadAccessWithPasswordDeriverAndSessions (the injected now is only
	// applied afterwards), so a hardcoded date goes stale within a day and
	// the reloaded session would be dropped as idle-expired.
	now := time.Now().UTC().Truncate(time.Second)
	load := func() *AccessManager {
		manager, err := loadAccessWithPasswordDeriverAndSessions(
			accessPath,
			sessionPath,
			fastTestPasswordDeriver,
		)
		if err != nil {
			t.Fatal(err)
		}
		manager.passwordKDFGate = make(chan struct{}, 1)
		manager.now = func() time.Time { return now }
		return manager
	}
	first := load()
	session, err := first.Login(testAdminUsername, testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(session.Token)) {
		t.Fatal("session file contains the plaintext bearer token")
	}
	second := load()
	authenticated, err := second.Authenticate(session.Token)
	if err != nil {
		t.Fatalf("Authenticate() after restart error = %v", err)
	}
	if authenticated.CSRFToken != session.CSRFToken {
		t.Fatal("restored session has a different CSRF token")
	}
	if err := second.Logout(session.Token); err != nil {
		t.Fatal(err)
	}
	third := load()
	if _, err := third.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("logged-out session survived restart: %v", err)
	}
}

func TestFailedCSRFAttemptDoesNotRefreshIdleExpiry(t *testing.T) {
	t.Parallel()

	manager, username, password := newTestAdminAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.sessionIdleTimeout = 10 * time.Minute

	session, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	if manager.AuthorizeCSRF(session.Token, strings.Repeat("A", encodedCredentialLength)) {
		t.Fatal("AuthorizeCSRF() accepted the wrong token")
	}
	now = now.Add(2 * time.Minute)
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("failed CSRF kept session alive; Authenticate() error = %v", err)
	}
}

func TestSessionAbsoluteExpiryCannotBeExtended(t *testing.T) {
	t.Parallel()

	manager, username, password := newTestAdminAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.sessionIdleTimeout = 10 * time.Minute
	manager.sessionAbsoluteTimeout = 25 * time.Minute

	session, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	for _, elapsed := range []time.Duration{9, 18, 24} {
		now = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC).
			Add(elapsed * time.Minute)
		if _, err := manager.Authenticate(session.Token); err != nil {
			t.Fatalf("Authenticate() at %v error = %v", elapsed*time.Minute, err)
		}
	}
	now = time.Date(2026, 7, 27, 12, 25, 0, 0, time.UTC)
	if _, err := manager.Authenticate(session.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Authenticate() at absolute expiry error = %v", err)
	}
}

func TestSessionsAreBoundedAndCanAllBeInvalidated(t *testing.T) {
	t.Parallel()

	manager, username, password := newTestAdminAccessManager(t)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.maxSessions = 2

	first, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	second, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	third, err := manager.Login(username, password)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Authenticate(first.Token); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("oldest session was not evicted: %v", err)
	}
	if _, err := manager.Authenticate(second.Token); err != nil {
		t.Fatalf("second session was unexpectedly evicted: %v", err)
	}
	if _, err := manager.Authenticate(third.Token); err != nil {
		t.Fatalf("newest session was unexpectedly evicted: %v", err)
	}

	manager.InvalidateAllSessions()
	for _, token := range []string{second.Token, third.Token} {
		if _, err := manager.Authenticate(token); !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("InvalidateAllSessions() left a valid session: %v", err)
		}
	}
}

func TestSessionCookieSecurityAttributes(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 7, 28, 0, 0, 0, 0, time.FixedZone("test", 3600))
	cookie := NewSessionCookie("session-token", expiresAt)
	if cookie.Name != SessionCookieName ||
		cookie.Path != "/" ||
		cookie.Domain != "" ||
		!cookie.Secure ||
		!cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode ||
		!cookie.Expires.Equal(expiresAt.UTC()) {
		t.Fatalf("insecure session cookie: %+v", cookie)
	}

	deleted := DeleteSessionCookie()
	if deleted.Name != SessionCookieName ||
		deleted.Value != "" ||
		deleted.Path != "/" ||
		deleted.Domain != "" ||
		!deleted.Secure ||
		!deleted.HttpOnly ||
		deleted.SameSite != http.SameSiteStrictMode ||
		deleted.MaxAge != -1 ||
		!deleted.Expires.Before(time.Now()) {
		t.Fatalf("insecure deletion cookie: %+v", deleted)
	}
}

func newTestAccessManager(t *testing.T) (*AccessManager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.json")
	accessKey, err := InitializeAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := LoadAccess(path)
	if err != nil {
		t.Fatal(err)
	}
	return manager, accessKey
}

func newTestAdminAccessManager(t *testing.T) (*AccessManager, string, string) {
	t.Helper()
	manager, username := newTestAdminAccessManagerWithPassword(t, testAdminPassword)
	return manager, username, testAdminPassword
}

func newTestAdminAccessManagerWithPassword(
	t *testing.T,
	password string,
) (*AccessManager, string) {
	t.Helper()
	path := createTestAdminAccessFile(t, password)
	manager, err := loadAccessWithPasswordDeriver(path, fastTestPasswordDeriver)
	if err != nil {
		t.Fatal(err)
	}
	manager.passwordKDFGate = make(chan struct{}, 1)
	return manager, testAdminUsername
}

func createTestAdminAccessFile(t *testing.T, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.json")
	if err := initializeAdminAccessWithPasswordDeriver(
		path,
		testAdminUsername,
		[]byte(password),
		fastTestPasswordDeriver,
		nilSafeRandomReader{},
	); err != nil {
		t.Fatal(err)
	}
	return path
}

func fastTestPasswordDeriver(password, salt []byte) [passwordHashBytes]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("theatropolis test password derivation\x00"))
	_, _ = hash.Write(salt)
	_, _ = hash.Write(password)
	sum := hash.Sum(nil)
	defer clear(sum)
	var result [passwordHashBytes]byte
	copy(result[:], sum)
	return result
}

type nilSafeRandomReader struct{}

var testRandomCounter atomic.Uint64

func (nilSafeRandomReader) Read(destination []byte) (int, error) {
	value := testRandomCounter.Add(1)
	for index := range destination {
		destination[index] = byte(value + uint64(index))
	}
	return len(destination), nil
}

type alwaysErrorReader struct{}

func (alwaysErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("injected random source failure")
}

func validTestPasswordDocument() passwordAccessDocument {
	salt := make([]byte, passwordSaltBytes)
	hash := fastTestPasswordDeriver([]byte(testAdminPassword), salt)
	return passwordAccessDocument{
		Version:       adminAccessFileVersion,
		Type:          passwordDocumentType,
		Username:      testAdminUsername,
		Algorithm:     "argon2id",
		Argon2Version: argon2IDVersion,
		MemoryKiB:     argon2MemoryKiB,
		Iterations:    argon2Iterations,
		Parallelism:   argon2Parallelism,
		Salt:          base64.RawURLEncoding.EncodeToString(salt),
		PasswordHash:  base64.RawURLEncoding.EncodeToString(hash[:]),
	}
}

func passwordDocumentMap(t *testing.T, document passwordAccessDocument) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func readPasswordDocument(t *testing.T, path string) passwordAccessDocument {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document passwordAccessDocument
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func writeAccessTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNewFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("access file permissions = %o, want 0600", info.Mode().Perm())
	}
}
