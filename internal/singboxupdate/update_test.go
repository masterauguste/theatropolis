package singboxupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseSigningPublicKeyFingerprint(t *testing.T) {
	t.Parallel()
	block, trailing := pem.Decode([]byte(releaseSigningPublicKeyPEM))
	if block == nil || len(trailing) != 0 || block.Type != "PUBLIC KEY" {
		t.Fatal("embedded release signing public key is invalid")
	}
	digest := sha256.Sum256(block.Bytes)
	const want = "3b76197b4c5e4bd3b368610d3367f1f6d5b16f0893f4f57fda878ba7de97fb13"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("release signing public key fingerprint = %q, want %q", got, want)
	}
}

func TestValidVersionAcceptsSupportedStableAndPrerelease(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"v1.14.0-theatropolis.1",
		"v1.14.0-rc.1.theatropolis.1",
		"v2.0.0-theatropolis.12",
		"v10.0.0-rc.1.theatropolis.2",
	} {
		if !ValidVersion(value) {
			t.Errorf("ValidVersion(%q) = false", value)
		}
	}
	for _, value := range []string{
		"1.14.0",
		"v1.13.12",
		"v1.14.0",
		"v1.14.0-rc.1",
		"v1.14.0-alpha.27",
		"v1.14.0-beta.2",
		"v1.14.0-dev",
		"v1.14.0-alpha.1/../../x",
		"latest",
	} {
		if ValidVersion(value) {
			t.Errorf("ValidVersion(%q) = true", value)
		}
	}
}

func TestVerifyBuildManifestRequiresManagedUserCapabilities(t *testing.T) {
	t.Parallel()
	valid := []byte(`{
		"schema_version":2,
		"release":{"tag":"v1.14.0-rc.1.theatropolis.1","version":"1.14.0-rc.1.theatropolis.1"},
		"patchset":{"capabilities":["managed-users-v1","anytls-live-users","hysteria2-live-users","session-revocation-v1","traffic-reset-v1"]},
		"build":{"tags":["with_v2ray_api","with_theatropolis_managed_users"]}
	}`)
	if err := verifyBuildManifest(valid, "v1.14.0-rc.1.theatropolis.1"); err != nil {
		t.Fatal(err)
	}
	invalid := bytes.Replace(valid, []byte("session-revocation-v1"), []byte("other-capability"), 1)
	if err := verifyBuildManifest(invalid, "v1.14.0-rc.1.theatropolis.1"); err == nil {
		t.Fatal("manifest without session revocation was accepted")
	}
	invalid = bytes.Replace(valid, []byte("traffic-reset-v1"), []byte("other-capability"), 1)
	if err := verifyBuildManifest(invalid, "v1.14.0-rc.1.theatropolis.1"); err == nil {
		t.Fatal("manifest without traffic reset was accepted")
	}
}

func TestVerifyChecksumManifestAndSelectArchiveDigest(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	manifest := []byte(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  sing-box-1.14.0-rc.1-linux-amd64.tar.gz\n" +
			"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  sing-box-1.14.0-rc.1-linux-arm64.tar.gz\n",
	)
	digest := sha256.Sum256(manifest)
	signature, err := rsa.SignPSS(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyChecksumManifest(manifest, signature, publicPEM); err != nil {
		t.Fatal(err)
	}
	want := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := checksumForAsset(
		manifest,
		"sing-box-1.14.0-rc.1-linux-amd64.tar.gz",
	)
	if err != nil || got != want {
		t.Fatalf("checksumForAsset() = %q, %v, want %q", got, err, want)
	}
	manifest[0] = 'f'
	if err := verifyChecksumManifest(manifest, signature, publicPEM); err == nil {
		t.Fatal("modified manifest passed signature verification")
	}
}

func TestChecksumForAssetRejectsMalformedAndDuplicateEntries(t *testing.T) {
	t.Parallel()
	const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, manifest := range []string{
		digest + "  archive.tar.gz",
		strings.ToUpper(digest) + "  archive.tar.gz\n",
		digest + "  archive.tar.gz\n" + digest + "  archive.tar.gz\n",
		digest + " archive.tar.gz extra\n",
	} {
		if _, err := checksumForAsset([]byte(manifest), "archive.tar.gz"); err == nil {
			t.Fatalf("malformed manifest was accepted: %q", manifest)
		}
	}
}

func TestVersionOutputHasTagRequiresExactBuildTag(t *testing.T) {
	t.Parallel()
	output := "sing-box version 1.14.0-rc.1.theatropolis.1\n\nEnvironment: go1.26 linux/amd64\nTags: with_quic, with_v2ray_api, with_theatropolis_managed_users, with_acme\n"
	if !versionOutputHasTag(output, "with_v2ray_api") {
		t.Fatal("expected V2Ray API build tag was not detected")
	}
	if !versionOutputHasTag(output, "with_theatropolis_managed_users") {
		t.Fatal("expected managed-user build tag was not detected")
	}
	for _, tag := range []string{"v2ray_api", "with_v2ray", "with_v2ray_api_extra"} {
		if versionOutputHasTag(output, tag) {
			t.Fatalf("non-exact build tag %q was accepted", tag)
		}
	}
}

func TestSchedulerUsesIndependentSecureStateFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	scheduler, err := NewScheduler(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Schedule(
		"singbox_0123456789abcdef",
		"v1.14.0-rc.1.theatropolis.1",
	); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, requestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("request mode = %o, want 600", info.Mode().Perm())
	}
	if err := scheduler.Schedule(
		"singbox_fedcba9876543210",
		"v1.14.0-theatropolis.1",
	); err != ErrUpdatePending {
		t.Fatalf("second schedule error = %v, want ErrUpdatePending", err)
	}
}

func TestExtractArchiveRequiresBinaryAndCronetLibrary(t *testing.T) {
	t.Parallel()
	archive := testArchive(t, map[string][]byte{
		"sing-box-1.14.0-rc.1-linux-amd64/sing-box":     []byte("binary"),
		"sing-box-1.14.0-rc.1-linux-amd64/libcronet.so": []byte("library"),
		"sing-box-1.14.0-rc.1-linux-amd64/LICENSE":      []byte("license"),
	})
	binary, library, err := extractArchive(
		archive,
		"1.14.0-rc.1",
		"amd64",
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(binary) != "binary" || string(library) != "library" {
		t.Fatalf("unexpected extracted components %q %q", binary, library)
	}
}

func testArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, contents := range files {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(contents)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
