package singboxupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidVersionAcceptsSupportedStableAndPrerelease(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"v1.14.0",
		"v1.14.0-alpha.27",
		"v1.14.0-beta.2",
		"v1.14.0-rc.1",
		"v2.0.0",
	} {
		if !ValidVersion(value) {
			t.Errorf("ValidVersion(%q) = false", value)
		}
	}
	for _, value := range []string{
		"1.14.0",
		"v1.13.12",
		"v1.14.0-dev",
		"v1.14.0-alpha.1/../../x",
		"latest",
	} {
		if ValidVersion(value) {
			t.Errorf("ValidVersion(%q) = true", value)
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
		"v1.14.0-beta.2",
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
		"v1.14.0",
	); err != ErrUpdatePending {
		t.Fatalf("second schedule error = %v, want ErrUpdatePending", err)
	}
}

func TestExtractArchiveRequiresBinaryAndCronetLibrary(t *testing.T) {
	t.Parallel()
	archive := testArchive(t, map[string][]byte{
		"sing-box-1.14.0-beta.2-linux-amd64/sing-box":     []byte("binary"),
		"sing-box-1.14.0-beta.2-linux-amd64/libcronet.so": []byte("library"),
		"sing-box-1.14.0-beta.2-linux-amd64/LICENSE":      []byte("license"),
	})
	binary, library, err := extractArchive(
		archive,
		"1.14.0-beta.2",
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
