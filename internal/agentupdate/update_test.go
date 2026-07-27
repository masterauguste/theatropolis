package agentupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestApplyInstallsExactRequestedRelease(t *testing.T) {
	t.Parallel()
	stateDirectory := filepath.Join(t.TempDir(), "state")
	scheduler, err := NewScheduler(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	const requestID = "request_0123456789abcdef"
	const targetVersion = "v1.2.3-beta.1"
	if err := scheduler.Schedule(requestID, targetVersion); err != nil {
		t.Fatal(err)
	}

	archive := testArchive(t, map[string][]byte{
		"theatropolis-agent":  []byte("new agent"),
		"theatropolis-master": []byte("new master"),
	})
	digest := sha256.Sum256(archive)
	manifest := hex.EncodeToString(digest[:]) +
		"  theatropolis_linux_arm64.tar.gz\n"
	var requested []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested = append(requested, request.URL.String())
		body := []byte(manifest)
		if strings.HasSuffix(request.URL.Path, ".tar.gz") {
			body = archive
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Request:       request,
		}, nil
	})}
	installPath := filepath.Join(t.TempDir(), "theatropolis-agent")
	if err := os.WriteFile(installPath, []byte("old agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	restarted := false
	err = Apply(context.Background(), ApplyOptions{
		StateDirectory: stateDirectory,
		InstallPath:    installPath,
		Architecture:   "arm64",
		RunningVersion: "v1.2.2",
		HTTPClient:     client,
		Restart: func(context.Context) error {
			restarted = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !restarted {
		t.Fatal("agent service was not restarted")
	}
	if got, err := os.ReadFile(installPath); err != nil || string(got) != "new agent" {
		t.Fatalf("installed binary = %q, %v", got, err)
	}
	if len(requested) != 2 {
		t.Fatalf("requested URLs = %v", requested)
	}
	for _, value := range requested {
		if !strings.Contains(value, "/releases/download/"+targetVersion+"/") {
			t.Fatalf("request did not use exact target version: %s", value)
		}
	}
	result, exists, err := scheduler.LoadResult()
	if err != nil || !exists {
		t.Fatalf("load result: exists=%v err=%v", exists, err)
	}
	if result.Status != "applied" || result.RunningVersion != targetVersion {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestApplyRejectsChecksumMismatch(t *testing.T) {
	t.Parallel()
	stateDirectory := filepath.Join(t.TempDir(), "state")
	scheduler, _ := NewScheduler(stateDirectory)
	if err := scheduler.Schedule("request_0123456789abcdef", "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	archive := testArchive(t, map[string][]byte{"theatropolis-agent": []byte("new")})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := []byte(strings.Repeat("0", 64) + "  theatropolis_linux_amd64.tar.gz\n")
		if strings.HasSuffix(request.URL.Path, ".tar.gz") {
			body = archive
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Request:       request,
		}, nil
	})}
	installPath := filepath.Join(t.TempDir(), "theatropolis-agent")
	if err := os.WriteFile(installPath, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Apply(context.Background(), ApplyOptions{
		StateDirectory: stateDirectory,
		InstallPath:    installPath,
		Architecture:   "amd64",
		RunningVersion: "v1.2.2",
		HTTPClient:     client,
		Restart:        func(context.Context) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("Apply error = %v", err)
	}
	if got, _ := os.ReadFile(installPath); string(got) != "old" {
		t.Fatalf("binary changed after failed verification: %q", got)
	}
	result, exists, loadErr := scheduler.LoadResult()
	if loadErr != nil || !exists || result.Status != "failed" {
		t.Fatalf("unexpected failure result: %+v exists=%v err=%v", result, exists, loadErr)
	}
}

func TestExtractAgentBinaryRejectsUnexpectedPath(t *testing.T) {
	t.Parallel()
	archive := testArchive(t, map[string][]byte{
		"../theatropolis-agent": []byte("malicious"),
	})
	if _, err := extractAgentBinary(archive); err == nil {
		t.Fatal("unexpected archive path was accepted")
	}
}

func TestSchedulerRejectsConcurrentRequest(t *testing.T) {
	t.Parallel()
	scheduler, _ := NewScheduler(t.TempDir())
	if err := scheduler.Schedule("request_0123456789abcdef", "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Schedule("request_fedcba9876543210", "v1.2.4"); err != ErrUpdatePending {
		t.Fatalf("second Schedule error = %v", err)
	}
}

func testArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, contents := range entries {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
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
