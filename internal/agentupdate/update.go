package agentupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	requestFileName    = "update-request.json"
	processingFileName = ".update-request.processing.json"
	resultFileName     = "update-result.json"
	maxMetadataBytes   = 16 << 10
	maxChecksumBytes   = 1 << 20
	maxArchiveBytes    = 64 << 20
	maxBinaryBytes     = 64 << 20
)

var (
	ErrUpdatePending = errors.New("an agent update is already pending")
	versionPattern   = regexp.MustCompile(
		`\Av[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9][A-Za-z0-9.-]*)?\z`,
	)
	requestIDPattern = regexp.MustCompile(`\A[A-Za-z0-9_-]{16,128}\z`)
)

type Request struct {
	Version       int    `json:"version"`
	RequestID     string `json:"request_id"`
	TargetVersion string `json:"target_version"`
}

type Result struct {
	Version        int       `json:"version"`
	RequestID      string    `json:"request_id"`
	TargetVersion  string    `json:"target_version"`
	RunningVersion string    `json:"running_version"`
	Status         string    `json:"status"`
	Diagnostic     string    `json:"diagnostic,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
}

type Scheduler struct {
	stateDirectory string
	mu             sync.Mutex
}

func NewScheduler(stateDirectory string) (*Scheduler, error) {
	if strings.TrimSpace(stateDirectory) == "" {
		return nil, errors.New("agent update state directory is required")
	}
	return &Scheduler{stateDirectory: filepath.Clean(stateDirectory)}, nil
}

func ValidVersion(value string) bool {
	return versionPattern.MatchString(value)
}

func ValidRequestID(value string) bool {
	return requestIDPattern.MatchString(value)
}

func (s *Scheduler) Schedule(requestID, targetVersion string) error {
	if !requestIDPattern.MatchString(requestID) {
		return errors.New("update request ID is invalid")
	}
	if !ValidVersion(targetVersion) {
		return errors.New("target agent version is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, path := range []string{s.requestPath(), s.processingPath()} {
		if _, err := os.Lstat(path); err == nil {
			return ErrUpdatePending
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect pending agent update: %w", err)
		}
	}
	encoded, err := json.Marshal(Request{
		Version:       1,
		RequestID:     requestID,
		TargetVersion: targetVersion,
	})
	if err != nil {
		return fmt.Errorf("encode agent update request: %w", err)
	}
	encoded = append(encoded, '\n')
	return writeAtomic(s.requestPath(), encoded, 0o600)
}

func (s *Scheduler) LoadResult() (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Result
	exists, err := readExactJSON(s.resultPath(), &result)
	if err != nil || !exists {
		return Result{}, exists, err
	}
	if err := validateResult(result); err != nil {
		return Result{}, false, err
	}
	return result, true, nil
}

func (s *Scheduler) AcknowledgeResult(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Result
	exists, err := readExactJSON(s.resultPath(), &result)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if result.RequestID != requestID {
		return errors.New("agent update result changed before acknowledgment")
	}
	if err := os.Remove(s.resultPath()); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove agent update result: %w", err)
	}
	return nil
}

func (s *Scheduler) requestPath() string {
	return filepath.Join(s.stateDirectory, requestFileName)
}

func (s *Scheduler) processingPath() string {
	return filepath.Join(s.stateDirectory, processingFileName)
}

func (s *Scheduler) resultPath() string {
	return filepath.Join(s.stateDirectory, resultFileName)
}

type ApplyOptions struct {
	StateDirectory string
	InstallPath    string
	Architecture   string
	RunningVersion string
	HTTPClient     *http.Client
	Restart        func(context.Context) error
}

func Apply(ctx context.Context, options ApplyOptions) error {
	stateDirectory := filepath.Clean(options.StateDirectory)
	if strings.TrimSpace(options.StateDirectory) == "" {
		return errors.New("agent update state directory is required")
	}
	if strings.TrimSpace(options.InstallPath) == "" {
		return errors.New("agent install path is required")
	}
	architecture := options.Architecture
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	if architecture != "amd64" && architecture != "arm64" {
		return errors.New("agent updates support only amd64 and arm64")
	}

	requestPath := filepath.Join(stateDirectory, requestFileName)
	processingPath := filepath.Join(stateDirectory, processingFileName)
	if _, err := os.Lstat(processingPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(requestPath, processingPath); err != nil {
			return fmt.Errorf("claim agent update request: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect claimed agent update request: %w", err)
	}
	defer os.Remove(processingPath)

	var request Request
	exists, err := readExactJSON(processingPath, &request)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("agent update request disappeared")
	}
	if request.Version != 1 ||
		!requestIDPattern.MatchString(request.RequestID) ||
		!ValidVersion(request.TargetVersion) {
		return errors.New("agent update request is invalid")
	}

	result := Result{
		Version:        1,
		RequestID:      request.RequestID,
		TargetVersion:  request.TargetVersion,
		RunningVersion: options.RunningVersion,
		Status:         "failed",
		ObservedAt:     time.Now().UTC(),
	}
	applyErr := applyRelease(ctx, options, request, architecture)
	if applyErr == nil {
		result.Status = "applied"
		result.RunningVersion = request.TargetVersion
	} else {
		result.Diagnostic = sanitizeDiagnostic(applyErr.Error())
	}
	resultPath := filepath.Join(stateDirectory, resultFileName)
	if err := writeResult(resultPath, result); err != nil {
		return err
	}

	restart := options.Restart
	if restart == nil {
		restart = func(ctx context.Context) error {
			return exec.CommandContext(
				ctx,
				"systemctl",
				"restart",
				"theatropolis-agent.service",
			).Run()
		}
	}
	restartErr := restart(ctx)
	if applyErr != nil {
		return applyErr
	}
	if restartErr != nil {
		result.Status = "failed"
		result.RunningVersion = options.RunningVersion
		result.Diagnostic = sanitizeDiagnostic(
			"updated binary was installed but the agent service could not be restarted: " +
				restartErr.Error(),
		)
		result.ObservedAt = time.Now().UTC()
		if err := writeResult(resultPath, result); err != nil {
			return errors.Join(
				fmt.Errorf("restart updated agent: %w", restartErr),
				err,
			)
		}
		return fmt.Errorf("restart updated agent: %w", restartErr)
	}
	return nil
}

func writeResult(path string, result Result) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode agent update result: %w", err)
	}
	return writeAtomic(path, append(encoded, '\n'), 0o644)
}

func applyRelease(
	ctx context.Context,
	options ApplyOptions,
	request Request,
	architecture string,
) error {
	if request.TargetVersion == options.RunningVersion {
		return nil
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 90 * time.Second,
			CheckRedirect: func(request *http.Request, _ []*http.Request) error {
				host := strings.ToLower(request.URL.Hostname())
				if request.URL.Scheme != "https" ||
					(host != "github.com" &&
						!strings.HasSuffix(host, ".githubusercontent.com")) {
					return errors.New("release download redirected to an untrusted host")
				}
				return nil
			},
		}
	}
	baseURL := "https://github.com/masterauguste/theatropolis/releases/download/" +
		request.TargetVersion
	checksums, err := download(ctx, client, baseURL+"/checksums.txt", maxChecksumBytes)
	if err != nil {
		return fmt.Errorf("download release checksums: %w", err)
	}
	archiveName := "theatropolis_linux_" + architecture + ".tar.gz"
	expectedDigest, err := checksumFor(checksums, archiveName)
	if err != nil {
		return err
	}
	archive, err := download(ctx, client, baseURL+"/"+archiveName, maxArchiveBytes)
	if err != nil {
		return fmt.Errorf("download agent release: %w", err)
	}
	actualDigest := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(actualDigest[:]), expectedDigest) {
		return errors.New("agent release checksum verification failed")
	}
	binary, err := extractAgentBinary(archive)
	if err != nil {
		return err
	}
	return installBinary(options.InstallPath, binary)
}

func download(
	ctx context.Context,
	client *http.Client,
	url string,
	limit int64,
) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("download exceeds the size limit")
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, errors.New("download exceeds the size limit")
	}
	return contents, nil
}

func checksumFor(contents []byte, archiveName string) (string, error) {
	var digest string
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != archiveName {
			continue
		}
		if digest != "" {
			return "", errors.New("release checksum manifest contains duplicate entries")
		}
		if len(fields[0]) != sha256.Size*2 {
			return "", errors.New("release checksum is invalid")
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", errors.New("release checksum is invalid")
		}
		digest = strings.ToLower(fields[0])
	}
	if digest == "" {
		return "", errors.New("release checksum is missing")
	}
	return digest, nil
}

func extractAgentBinary(archive []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open agent release archive: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	var binary []byte
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read agent release archive: %w", err)
		}
		if header.Name != "theatropolis-agent" &&
			header.Name != "theatropolis-master" {
			return nil, errors.New("agent release archive contains an unexpected path")
		}
		if header.Typeflag != tar.TypeReg || header.Size < 1 ||
			header.Size > maxBinaryBytes {
			return nil, errors.New("agent release archive contains an unsafe entry")
		}
		if header.Name != "theatropolis-agent" {
			continue
		}
		if binary != nil {
			return nil, errors.New("agent release archive contains duplicate agent binaries")
		}
		binary, err = io.ReadAll(io.LimitReader(tarReader, maxBinaryBytes+1))
		if err != nil || int64(len(binary)) != header.Size {
			return nil, errors.New("agent release archive contains a truncated binary")
		}
	}
	if len(binary) == 0 {
		return nil, errors.New("agent release archive is missing the agent binary")
	}
	return binary, nil
}

func installBinary(path string, binary []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect installed agent: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("installed agent is not a regular file")
	}
	directory := filepath.Dir(path)
	tempFile, err := os.CreateTemp(directory, ".theatropolis-agent-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary agent binary: %w", err)
	}
	tempPath := tempFile.Name()
	installed := false
	defer func() {
		_ = tempFile.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(0o755); err != nil {
		return fmt.Errorf("set agent binary permissions: %w", err)
	}
	if _, err := tempFile.Write(binary); err != nil {
		return fmt.Errorf("write agent binary: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("flush agent binary: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close agent binary: %w", err)
	}
	if err := replaceFile(tempPath, path); err != nil {
		return fmt.Errorf("replace agent binary: %w", err)
	}
	installed = true
	return nil
}

func readExactJSON(path string, destination any) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect agent update metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
		return false, errors.New("agent update metadata is not a regular file or exceeds the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open agent update metadata: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxMetadataBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, fmt.Errorf("decode agent update metadata: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, errors.New("agent update metadata contains trailing data")
	}
	return true, nil
}

func validateResult(result Result) error {
	if result.Version != 1 ||
		!requestIDPattern.MatchString(result.RequestID) ||
		!ValidVersion(result.TargetVersion) ||
		result.ObservedAt.IsZero() {
		return errors.New("agent update result is invalid")
	}
	switch result.Status {
	case "applied", "failed":
	default:
		return errors.New("agent update result has an unknown status")
	}
	return nil
}

func sanitizeDiagnostic(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || character >= ' ' {
			return character
		}
		return -1
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > 2048 {
		value = value[:2048] + "…"
	}
	return value
}

func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create agent update directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("agent update path is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect agent update path: %w", err)
	}
	tempFile, err := os.CreateTemp(directory, ".agent-update-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary agent update file: %w", err)
	}
	tempPath := tempFile.Name()
	installed := false
	defer func() {
		_ = tempFile.Close()
		if !installed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(mode); err != nil {
		return fmt.Errorf("secure temporary agent update file: %w", err)
	}
	if _, err := tempFile.Write(contents); err != nil {
		return fmt.Errorf("write temporary agent update file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("flush temporary agent update file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary agent update file: %w", err)
	}
	if err := replaceFile(tempPath, path); err != nil {
		return fmt.Errorf("replace agent update file: %w", err)
	}
	installed = true
	return nil
}
