package singboxupdate

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
	requestFileName    = "sing-box-update-request.json"
	processingFileName = ".sing-box-update-request.processing.json"
	resultFileName     = "sing-box-update-result.json"
	maxMetadataBytes   = 4 << 20
	maxArchiveBytes    = 96 << 20
	maxComponentBytes  = 80 << 20
)

var (
	ErrUpdatePending = errors.New("a sing-box update is already pending")
	versionPattern   = regexp.MustCompile(
		`\Av(?:1\.(?:1[4-9]|[2-9][0-9])|[2-9][0-9]*\.[0-9]+)\.[0-9]+(?:-(?:alpha|beta|rc)\.[0-9]+)?\z`,
	)
	requestIDPattern = regexp.MustCompile(`\A[A-Za-z0-9_-]{16,128}\z`)
	digestPattern    = regexp.MustCompile(`\Asha256:([0-9a-f]{64})\z`)
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
		return nil, errors.New("sing-box update state directory is required")
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
	if !ValidRequestID(requestID) {
		return errors.New("sing-box update request ID is invalid")
	}
	if !ValidVersion(targetVersion) {
		return errors.New("target sing-box version is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range []string{requestFileName, processingFileName} {
		if _, err := os.Lstat(filepath.Join(s.stateDirectory, name)); err == nil {
			return ErrUpdatePending
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect pending sing-box update: %w", err)
		}
	}
	encoded, err := json.Marshal(Request{
		Version: 1, RequestID: requestID, TargetVersion: targetVersion,
	})
	if err != nil {
		return fmt.Errorf("encode sing-box update request: %w", err)
	}
	return writeAtomic(
		filepath.Join(s.stateDirectory, requestFileName),
		append(encoded, '\n'),
		0o600,
	)
}

func (s *Scheduler) LoadResult() (Result, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Result
	exists, err := readExactJSON(
		filepath.Join(s.stateDirectory, resultFileName),
		&result,
	)
	if err != nil || !exists {
		return Result{}, exists, err
	}
	if result.Version != 1 || !ValidRequestID(result.RequestID) ||
		!ValidVersion(result.TargetVersion) ||
		(result.Status != "applied" && result.Status != "failed") {
		return Result{}, false, errors.New("sing-box update result is invalid")
	}
	return result, true, nil
}

func (s *Scheduler) AcknowledgeResult(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result Result
	path := filepath.Join(s.stateDirectory, resultFileName)
	exists, err := readExactJSON(path, &result)
	if err != nil || !exists {
		return err
	}
	if result.RequestID != requestID {
		return errors.New("sing-box update result changed before acknowledgment")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove sing-box update result: %w", err)
	}
	return nil
}

type ApplyOptions struct {
	StateDirectory string
	InstallPath    string
	LibraryPath    string
	Architecture   string
	RunningVersion string
	ValidationUser string
	HTTPClient     *http.Client
	Restart        func(context.Context) error
}

func Apply(ctx context.Context, options ApplyOptions) error {
	if strings.TrimSpace(options.StateDirectory) == "" ||
		strings.TrimSpace(options.InstallPath) == "" ||
		strings.TrimSpace(options.LibraryPath) == "" {
		return errors.New("sing-box update paths are required")
	}
	if strings.TrimSpace(options.ValidationUser) == "" {
		return errors.New("sing-box validation user is required")
	}
	architecture := options.Architecture
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	if architecture != "amd64" && architecture != "arm64" {
		return errors.New("sing-box updates support only amd64 and arm64")
	}
	stateDirectory := filepath.Clean(options.StateDirectory)
	requestPath := filepath.Join(stateDirectory, requestFileName)
	processingPath := filepath.Join(stateDirectory, processingFileName)
	if _, err := os.Lstat(processingPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(requestPath, processingPath); err != nil {
			return fmt.Errorf("claim sing-box update request: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("inspect sing-box update request: %w", err)
	}
	defer os.Remove(processingPath)

	var request Request
	exists, err := readExactJSON(processingPath, &request)
	if err != nil {
		return err
	}
	if !exists || request.Version != 1 || !ValidRequestID(request.RequestID) ||
		!ValidVersion(request.TargetVersion) {
		return errors.New("sing-box update request is invalid")
	}
	result := Result{
		Version: 1, RequestID: request.RequestID,
		TargetVersion:  request.TargetVersion,
		RunningVersion: options.RunningVersion,
		Status:         "failed", ObservedAt: time.Now().UTC(),
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
	if applyErr != nil {
		return applyErr
	}
	restart := options.Restart
	if restart == nil {
		restart = func(ctx context.Context) error {
			return exec.CommandContext(
				ctx, "systemctl", "restart", "theatropolis-agent.service",
			).Run()
		}
	}
	if err := restart(ctx); err != nil {
		result.Status = "failed"
		result.RunningVersion = options.RunningVersion
		result.Diagnostic = sanitizeDiagnostic("sing-box was installed but the agent service could not be restarted: " + err.Error())
		result.ObservedAt = time.Now().UTC()
		if writeErr := writeResult(resultPath, result); writeErr != nil {
			return errors.Join(err, writeErr)
		}
		return fmt.Errorf("restart agent after sing-box update: %w", err)
	}
	return nil
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Draft   bool          `json:"draft"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
	BrowserDownloadURL string `json:"browser_download_url"`
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
		client = secureHTTPClient()
	}
	apiURL := "https://api.github.com/repos/SagerNet/sing-box/releases/tags/" +
		request.TargetVersion
	metadata, err := download(ctx, client, apiURL, maxMetadataBytes)
	if err != nil {
		return fmt.Errorf("download sing-box release metadata: %w", err)
	}
	var release githubRelease
	if err := json.Unmarshal(metadata, &release); err != nil {
		return errors.New("sing-box release metadata is invalid")
	}
	if release.Draft || release.TagName != request.TargetVersion {
		return errors.New("sing-box release tag did not match the requested version")
	}
	version := strings.TrimPrefix(request.TargetVersion, "v")
	assetName := "sing-box-" + version + "-linux-" + architecture + ".tar.gz"
	var selected *githubAsset
	for index := range release.Assets {
		if release.Assets[index].Name == assetName {
			if selected != nil {
				return errors.New("sing-box release contains duplicate target assets")
			}
			selected = &release.Assets[index]
		}
	}
	if selected == nil || selected.Size <= 0 || selected.Size > maxArchiveBytes {
		return errors.New("sing-box release does not contain a valid target archive")
	}
	digestMatch := digestPattern.FindStringSubmatch(selected.Digest)
	if len(digestMatch) != 2 {
		return errors.New("sing-box release is missing its SHA-256 digest")
	}
	expectedURL := "https://github.com/SagerNet/sing-box/releases/download/" +
		request.TargetVersion + "/" + assetName
	if selected.BrowserDownloadURL != expectedURL {
		return errors.New("sing-box release returned an unexpected download URL")
	}
	archive, err := download(ctx, client, selected.BrowserDownloadURL, maxArchiveBytes)
	if err != nil {
		return fmt.Errorf("download sing-box release: %w", err)
	}
	actualDigest := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(actualDigest[:]), digestMatch[1]) {
		return errors.New("sing-box release checksum verification failed")
	}
	binary, library, err := extractArchive(archive, version, architecture)
	if err != nil {
		return err
	}
	return installComponents(ctx, options, request.TargetVersion, binary, library)
}

func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			host := strings.ToLower(request.URL.Hostname())
			if request.URL.Scheme != "https" ||
				(host != "api.github.com" && host != "github.com" &&
					!strings.HasSuffix(host, ".githubusercontent.com")) {
				return errors.New("sing-box download redirected to an untrusted host")
			}
			return nil
		},
	}
}

func download(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "theatropolis-agent")
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

func extractArchive(archive []byte, version, architecture string) ([]byte, []byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, nil, errors.New("sing-box release is not a valid gzip archive")
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	prefix := "sing-box-" + version + "-linux-" + architecture + "/"
	var binary, library []byte
	seen := make(map[string]bool)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, errors.New("sing-box release is not a valid tar archive")
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.ToSlash(header.Name)
		if name != prefix+"sing-box" && name != prefix+"libcronet.so" {
			continue
		}
		if seen[name] || header.Size <= 0 || header.Size > maxComponentBytes {
			return nil, nil, errors.New("sing-box release contains an invalid component")
		}
		seen[name] = true
		content, err := io.ReadAll(io.LimitReader(reader, maxComponentBytes+1))
		if err != nil || int64(len(content)) != header.Size {
			return nil, nil, errors.New("sing-box release component could not be read")
		}
		if name == prefix+"sing-box" {
			binary = content
		} else {
			library = content
		}
	}
	if len(binary) == 0 || len(library) == 0 {
		return nil, nil, errors.New("sing-box release is missing required components")
	}
	return binary, library, nil
}

func installComponents(
	ctx context.Context,
	options ApplyOptions,
	targetVersion string,
	binary, library []byte,
) error {
	binaryPath := filepath.Clean(options.InstallPath)
	libraryPath := filepath.Clean(options.LibraryPath)
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		return fmt.Errorf("create sing-box binary directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(libraryPath), 0o755); err != nil {
		return fmt.Errorf("create sing-box library directory: %w", err)
	}
	tempDirectory, err := os.MkdirTemp(filepath.Dir(binaryPath), ".sing-box-update-*")
	if err != nil {
		return fmt.Errorf("create sing-box update directory: %w", err)
	}
	defer os.RemoveAll(tempDirectory)
	if err := os.Chmod(tempDirectory, 0o755); err != nil {
		return fmt.Errorf("make sing-box update directory traversable: %w", err)
	}
	tempBinary := filepath.Join(tempDirectory, "sing-box")
	tempLibrary := filepath.Join(tempDirectory, "libcronet.so")
	if err := os.WriteFile(tempBinary, binary, 0o755); err != nil {
		return fmt.Errorf("write candidate sing-box binary: %w", err)
	}
	if err := os.Chmod(tempBinary, 0o755); err != nil {
		return fmt.Errorf("make candidate sing-box executable: %w", err)
	}
	if err := os.WriteFile(tempLibrary, library, 0o644); err != nil {
		return fmt.Errorf("write candidate sing-box library: %w", err)
	}
	if err := os.Chmod(tempLibrary, 0o644); err != nil {
		return fmt.Errorf("make candidate sing-box library readable: %w", err)
	}
	command := exec.CommandContext(ctx, tempBinary, "version")
	if err := configureUnprivilegedCommand(
		command,
		options.ValidationUser,
		filepath.Clean(options.StateDirectory),
		tempDirectory,
	); err != nil {
		return err
	}
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(
		string(output),
		"sing-box version "+strings.TrimPrefix(targetVersion, "v"),
	) {
		return errors.New("candidate sing-box executable failed version verification")
	}
	activeConfigPath := filepath.Join(
		filepath.Clean(options.StateDirectory),
		"sing-box",
		"active.json",
	)
	if info, statErr := os.Lstat(activeConfigPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return errors.New("active sing-box configuration is not a valid regular file")
		}
		checkCommand := exec.CommandContext(
			ctx,
			tempBinary,
			"check",
			"-c",
			activeConfigPath,
		)
		if err := configureUnprivilegedCommand(
			checkCommand,
			options.ValidationUser,
			filepath.Clean(options.StateDirectory),
			tempDirectory,
		); err != nil {
			return err
		}
		checkCommand.Stdout = io.Discard
		checkCommand.Stderr = io.Discard
		if err := checkCommand.Run(); err != nil {
			return errors.New("selected sing-box version rejected the active configuration")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("active sing-box configuration could not be inspected")
	}
	return replaceComponents(
		binaryPath,
		libraryPath,
		binary,
		library,
	)
}

func stageFile(path string, contents []byte, mode os.FileMode) (string, error) {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".theatropolis-update-*")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		os.Remove(tempName)
		return "", err
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		os.Remove(tempName)
		return "", err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		os.Remove(tempName)
		return "", err
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return "", err
	}
	return tempName, nil
}

func replaceComponents(
	binaryPath, libraryPath string,
	binary, library []byte,
) (replaceErr error) {
	stagedBinary, err := stageFile(binaryPath, binary, 0o755)
	if err != nil {
		return fmt.Errorf("stage sing-box executable: %w", err)
	}
	defer os.Remove(stagedBinary)
	stagedLibrary, err := stageFile(libraryPath, library, 0o644)
	if err != nil {
		return fmt.Errorf("stage sing-box library: %w", err)
	}
	defer os.Remove(stagedLibrary)

	binaryBackup, binaryExisted, err := moveToBackup(binaryPath)
	if err != nil {
		return fmt.Errorf("back up sing-box executable: %w", err)
	}
	libraryBackup, libraryExisted, err := moveToBackup(libraryPath)
	if err != nil {
		restoreBackup(binaryPath, binaryBackup, binaryExisted)
		return fmt.Errorf("back up sing-box library: %w", err)
	}
	defer func() {
		if replaceErr != nil {
			restoreBackup(binaryPath, binaryBackup, binaryExisted)
			restoreBackup(libraryPath, libraryBackup, libraryExisted)
			return
		}
		os.Remove(binaryBackup)
		os.Remove(libraryBackup)
	}()
	if err := os.Rename(stagedLibrary, libraryPath); err != nil {
		return fmt.Errorf("install sing-box library: %w", err)
	}
	if err := os.Rename(stagedBinary, binaryPath); err != nil {
		return fmt.Errorf("install sing-box executable: %w", err)
	}
	return nil
}

func moveToBackup(path string) (string, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() {
		return "", false, errors.New("installed component is not a regular file")
	}
	placeholder, err := os.CreateTemp(
		filepath.Dir(path),
		".theatropolis-backup-*",
	)
	if err != nil {
		return "", false, err
	}
	backupPath := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		os.Remove(backupPath)
		return "", false, err
	}
	if err := os.Remove(backupPath); err != nil {
		return "", false, err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return "", false, err
	}
	return backupPath, true, nil
}

func restoreBackup(path, backupPath string, existed bool) {
	_ = os.Remove(path)
	if existed {
		_ = os.Rename(backupPath, path)
	}
}

func writeResult(path string, result Result) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode sing-box update result: %w", err)
	}
	return writeAtomic(path, append(encoded, '\n'), 0o644)
}

func readExactJSON(path string, destination any) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
		return false, errors.New("sing-box update metadata is not a regular file or exceeds the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxMetadataBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return false, errors.New("sing-box update metadata contains trailing data")
	}
	return true, nil
}

func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".sing-box-update-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func sanitizeDiagnostic(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' ||
			character >= 0x20 && character != 0x7f {
			return character
		}
		return -1
	}, value)
	if len(value) > 2048 {
		value = value[:2048]
	}
	return strings.TrimSpace(value)
}
