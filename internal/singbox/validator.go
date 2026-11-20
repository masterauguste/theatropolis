package singbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	DefaultMaxConfigBytes     = 4 << 20
	DefaultMaxDiagnosticBytes = 8 << 10
)

type ValidationStatus string

const (
	ValidationValid         ValidationStatus = "valid"
	ValidationInvalid       ValidationStatus = "invalid"
	ValidationInternalError ValidationStatus = "internal_error"
)

type ValidationResult struct {
	Status              ValidationStatus
	Diagnostic          string
	ConfigSHA256        [sha256.Size]byte
	CheckedAt           time.Time
	Duration            time.Duration
	RawDiagnosticLength int
}

type Validator struct {
	BinaryPath         string
	StateDirectory     string
	MaxConfigBytes     int
	MaxDiagnosticBytes int
	Timeout            time.Duration
	runCommand         func(context.Context, string, string, io.Writer) error
}

func (v Validator) Check(ctx context.Context, config []byte, expectedSHA256 []byte) (result ValidationResult) {
	startedAt := time.Now()
	result = ValidationResult{
		Status:       ValidationInternalError,
		ConfigSHA256: sha256.Sum256(config),
		CheckedAt:    startedAt.UTC(),
	}
	defer func() {
		result.Duration = time.Since(startedAt)
	}()

	maxConfigBytes := v.MaxConfigBytes
	if maxConfigBytes <= 0 {
		maxConfigBytes = DefaultMaxConfigBytes
	}
	if len(config) == 0 {
		result.Diagnostic = "candidate configuration is empty"
		return result
	}
	if len(config) > maxConfigBytes {
		result.Diagnostic = fmt.Sprintf("candidate configuration exceeds the %d-byte limit", maxConfigBytes)
		return result
	}
	if len(expectedSHA256) != sha256.Size ||
		!bytes.Equal(expectedSHA256, result.ConfigSHA256[:]) {
		result.Diagnostic = "candidate configuration digest does not match the deployment command"
		return result
	}
	if !json.Valid(config) {
		result.Status = ValidationInvalid
		result.Diagnostic = "candidate configuration is not valid JSON"
		return result
	}
	if strings.TrimSpace(v.BinaryPath) == "" {
		result.Diagnostic = "sing-box executable path is not configured"
		return result
	}
	if strings.TrimSpace(v.StateDirectory) == "" {
		result.Diagnostic = "sing-box validation directory is not configured"
		return result
	}
	if err := prepareManagedSelfSignedCertificates(
		config,
		v.StateDirectory,
		time.Now(),
	); err != nil {
		result.Diagnostic = "managed self-signed certificate could not be prepared"
		return result
	}

	secrets := collectSecrets(config)
	validationDir := filepath.Join(v.StateDirectory, "validation")
	if err := os.MkdirAll(validationDir, 0o700); err != nil {
		result.Diagnostic = "could not prepare the validation directory"
		return result
	}

	candidate, err := os.CreateTemp(validationDir, "candidate-*.json")
	if err != nil {
		result.Diagnostic = "could not create the candidate configuration"
		return result
	}
	candidatePath := candidate.Name()
	defer func() {
		_ = os.Remove(candidatePath)
	}()

	if err := candidate.Chmod(0o600); err != nil {
		_ = candidate.Close()
		result.Diagnostic = "could not secure the candidate configuration"
		return result
	}
	if _, err := candidate.Write(config); err != nil {
		_ = candidate.Close()
		result.Diagnostic = "could not stage the candidate configuration"
		return result
	}
	if err := candidate.Sync(); err != nil {
		_ = candidate.Close()
		result.Diagnostic = "could not flush the candidate configuration"
		return result
	}
	if err := candidate.Close(); err != nil {
		result.Diagnostic = "could not close the candidate configuration"
		return result
	}

	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	maxDiagnosticBytes := v.MaxDiagnosticBytes
	if maxDiagnosticBytes <= 0 {
		maxDiagnosticBytes = DefaultMaxDiagnosticBytes
	}
	output := newLimitedBuffer(maxDiagnosticBytes)
	runCommand := v.runCommand
	if runCommand == nil {
		err = runSingBoxCheck(
			checkCtx,
			v.BinaryPath,
			candidatePath,
			v.StateDirectory,
			output,
		)
	} else {
		err = runCommand(checkCtx, v.BinaryPath, candidatePath, output)
	}

	rawOutput := output.String()
	result.RawDiagnosticLength = output.Total()
	result.Diagnostic = sanitizeDiagnostic(rawOutput, secrets, validationDir, maxDiagnosticBytes)

	if errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
		result.Status = ValidationInternalError
		result.Diagnostic = appendDiagnostic(result.Diagnostic, "sing-box validation timed out")
		return result
	}
	if err == nil {
		result.Status = ValidationValid
		result.Diagnostic = ""
		return result
	}

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.Status = ValidationInvalid
		if result.Diagnostic == "" {
			result.Diagnostic = "sing-box rejected the candidate configuration"
		}
		return result
	}

	result.Status = ValidationInternalError
	result.Diagnostic = appendDiagnostic(result.Diagnostic, "could not execute sing-box validation")
	return result
}

func runSingBoxCheck(
	ctx context.Context,
	binaryPath string,
	candidatePath string,
	workingDirectory string,
	output io.Writer,
) error {
	command := exec.CommandContext(ctx, binaryPath, "check", "-c", candidatePath)
	command.Dir = workingDirectory
	command.Stdout = output
	command.Stderr = output
	return command.Run()
}

var userInfoPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`)

func sanitizeDiagnostic(raw string, secrets []string, stateDirectory string, limit int) string {
	clean := strings.ReplaceAll(raw, stateDirectory, "<validation-directory>")
	clean = userInfoPattern.ReplaceAllString(clean, "${1}<redacted>@")
	for _, secret := range secrets {
		clean = strings.ReplaceAll(clean, secret, "<redacted>")
	}

	clean = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, clean)
	clean = strings.TrimSpace(clean)
	if len(clean) > limit {
		clean = clean[:limit] + "\n<diagnostic truncated>"
	}
	return clean
}

func collectSecrets(config []byte) []string {
	var document any
	if err := json.Unmarshal(config, &document); err != nil {
		return nil
	}

	unique := make(map[string]struct{})
	var visit func(any, string)
	visit = func(value any, key string) {
		switch typed := value.(type) {
		case map[string]any:
			for childKey, childValue := range typed {
				visit(childValue, childKey)
			}
		case []any:
			for _, childValue := range typed {
				visit(childValue, key)
			}
		case string:
			if isSensitiveKey(key) && typed != "" {
				unique[typed] = struct{}{}
			}
		}
	}
	visit(document, "")

	secrets := make([]string, 0, len(unique))
	for secret := range unique {
		secrets = append(secrets, secret)
	}
	sort.Slice(secrets, func(i, j int) bool {
		return len(secrets[i]) > len(secrets[j])
	})
	return secrets
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch normalized {
	case "password",
		"passwd",
		"secret",
		"token",
		"uuid",
		"key",
		"private_key",
		"pre_shared_key",
		"access_key_secret",
		"api_token",
		"zone_token",
		"account_key":
		return true
	default:
		return strings.HasSuffix(normalized, "_password") ||
			strings.HasSuffix(normalized, "_secret") ||
			strings.HasSuffix(normalized, "_token") ||
			strings.HasSuffix(normalized, "_private_key")
	}
}

func appendDiagnostic(current, extra string) string {
	if current == "" {
		return extra
	}
	return current + "\n" + extra
}

type limitedBuffer struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	limit   int
	total   int
	dropped bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.total += len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		_, _ = b.buffer.Write(data[:min(remaining, len(data))])
	}
	if len(data) > remaining {
		b.dropped = true
	}
	return len(data), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	value := b.buffer.String()
	if b.dropped {
		value += "\n<diagnostic truncated>"
	}
	return value
}

func (b *limitedBuffer) Total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

var _ io.Writer = (*limitedBuffer)(nil)
