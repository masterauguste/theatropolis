package singbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

const executableCheckTimeout = 5 * time.Second

var singBoxVersionPattern = regexp.MustCompile(
	`(?m)^sing-box version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][0-9A-Za-z.-]+)?\r?$`,
)

// CheckSupportedExecutable verifies that binaryPath is a runnable sing-box
// 1.14+ executable without returning any of its output to callers.
func CheckSupportedExecutable(ctx context.Context, binaryPath string) error {
	_, err := ExecutableVersion(ctx, binaryPath)
	return err
}

// ExecutableVersion verifies binaryPath and returns its canonical v-prefixed
// version for status reporting and exact-version update decisions.
func ExecutableVersion(ctx context.Context, binaryPath string) (string, error) {
	info, err := os.Stat(binaryPath)
	if err != nil {
		return "", errors.New("sing-box executable is unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("sing-box executable is not a runnable regular file")
	}

	checkContext, cancel := context.WithTimeout(ctx, executableCheckTimeout)
	defer cancel()
	output := newLimitedBuffer(DefaultMaxDiagnosticBytes)
	command := exec.CommandContext(checkContext, binaryPath, "version")
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return "", errors.New("sing-box version could not be verified")
	}
	major, minor, ok := parseSingBoxVersion(output.String())
	if !ok {
		return "", errors.New("sing-box returned an unrecognized version")
	}
	if major < 1 || major == 1 && minor < 14 {
		return "", errors.New("sing-box 1.14 or newer is required")
	}
	versionMatch := regexp.MustCompile(
		`(?m)^sing-box version ([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)\r?$`,
	).FindStringSubmatch(output.String())
	if len(versionMatch) != 2 {
		return "", errors.New("sing-box returned an unrecognized version")
	}
	return "v" + versionMatch[1], nil
}

func parseSingBoxVersion(output string) (major int, minor int, ok bool) {
	match := singBoxVersionPattern.FindStringSubmatch(output)
	if len(match) != 4 {
		return 0, 0, false
	}
	major, majorErr := strconv.Atoi(match[1])
	minor, minorErr := strconv.Atoi(match[2])
	if majorErr != nil || minorErr != nil {
		return 0, 0, false
	}
	return major, minor, true
}
