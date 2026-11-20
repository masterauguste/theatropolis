//go:build windows

package singboxupdate

import (
	"errors"
	"os/exec"
)

func configureUnprivilegedCommand(
	_ *exec.Cmd,
	_, _, _ string,
) error {
	return errors.New("privileged sing-box updates are not supported on Windows")
}
