//go:build !windows

package singboxupdate

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func configureUnprivilegedCommand(
	command *exec.Cmd,
	username, stateDirectory, libraryDirectory string,
) error {
	account, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("look up sing-box validation user: %w", err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errors.New("sing-box validation user must be an unprivileged numeric account")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return errors.New("sing-box validation group is invalid")
	}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid:    uint32(uid),
		Gid:    uint32(gid),
		Groups: []uint32{},
	}}
	command.Dir = stateDirectory
	command.Env = []string{
		"HOME=" + stateDirectory,
		"LD_LIBRARY_PATH=" + libraryDirectory,
		"PATH=/usr/bin:/bin",
		"XDG_DATA_HOME=" + stateDirectory + "/data",
	}
	return nil
}
