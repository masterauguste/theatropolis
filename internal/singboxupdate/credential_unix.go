//go:build !windows

package singboxupdate

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
)

const setprivPath = "/usr/bin/setpriv"

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
	// Do not use SysProcAttr.Credential here. On Linux, os/exec performs
	// setgroups, setgid, setuid, and execve in the fork child and reports any
	// failure as the same opaque "fork/exec: operation not permitted" error.
	// setpriv keeps the same privilege boundary while making the failed stage
	// observable in its stderr. It is invoked by absolute path without a shell.
	candidatePath := command.Path
	candidateArgs := append([]string(nil), command.Args[1:]...)
	command.Path = setprivPath
	command.Args = []string{
		setprivPath,
		"--reuid=" + strconv.FormatUint(uid, 10),
		"--regid=" + strconv.FormatUint(gid, 10),
		"--clear-groups",
		"--no-new-privs",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--",
		candidatePath,
	}
	command.Args = append(command.Args, candidateArgs...)
	command.Dir = stateDirectory
	command.Env = []string{
		"HOME=" + stateDirectory,
		"LD_LIBRARY_PATH=" + libraryDirectory,
		"PATH=/usr/bin:/bin",
		"XDG_DATA_HOME=" + stateDirectory + "/data",
	}
	return nil
}
