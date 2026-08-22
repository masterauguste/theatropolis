//go:build !windows

package singboxupdate

import (
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestConfigureUnprivilegedCommandRejectsRoot(t *testing.T) {
	t.Parallel()
	command := exec.Command("true")
	if err := configureUnprivilegedCommand(command, "root", "/state", "/library"); err == nil {
		t.Fatal("root validation account was accepted")
	}
}

func TestConfigureUnprivilegedCommandDropsCredentialsAndEnvironment(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Skip("test requires a resolvable non-root account")
	}
	t.Setenv("THEATROPOLIS_TEST_SECRET", "must-not-leak")

	command := exec.Command("true")
	if err := configureUnprivilegedCommand(
		command,
		account.Username,
		"/state",
		"/library",
	); err != nil {
		t.Fatal(err)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.Credential == nil ||
		command.SysProcAttr.Credential.Uid != uint32(uid) {
		t.Fatalf("command credential = %+v", command.SysProcAttr)
	}
	if command.SysProcAttr.Credential.Groups == nil ||
		len(command.SysProcAttr.Credential.Groups) != 0 {
		t.Fatalf("supplementary groups were not cleared: %+v", command.SysProcAttr)
	}
	if strings.Contains(strings.Join(command.Env, "\n"), "THEATROPOLIS_TEST_SECRET") {
		t.Fatal("root helper environment leaked into candidate process")
	}
}
