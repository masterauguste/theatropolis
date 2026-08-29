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
	if command.Path != setprivPath {
		t.Fatalf("command path = %q, want %q", command.Path, setprivPath)
	}
	arguments := strings.Join(command.Args, " ")
	for _, expected := range []string{
		"--reuid=" + strconv.FormatUint(uid, 10),
		"--clear-groups",
		"--no-new-privs",
		"--inh-caps=-all",
		"--ambient-caps=-all",
	} {
		if !strings.Contains(arguments, expected) {
			t.Errorf("command arguments %q do not contain %q", arguments, expected)
		}
	}
	if got := command.Args[len(command.Args)-1]; got != "/usr/bin/true" {
		t.Fatalf("candidate path = %q, want /usr/bin/true", got)
	}
	if strings.Contains(strings.Join(command.Env, "\n"), "THEATROPOLIS_TEST_SECRET") {
		t.Fatal("root helper environment leaked into candidate process")
	}
}

func TestConfigureUnprivilegedCommandPreservesCandidateArguments(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		t.Skip("test requires a resolvable non-root account")
	}

	command := exec.Command("/candidate/sing-box", "check", "-c", "/state/active.json")
	if err := configureUnprivilegedCommand(
		command,
		account.Username,
		"/state",
		"/library",
	); err != nil {
		t.Fatal(err)
	}
	got := command.Args[len(command.Args)-4:]
	want := []string{"/candidate/sing-box", "check", "-c", "/state/active.json"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("candidate arguments = %q, want %q", got, want)
	}
}
