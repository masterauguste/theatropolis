package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/masterauguste/theatropolis/internal/webui"
)

func TestReadAdminPasswordBoundsAndTerminators(t *testing.T) {
	maximum := strings.Repeat("x", maxAdminPasswordBytes)
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain maximum", input: maximum, want: maximum},
		{name: "maximum LF", input: maximum + "\n", want: maximum},
		{name: "maximum CRLF", input: maximum + "\r\n", want: maximum},
		{
			name:    "maximum CRLF and trailing byte",
			input:   maximum + "\r\nx",
			wantErr: true,
		},
		{name: "maximum plus byte", input: maximum + "x", wantErr: true},
		{name: "multiple lines", input: "first\nsecond\n", wantErr: true},
		{name: "empty", input: "\n", wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			password, err := readAdminPassword(strings.NewReader(test.input))
			defer clear(password)
			if test.wantErr {
				if err == nil {
					t.Fatal("readAdminPassword() unexpectedly succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("readAdminPassword() error = %v", err)
			}
			if string(password) != test.want {
				t.Fatalf(
					"readAdminPassword() length = %d, want %d",
					len(password),
					len(test.want),
				)
			}
		})
	}
}

func TestSetWebAdminReadsPasswordFromStdinWithoutOutput(t *testing.T) {
	stateDirectory := t.TempDir()
	username := "fixture-admin"
	password := "Crimson-Orbit-Window-742"

	originalEffectiveUserID := effectiveUserID
	effectiveUserID = func() int { return 0 }
	t.Cleanup(func() {
		effectiveUserID = originalEffectiveUserID
	})

	output, err := runSetWebAdminWithInput(
		t,
		password+"\n",
		"set-web-admin",
		"--state-dir", stateDirectory,
		"--username", username,
		"--password-stdin",
	)
	if err != nil {
		t.Fatalf("set-web-admin error = %v", err)
	}
	if output != "" {
		t.Fatalf("set-web-admin output = %q, want empty", output)
	}

	accessPath := filepath.Join(stateDirectory, "web-auth.json")
	encoded, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(password)) {
		t.Fatal("credential file contains the plaintext password")
	}
	manager, err := webui.LoadAccess(accessPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Login(username, password); err != nil {
		t.Fatalf("Login() with initialized admin error = %v", err)
	}
}

func TestSetWebAdminRequiresExplicitReplace(t *testing.T) {
	stateDirectory := t.TempDir()
	originalEffectiveUserID := effectiveUserID
	effectiveUserID = func() int { return 0 }
	t.Cleanup(func() {
		effectiveUserID = originalEffectiveUserID
	})

	if _, err := runSetWebAdminWithInput(
		t,
		"Crimson-Orbit-Window-742\n",
		"set-web-admin",
		"--state-dir", stateDirectory,
		"--username", "first-admin",
		"--password-stdin",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := runSetWebAdminWithInput(
		t,
		"Silver-Comet-Harbor-936\n",
		"set-web-admin",
		"--state-dir", stateDirectory,
		"--username", "second-admin",
		"--password-stdin",
	); err == nil {
		t.Fatal("set-web-admin unexpectedly replaced an existing credential")
	}
	output, err := runSetWebAdminWithInput(
		t,
		"Silver-Comet-Harbor-936\n",
		"set-web-admin",
		"--state-dir", stateDirectory,
		"--username", "second-admin",
		"--password-stdin",
		"--replace",
	)
	if err != nil {
		t.Fatalf("set-web-admin --replace error = %v", err)
	}
	if output != "" {
		t.Fatalf("set-web-admin --replace output = %q, want empty", output)
	}
}

func runSetWebAdminWithInput(
	t *testing.T,
	input string,
	arguments ...string,
) (string, error) {
	t.Helper()

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stdinWriter, input); err != nil {
		t.Fatal(err)
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatal(err)
	}
	defer stdinReader.Close()

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	originalStdout := os.Stdout
	os.Stdin = stdinReader
	os.Stdout = stdoutWriter
	defer func() {
		os.Stdin = originalStdin
		os.Stdout = originalStdout
	}()

	runErr := run(arguments)
	if err := stdoutWriter.Close(); err != nil {
		t.Fatal(err)
	}
	output, readErr := io.ReadAll(stdoutReader)
	_ = stdoutReader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(output), runErr
}
