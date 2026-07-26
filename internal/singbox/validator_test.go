package singbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestValidatorRejectsInvalidJSONWithoutStartingSingBox(t *testing.T) {
	t.Parallel()

	config := []byte(`{"inbounds":`)
	digest := sha256.Sum256(config)
	called := false
	validator := Validator{
		BinaryPath:     "sing-box",
		StateDirectory: t.TempDir(),
		runCommand: func(context.Context, string, string, io.Writer) error {
			called = true
			return nil
		},
	}
	result := validator.Check(context.Background(), config, digest[:])
	if result.Status != ValidationInvalid {
		t.Fatalf("got status %q", result.Status)
	}
	if called {
		t.Fatal("sing-box was started for syntactically invalid JSON")
	}
}

func TestValidatorRedactsSecretsAndCandidatePath(t *testing.T) {
	t.Parallel()

	const secret = "an-extremely-secret-password"
	config := []byte(`{"password":"` + secret + `"}`)
	digest := sha256.Sum256(config)
	stateDirectory := t.TempDir()
	validator := Validator{
		BinaryPath:     "sing-box",
		StateDirectory: stateDirectory,
		runCommand: func(
			_ context.Context,
			_ string,
			candidatePath string,
			output io.Writer,
		) error {
			_, _ = io.WriteString(
				output,
				"invalid password "+secret+" at "+candidatePath+
					" from anytls://user:another-secret@example.com",
			)
			return &exec.ExitError{}
		},
	}
	result := validator.Check(context.Background(), config, digest[:])
	if result.Status != ValidationInvalid {
		t.Fatalf("got status %q with diagnostic %q", result.Status, result.Diagnostic)
	}
	for _, forbidden := range []string{secret, stateDirectory, "user:another-secret"} {
		if strings.Contains(result.Diagnostic, forbidden) {
			t.Fatalf("diagnostic leaked %q: %q", forbidden, result.Diagnostic)
		}
	}
	if !strings.Contains(result.Diagnostic, "<redacted>") {
		t.Fatalf("diagnostic did not identify redaction: %q", result.Diagnostic)
	}
}

func TestValidatorRejectsDigestMismatch(t *testing.T) {
	t.Parallel()

	config := []byte(`{}`)
	wrongDigest := sha256.Sum256([]byte(`{"different":true}`))
	validator := Validator{
		BinaryPath:     "sing-box",
		StateDirectory: t.TempDir(),
		runCommand: func(context.Context, string, string, io.Writer) error {
			return errors.New("must not run")
		},
	}
	result := validator.Check(context.Background(), config, wrongDigest[:])
	if result.Status != ValidationInternalError {
		t.Fatalf("got status %q", result.Status)
	}
	if result.Diagnostic != "candidate configuration digest does not match the deployment command" {
		t.Fatalf("unexpected diagnostic %q", result.Diagnostic)
	}
}
