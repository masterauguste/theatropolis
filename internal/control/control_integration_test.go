package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/agent"
	"github.com/masterauguste/theatropolis/internal/control"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"github.com/masterauguste/theatropolis/internal/singbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const helperEnvironment = "THEATROPOLIS_SING_BOX_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnvironment) == "1" {
		runSingBoxTestHelper()
		os.Exit(97)
	}
	os.Exit(m.Run())
}

func runSingBoxTestHelper() {
	if len(os.Args) != 4 || os.Args[1] != "check" || os.Args[2] != "-c" {
		_, _ = fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	config, err := os.ReadFile(os.Args[3])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "could not read candidate")
		os.Exit(2)
	}
	var document struct {
		Password string `json:"password"`
	}
	if json.Unmarshal(config, &document) != nil {
		_, _ = fmt.Fprintln(os.Stderr, "invalid json")
		os.Exit(2)
	}
	_, _ = fmt.Fprintf(
		os.Stderr,
		"configuration password %s rejected at %s",
		document.Password,
		os.Args[3],
	)
	os.Exit(1)
}

type channelNotifier struct {
	events chan deployment.Event
}

func (n *channelNotifier) Notify(_ context.Context, event deployment.Event) error {
	n.events <- event
	return nil
}

func TestInvalidConfigurationReachesMasterNotificationWithoutSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener := bufconn.Listen(1 << 20)
	identities := identity.NewRegistry()
	deployments := deployment.NewMemoryStore()
	notifier := &channelNotifier{events: make(chan deployment.Event, 1)}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	controlServer := control.NewServer(identities, deployments, notifier, logger)
	grpcServer := grpc.NewServer()
	controlv1.RegisterAgentControlServiceServer(grpcServer, controlServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	connection, err := grpc.NewClient(
		"passthrough:///theatropolis-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controlv1.NewAgentControlServiceClient(connection)

	token, err := identities.CreateEnrollment(ctx, "edge-test-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runner := &agent.Runner{
		AgentID:      "edge-test-1",
		AgentVersion: "test",
		PrivateKey:   privateKey,
		Validator: singbox.Validator{
			BinaryPath:     os.Args[0],
			StateDirectory: filepath.Join(t.TempDir(), "agent-state"),
		},
	}
	if err := runner.Enroll(ctx, client, token); err != nil {
		t.Fatal(err)
	}

	if err := os.Setenv(helperEnvironment, "1"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(helperEnvironment)
	runnerResult := make(chan error, 1)
	go func() {
		runnerResult <- runner.Run(ctx, client)
	}()

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !controlServer.Sessions.IsOnline(runner.AgentID) {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("agent did not establish its authenticated control session")
		}
	}

	const secret = "do-not-leak-this-password"
	config := []byte(`{"password":"` + secret + `"}`)
	queued, err := controlServer.QueueValidation(
		ctx,
		runner.AgentID,
		"deployment-1",
		"revision-1",
		config,
		5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if queued.Status != deployment.StatusValidating {
		t.Fatalf("got initial status %q", queued.Status)
	}

	select {
	case event := <-notifier.events:
		if event.Deployment.Status != deployment.StatusValidationFailed {
			t.Fatalf("got final status %q", event.Deployment.Status)
		}
		if !strings.Contains(event.Message, "rejected") {
			t.Fatalf("unexpected user notification %q", event.Message)
		}
		for _, forbidden := range []string{secret, runner.Validator.StateDirectory} {
			if strings.Contains(event.Deployment.Diagnostic, forbidden) {
				t.Fatalf("master notification leaked %q: %q", forbidden, event.Deployment.Diagnostic)
			}
		}
	case <-ctx.Done():
		t.Fatal("master did not receive the validation failure")
	}

	stored, err := deployments.Get(ctx, "deployment-1")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != deployment.StatusValidationFailed {
		t.Fatalf("stored status is %q", stored.Status)
	}

	cancel()
	select {
	case <-runnerResult:
	case <-time.After(time.Second):
		t.Fatal("agent did not stop after context cancellation")
	}
}
