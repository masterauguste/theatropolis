package control

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/deployment"
	"github.com/masterauguste/theatropolis/internal/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recordingNotifier struct {
	events []deployment.Event
}

func (n *recordingNotifier) Notify(_ context.Context, event deployment.Event) error {
	n.events = append(n.events, event)
	return nil
}

func newTestServer(store deployment.Store, notifier deployment.Notifier) *Server {
	return NewServer(
		identity.NewRegistry(),
		store,
		notifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

func TestQueueValidationRecordsOfflineDeliveryFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	notifier := &recordingNotifier{}
	server := newTestServer(store, notifier)

	record, err := server.QueueValidation(
		ctx,
		"offline-agent",
		"deployment-offline",
		"revision-1",
		[]byte(`{}`),
		time.Second,
	)
	if err == nil {
		t.Fatal("expected an offline delivery error")
	}
	if record.Status != deployment.StatusDeliveryFailed {
		t.Fatalf("got status %q", record.Status)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("got %d notifications", len(notifier.events))
	}
}

func TestValidationReportCannotCrossAgentBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := deployment.NewMemoryStore()
	server := newTestServer(store, nil)
	record, err := deployment.New(
		"deployment-1",
		"agent-owner",
		"revision-1",
		[]byte(`{}`),
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		ctx,
		record.ID,
		deployment.StatusValidating,
		"",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}

	err = server.handleValidationReport(ctx, "agent-attacker", &controlv1.ConfigValidationReport{
		DeploymentId: record.ID,
		RevisionId:   record.RevisionID,
		ConfigSha256: record.ConfigSHA256[:],
		Status:       controlv1.ConfigValidationStatus_CONFIG_VALIDATION_STATUS_VALID,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got error %v", err)
	}
	stored, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != deployment.StatusValidating {
		t.Fatalf("forged report changed status to %q", stored.Status)
	}
}

func TestMasterBoundsAgentDiagnostic(t *testing.T) {
	t.Parallel()

	server := newTestServer(deployment.NewMemoryStore(), nil)
	err := server.handleValidationReport(
		context.Background(),
		"agent-1",
		&controlv1.ConfigValidationReport{
			DeploymentId: "deployment-1",
			Diagnostic:   strings.Repeat("x", MaxDiagnosticBytes*4+1),
		},
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got error %v", err)
	}
}
