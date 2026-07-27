package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	controlv1 "github.com/masterauguste/theatropolis/api/gen/theatropolis/control/v1"
	"github.com/masterauguste/theatropolis/internal/singbox"
)

type testConfigurationManager struct {
	result singbox.ApplyResult
	err    error
}

func (*testConfigurationManager) Start(
	context.Context,
) (singbox.StartupResult, error) {
	return singbox.StartupResult{}, nil
}

func (m *testConfigurationManager) Apply(
	context.Context,
	[]byte,
	[]byte,
) (singbox.ApplyResult, error) {
	return m.result, m.err
}

func (*testConfigurationManager) Stop(context.Context) error {
	return nil
}

func (*testConfigurationManager) Events() <-chan singbox.RuntimeEvent {
	return nil
}

func TestDeployConfigurationMapsManagerResult(t *testing.T) {
	t.Parallel()

	config := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(config)
	now := time.Now().UTC()
	runner := &Runner{
		Manager: &testConfigurationManager{
			result: singbox.ApplyResult{
				Status:       singbox.ApplyStatusApplied,
				ConfigSHA256: digest,
			},
		},
		Now: func() time.Time { return now },
	}
	report := runner.deployConfiguration(
		context.Background(),
		&controlv1.DeployConfigCommand{
			DeploymentId:   "deployment-1",
			RevisionId:     "revision-1",
			ConfigSha256:   digest[:],
			ConfigJson:     config,
			TimeoutSeconds: 5,
		},
	)
	if report.GetStatus() !=
		controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_APPLIED {
		t.Fatalf("deployment status = %s", report.GetStatus())
	}
	if report.GetDeploymentId() != "deployment-1" ||
		report.GetRevisionId() != "revision-1" ||
		string(report.GetConfigSha256()) != string(digest[:]) {
		t.Fatalf("deployment report lost request identity: %+v", report)
	}
}

func TestDeployConfigurationReportsInternalManagerFailure(t *testing.T) {
	t.Parallel()

	config := []byte(`{}`)
	digest := sha256.Sum256(config)
	runner := &Runner{
		Manager: &testConfigurationManager{
			err: errors.New("private internal failure"),
		},
	}
	report := runner.deployConfiguration(
		context.Background(),
		&controlv1.DeployConfigCommand{
			DeploymentId:   "deployment-2",
			RevisionId:     "revision-2",
			ConfigSha256:   digest[:],
			ConfigJson:     config,
			TimeoutSeconds: 5,
		},
	)
	if report.GetStatus() !=
		controlv1.ConfigDeploymentStatus_CONFIG_DEPLOYMENT_STATUS_INTERNAL_ERROR {
		t.Fatalf("deployment status = %s", report.GetStatus())
	}
	if report.GetDiagnostic() !=
		"agent could not complete the configuration deployment" {
		t.Fatalf("deployment diagnostic leaked internals: %q", report.GetDiagnostic())
	}
}

func TestRuntimeReportContainsOnlyRuntimeMetadata(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte(`{"password":"secret"}`))
	observed := time.Now().UTC()
	report := runtimeReport(singbox.RuntimeEvent{
		Status:       singbox.RuntimeStatusRestartFailed,
		ConfigSHA256: digest,
		ObservedAt:   observed,
		Diagnostic:   "managed sing-box could not be restarted",
	})
	if report.GetStatus() !=
		controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED ||
		report.GetObservedAtUnix() != observed.Unix() ||
		string(report.GetConfigSha256()) != string(digest[:]) {
		t.Fatalf("runtime report = %+v", report)
	}
	if report.GetDiagnostic() != "managed sing-box could not be restarted" {
		t.Fatalf("runtime diagnostic = %q", report.GetDiagnostic())
	}
}

func TestRuntimeReportMapsEveryManagerStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		manager singbox.RuntimeStatus
		wire    controlv1.ConfigRuntimeStatus
	}{
		{singbox.RuntimeStatusRunning, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RUNNING},
		{singbox.RuntimeStatusExited, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_EXITED},
		{singbox.RuntimeStatusRestartFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_RESTART_FAILED},
		{singbox.RuntimeStatusValidationFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_VALIDATION_FAILED},
		{singbox.RuntimeStatusActivationFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_ACTIVATION_FAILED},
		{singbox.RuntimeStatusStopFailed, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOP_FAILED},
		{singbox.RuntimeStatusStopped, controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_STOPPED},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.manager), func(t *testing.T) {
			t.Parallel()
			report := runtimeReport(singbox.RuntimeEvent{
				Status:     test.manager,
				ObservedAt: time.Now().UTC(),
			})
			if report.GetStatus() != test.wire {
				t.Fatalf(
					"runtimeReport(%q) status = %s, want %s",
					test.manager,
					report.GetStatus(),
					test.wire,
				)
			}
			if report.GetStatus() ==
				controlv1.ConfigRuntimeStatus_CONFIG_RUNTIME_STATUS_UNSPECIFIED {
				t.Fatalf("runtimeReport(%q) produced unspecified status", test.manager)
			}
		})
	}
}
