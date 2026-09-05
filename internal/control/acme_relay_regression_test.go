package control

import (
	"bytes"
	"context"
	"testing"
)

func TestAuditRelayPoolNoOp(t *testing.T) {
	ctx := context.Background()
	server, registry, store := newPoolTestServer(t)
	if _, err := registry.SetReported("agent-a", []string{poolTestAddress}, nil); err != nil {
		t.Fatal(err)
	}
	storeAppliedConfig(t, ctx, store, "agent-a", poolSourceConfig(8443))
	session := registerPoolSession(t, server, "agent-b")
	session.capabilities[ACMEHTTP01RelayCapability] = struct{}{}
	logical := []byte(`{"inbounds":[{"type":"anytls","listen_port":443}],"certificate_providers":[{"type":"acme","tag":"acme","domain":["proxy.test"]}],"outbounds":[{"type":"theatropolis-pool-ref","tag":"via-a","ref":"` + poolTestRef + `"}]}`)
	before := deployThroughServer(t, ctx, server, session, "agent-b", logical)
	server.propagatePoolChange(ctx, "unrelated pool update", "agent-a")
	select {
	case frame := <-session.commands:
		after := frame.GetDeployConfig()
		if bytes.Equal(before.ConfigJson, after.ConfigJson) {
			t.Fatalf("unchanged effective config was unnecessarily redeployed: before=%s after=%s", before.DeploymentId, after.DeploymentId)
		}
		t.Fatalf("unexpected command: %v", frame)
	default:
	}
	if _, err := registry.SetReported("agent-a", []string{"192.0.2.42"}, nil); err != nil {
		t.Fatal(err)
	}
	server.propagatePoolChange(ctx, "changed source address", "agent-a")
	select {
	case frame := <-session.commands:
		after := frame.GetDeployConfig()
		if after == nil || bytes.Equal(before.ConfigJson, after.ConfigJson) ||
			!bytes.Contains(after.ConfigJson, []byte(`192.0.2.42`)) ||
			!bytes.Contains(after.ConfigJson, []byte(`"alternative_http_port":19091`)) {
			t.Fatal("actual pool change did not preserve the relay while updating its destination")
		}
	default:
		t.Fatal("actual pool change was incorrectly deduplicated")
	}
}
