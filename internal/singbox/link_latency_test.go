package singbox

import "testing"

func TestParseLinkLatencyTargetsSelectsManagedRelayLinks(t *testing.T) {
	targets, err := ParseLinkLatencyTargets([]byte(`{
		"outbounds": [
			{"type":"anytls","tag":"tp-out-first","server":"203.0.113.10","server_port":443,"password":"secret"},
			{"type":"shadowsocks","tag":"tp-out-second","server":"2001:db8::10","server_port":20048},
			{"type":"hysteria2","tag":"tp-out-udp","server":"203.0.113.11","server_port":443,"tls":{"server_name":"hy.example"},"obfs":{"type":"salamander","password":"secret"}},
			{"type":"anytls","tag":"manual","server":"203.0.113.12","server_port":443}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 || targets[0].OutboundTag != "tp-out-first" || targets[0].Transport != "tcp" || targets[1].Port != 20048 ||
		targets[2].Transport != "quic" || targets[2].ServerName != "hy.example" || targets[2].ObfsSecret != "secret" {
		t.Fatalf("targets = %#v", targets)
	}
}
