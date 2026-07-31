package pool

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestParseOutboundURI(t *testing.T) {
	t.Parallel()
	vmess := base64.RawURLEncoding.EncodeToString([]byte(`{"add":"vm.example","port":"443","id":"uuid","scy":"auto","tls":"tls","sni":"cdn.example","net":"ws","host":"front.example","path":"/ws","ps":"VMess remark"}`))
	tests := []struct {
		name, uri, wantType, wantRemark string
		want                            map[string]any
	}{
		{"shadowsocks", "ss://aes-128-gcm:secret@ss.example:8388#Singapore", "shadowsocks", "Singapore", map[string]any{"method": "aes-128-gcm", "password": "secret"}},
		{"trojan", "trojan://secret@tr.example:443?sni=edge.example&allowInsecure=1#Backup", "trojan", "Backup", map[string]any{"password": "secret"}},
		{"vless websocket", "vless://uuid@vl.example:443?security=tls&sni=edge.example&type=ws&host=front.example&path=%2Fws", "vless", "", map[string]any{"uuid": "uuid"}},
		{"hysteria2 alias", "hy2://secret@hy.example:443?obfs=salamander&obfs-password=mask", "hysteria2", "", map[string]any{"password": "secret"}},
		{"tuic", "tuic://uuid:secret@tuic.example:443?congestion_control=bbr", "tuic", "", map[string]any{"uuid": "uuid", "password": "secret"}},
		{"vmess", "vmess://" + vmess, "vmess", "VMess remark", map[string]any{"uuid": "uuid"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, remark, err := ParseOutboundURI(test.uri)
			if err != nil {
				t.Fatalf("ParseOutboundURI() error = %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got["type"] != test.wantType || remark != test.wantRemark {
				t.Fatalf("got %s, %q", raw, remark)
			}
			for key, value := range test.want {
				if got[key] != value {
					t.Errorf("%s = %#v, want %#v", key, got[key], value)
				}
			}
		})
	}
}

func TestParseOutboundURIRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "ftp://example.com:21", "trojan://example.com:443", "vless://uuid@example.com", "vless://uuid@example.com:443?type=kcp"} {
		if _, _, err := ParseOutboundURI(value); !errors.Is(err, ErrInvalidOutbound) {
			t.Errorf("ParseOutboundURI(%q) error = %v", value, err)
		}
	}
}
