package singbox

import (
	"errors"
	"testing"
)

func TestValidateManagedConfigReservesHTTP01Port(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config string
		want   error
	}{
		{
			name:   "port 80",
			config: `{"inbounds":[{"type":"anytls","listen_port":80}]}`,
			want:   ErrReservedListenPort,
		},
		{
			name:   "decimal port 80",
			config: `{"inbounds":[{"type":"hysteria2","listen_port":80.0}]}`,
			want:   ErrReservedListenPort,
		},
		{
			name:   "port 443 remains available",
			config: `{"inbounds":[{"type":"anytls","listen_port":443}]}`,
		},
		{
			name:   "managed user API port is reserved",
			config: `{"inbounds":[{"type":"anytls","listen_port":19090}]}`,
			want:   ErrManagedUserAPIListenPort,
		},
		{
			name:   "managed user API stays on loopback",
			config: `{"services":[{"type":"ssm-api","tag":"tp-managed-users","listen":"127.0.0.1","listen_port":19090}]}`,
		},
		{
			name:   "public managed user API is rejected",
			config: `{"services":[{"type":"ssm-api","tag":"tp-managed-users","listen":"0.0.0.0","listen_port":19090}]}`,
			want:   ErrUnsafeManagedUserAPI,
		},
		{
			name:   "no inbounds",
			config: `{}`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateManagedConfig([]byte(test.config))
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateManagedConfig() error = %v, want %v", err, test.want)
			}
		})
	}
}
