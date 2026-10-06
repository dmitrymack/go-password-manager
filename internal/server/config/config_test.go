package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envMap returns a getenv function backed by m.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		want    Config
		wantErr bool
	}{
		{
			name: "defaults",
			want: Config{GRPCAddress: "localhost:3200", LogLevel: "info"},
		},
		{
			name: "flags",
			args: []string{"-a", ":4000", "-tls-cert", "c.pem", "-tls-key", "k.pem", "-log-level", "debug"},
			want: Config{GRPCAddress: ":4000", TLSCertFile: "c.pem", TLSKeyFile: "k.pem", LogLevel: "debug"},
		},
		{
			name: "env overrides flags",
			args: []string{"-a", ":4000"},
			env:  map[string]string{"GRPC_ADDRESS": ":5000", "LOG_LEVEL": "warn"},
			want: Config{GRPCAddress: ":5000", LogLevel: "warn"},
		},
		{
			name:    "cert without key",
			args:    []string{"-tls-cert", "c.pem"},
			wantErr: true,
		},
		{
			name:    "empty address",
			args:    []string{"-a", ""},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"-nope"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(tt.args, envMap(tt.env))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, *cfg)
		})
	}
}

func TestTLSEnabled(t *testing.T) {
	assert.False(t, (&Config{}).TLSEnabled())
	assert.True(t, (&Config{TLSCertFile: "c", TLSKeyFile: "k"}).TLSEnabled())
}
