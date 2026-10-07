package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var secret = strings.Repeat("s", 32)

// envMap returns a getenv function backed by m.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// required are the env vars without defaults; tests that don't check
// them start from these.
func required() map[string]string {
	return map[string]string{"DATABASE_DSN": "postgres://db", "JWT_SECRET": secret}
}

func TestParse(t *testing.T) {
	defaults := Config{
		GRPCAddress: "localhost:3200",
		DatabaseDSN: "postgres://db",
		JWTSecret:   secret,
		TokenTTL:    24 * time.Hour,
		LogLevel:    "info",
	}

	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		want    func(c *Config) // changes to defaults expected
		wantErr bool
	}{
		{
			name: "defaults",
			env:  required(),
			want: func(*Config) {},
		},
		{
			name: "flags",
			args: []string{"-a", ":4000", "-d", "postgres://flag", "-jwt-secret", secret + "x",
				"-token-ttl", "1h", "-tls-cert", "c.pem", "-tls-key", "k.pem", "-log-level", "debug"},
			want: func(c *Config) {
				c.GRPCAddress, c.DatabaseDSN, c.JWTSecret = ":4000", "postgres://flag", secret+"x"
				c.TokenTTL, c.TLSCertFile, c.TLSKeyFile, c.LogLevel = time.Hour, "c.pem", "k.pem", "debug"
			},
		},
		{
			name: "env overrides flags",
			args: []string{"-a", ":4000", "-d", "postgres://flag", "-jwt-secret", secret},
			env:  map[string]string{"GRPC_ADDRESS": ":5000", "DATABASE_DSN": "postgres://db", "TOKEN_TTL": "30m"},
			want: func(c *Config) { c.GRPCAddress, c.TokenTTL = ":5000", 30*time.Minute },
		},
		{name: "no DSN", env: map[string]string{"JWT_SECRET": secret}, wantErr: true},
		{name: "short secret", env: map[string]string{"DATABASE_DSN": "x", "JWT_SECRET": "short"}, wantErr: true},
		{name: "bad TTL env", env: map[string]string{"DATABASE_DSN": "x", "JWT_SECRET": secret, "TOKEN_TTL": "soon"}, wantErr: true},
		{name: "zero TTL", args: []string{"-token-ttl", "0s"}, env: required(), wantErr: true},
		{name: "cert without key", args: []string{"-tls-cert", "c.pem"}, env: required(), wantErr: true},
		{name: "empty address", args: []string{"-a", ""}, env: required(), wantErr: true},
		{name: "unknown flag", args: []string{"-nope"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(tt.args, envMap(tt.env))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			want := defaults
			tt.want(&want)
			assert.Equal(t, want, *cfg)
		})
	}
}

func TestTLSEnabled(t *testing.T) {
	assert.False(t, (&Config{}).TLSEnabled())
	assert.True(t, (&Config{TLSCertFile: "c", TLSKeyFile: "k"}).TLSEnabled())
}
