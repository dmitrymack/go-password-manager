package config

import (
	"flag"
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
	return map[string]string{
		"DATABASE_DSN": "postgres://db", "JWT_SECRET": secret, "MASTER_KEY": "mk",
		"TLS_CERT": "c.pem", "TLS_KEY": "k.pem",
	}
}

func TestParse(t *testing.T) {
	defaults := Config{
		GRPCAddress: "localhost:3200",
		DatabaseDSN: "postgres://db",
		JWTSecret:   secret,
		MasterKey:   "mk",
		TLSCertFile: "c.pem",
		TLSKeyFile:  "k.pem",
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
				"-token-ttl", "1h", "-tls-cert", "flag.pem", "-tls-key", "flag.key", "-log-level", "debug"},
			env: map[string]string{"MASTER_KEY": "mk"}, // env only, no flag
			want: func(c *Config) {
				c.GRPCAddress, c.DatabaseDSN, c.JWTSecret = ":4000", "postgres://flag", secret+"x"
				c.TokenTTL, c.TLSCertFile, c.TLSKeyFile, c.LogLevel = time.Hour, "flag.pem", "flag.key", "debug"
			},
		},
		{
			name: "flags override env",
			args: []string{"-a", ":4000", "-token-ttl", "1h"},
			env: map[string]string{
				"GRPC_ADDRESS": ":5000", "TOKEN_TTL": "30m", "LOG_LEVEL": "warn",
				"DATABASE_DSN": "postgres://db", "JWT_SECRET": secret, "MASTER_KEY": "mk",
				"TLS_CERT": "c.pem", "TLS_KEY": "k.pem",
			},
			want: func(c *Config) { c.GRPCAddress, c.TokenTTL, c.LogLevel = ":4000", time.Hour, "warn" },
		},
		{name: "no DSN", env: map[string]string{"JWT_SECRET": secret, "MASTER_KEY": "mk"}, wantErr: true},
		{name: "no master key", env: map[string]string{"DATABASE_DSN": "x", "JWT_SECRET": secret}, wantErr: true},
		{name: "short secret", env: map[string]string{"DATABASE_DSN": "x", "JWT_SECRET": "short"}, wantErr: true},
		{name: "bad TTL env", env: map[string]string{"DATABASE_DSN": "x", "JWT_SECRET": secret, "MASTER_KEY": "mk", "TOKEN_TTL": "soon"}, wantErr: true},
		{name: "zero TTL", args: []string{"-token-ttl", "0s"}, env: required(), wantErr: true},
		{name: "no TLS", env: map[string]string{"DATABASE_DSN": "x", "JWT_SECRET": secret, "MASTER_KEY": "mk"}, wantErr: true},
		{name: "cert without key", args: []string{"-tls-key", ""}, env: required(), wantErr: true},
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

func TestParseHelp(t *testing.T) {
	_, err := Parse([]string{"-h"}, func(string) string { return "" })
	assert.ErrorIs(t, err, flag.ErrHelp)
}
