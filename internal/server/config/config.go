// Package config reads the server configuration.
// Priority: env var > flag > default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

// Config holds the server startup parameters.
type Config struct {
	GRPCAddress string        // -a, GRPC_ADDRESS: host:port the gRPC server listens on
	DatabaseDSN string        // -d, DATABASE_DSN: PostgreSQL connection string (required)
	JWTSecret   string        // -jwt-secret, JWT_SECRET: token signing secret (required)
	TokenTTL    time.Duration // -token-ttl, TOKEN_TTL: token lifetime, e.g. 24h
	TLSCertFile string        // -tls-cert, TLS_CERT: PEM certificate; empty together with TLSKeyFile disables TLS
	TLSKeyFile  string        // -tls-key, TLS_KEY: PEM private key of TLSCertFile
	LogLevel    string        // -log-level, LOG_LEVEL: zap level (debug, info, warn, error)
}

// TLSEnabled reports whether the server should serve over TLS.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" || c.TLSKeyFile != ""
}

// Parse builds a Config from args (without the program name) and getenv
// (os.Getenv in production; tests pass a fake).
func Parse(args []string, getenv func(string) string) (*Config, error) {
	cfg := &Config{}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.GRPCAddress, "a", "localhost:3200", "gRPC server host:port")
	fs.StringVar(&cfg.DatabaseDSN, "d", "", "PostgreSQL DSN")
	fs.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT signing secret")
	fs.DurationVar(&cfg.TokenTTL, "token-ttl", 24*time.Hour, "token lifetime")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate file (PEM)")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS private key file (PEM)")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug, info, warn, error")

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}

	for env, dst := range map[string]*string{
		"GRPC_ADDRESS": &cfg.GRPCAddress,
		"DATABASE_DSN": &cfg.DatabaseDSN,
		"JWT_SECRET":   &cfg.JWTSecret,
		"TLS_CERT":     &cfg.TLSCertFile,
		"TLS_KEY":      &cfg.TLSKeyFile,
		"LOG_LEVEL":    &cfg.LogLevel,
	} {
		if v := getenv(env); v != "" {
			*dst = v
		}
	}

	if v := getenv("TOKEN_TTL"); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("TOKEN_TTL: %w", err)
		}
		cfg.TokenTTL = ttl
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks the parsed values.
func (c *Config) validate() error {
	switch {
	case c.GRPCAddress == "":
		return errors.New("gRPC address must not be empty")
	case c.DatabaseDSN == "":
		return errors.New("database DSN is required (-d or DATABASE_DSN)")
	case len(c.JWTSecret) < 32:
		return errors.New("JWT secret must be at least 32 characters (-jwt-secret or JWT_SECRET)")
	case c.TokenTTL <= 0:
		return errors.New("token TTL must be positive")
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		return errors.New("TLS certificate and key must be set together")
	}
	return nil
}
