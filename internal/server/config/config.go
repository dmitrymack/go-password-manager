// Package config reads the server configuration.
// Priority: flag > env var > default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// Config holds the server startup parameters.
type Config struct {
	GRPCAddress string        // -a, GRPC_ADDRESS: host:port the gRPC server listens on
	DatabaseDSN string        // -d, DATABASE_DSN: PostgreSQL connection string (required)
	JWTSecret   string        // -jwt-secret, JWT_SECRET: token signing secret (required)
	MasterKey   string        // MASTER_KEY: hex master encryption key (required; env only)
	TokenTTL    time.Duration // -token-ttl, TOKEN_TTL: token lifetime, e.g. 24h
	TLSCertFile string        // -tls-cert, TLS_CERT: PEM certificate (required)
	TLSKeyFile  string        // -tls-key, TLS_KEY: PEM private key of TLSCertFile (required)
	LogLevel    string        // -log-level, LOG_LEVEL: zap level (debug, info, warn, error)
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

	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		fs.SetOutput(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage: gophkeeper-server [rotate-kek] [flags]\nFlags override env vars; MASTER_KEY is env only.")
		fs.PrintDefaults()
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}

	// Flags given on the command line; env vars don't override them.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	for env, name := range map[string]string{
		"GRPC_ADDRESS": "a",
		"DATABASE_DSN": "d",
		"JWT_SECRET":   "jwt-secret",
		"TOKEN_TTL":    "token-ttl",
		"TLS_CERT":     "tls-cert",
		"TLS_KEY":      "tls-key",
		"LOG_LEVEL":    "log-level",
	} {
		if v := getenv(env); v != "" && !given[name] {
			// Set parses the value like the flag would, e.g. a duration.
			if err := fs.Set(name, v); err != nil {
				return nil, fmt.Errorf("%s: %w", env, err)
			}
		}
	}
	cfg.MasterKey = getenv("MASTER_KEY") // env only: keep it out of ps and shell history

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
	case c.MasterKey == "":
		return errors.New("master key is required (MASTER_KEY)")
	case c.TokenTTL <= 0:
		return errors.New("token TTL must be positive")
	case c.TLSCertFile == "" || c.TLSKeyFile == "":
		return errors.New("TLS certificate and key are required (-tls-cert/TLS_CERT, -tls-key/TLS_KEY)")
	}
	return nil
}
