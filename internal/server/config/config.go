// Package config reads the server configuration.
// Priority: env var > flag > default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

// Config holds the server startup parameters.
type Config struct {
	GRPCAddress string // -a, GRPC_ADDRESS: host:port the gRPC server listens on
	TLSCertFile string // -tls-cert, TLS_CERT: PEM certificate; empty together with TLSKeyFile disables TLS
	TLSKeyFile  string // -tls-key, TLS_KEY: PEM private key of TLSCertFile
	LogLevel    string // -log-level, LOG_LEVEL: zap level (debug, info, warn, error)
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
	fs.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate file (PEM)")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS private key file (PEM)")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug, info, warn, error")

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parsing flags: %w", err)
	}

	for env, dst := range map[string]*string{
		"GRPC_ADDRESS": &cfg.GRPCAddress,
		"TLS_CERT":     &cfg.TLSCertFile,
		"TLS_KEY":      &cfg.TLSKeyFile,
		"LOG_LEVEL":    &cfg.LogLevel,
	} {
		if v := getenv(env); v != "" {
			*dst = v
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks the parsed values.
func (c *Config) validate() error {
	if c.GRPCAddress == "" {
		return errors.New("gRPC address must not be empty")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("TLS certificate and key must be set together")
	}
	return nil
}
