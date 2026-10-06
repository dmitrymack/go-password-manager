// Package app wires the server together and runs it.
package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/dmitrymack/go-password-manager/internal/server/config"
	"github.com/dmitrymack/go-password-manager/internal/server/interceptor"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// App is the assembled server.
type App struct {
	cfg    *config.Config
	logger *zap.Logger
	grpc   *grpc.Server
}

// New builds the server from cfg.
func New(cfg *config.Config, logger *zap.Logger) (*App, error) {
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(interceptor.Logging(logger)),
	}

	if cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading TLS key pair: %w", err)
		}
		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
		opts = append(opts, grpc.Creds(creds))
	} else {
		logger.Warn("TLS is disabled: traffic goes in plaintext")
	}

	srv := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(srv, health.NewServer())

	return &App{cfg: cfg, logger: logger, grpc: srv}, nil
}

// Run listens on the configured address and serves until ctx is done.
func (a *App) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", a.cfg.GRPCAddress)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", a.cfg.GRPCAddress, err)
	}
	return a.Serve(ctx, lis)
}

// Serve serves on lis until ctx is done, then stops gracefully.
// Tests call it directly with their own listener.
func (a *App) Serve(ctx context.Context, lis net.Listener) error {
	go func() {
		<-ctx.Done()
		a.logger.Info("shutting down")
		a.grpc.GracefulStop()
	}()

	a.logger.Info("server started", zap.String("address", lis.Addr().String()))
	return a.grpc.Serve(lis)
}
