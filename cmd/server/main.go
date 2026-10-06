// Command server runs the GophKeeper server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/dmitrymack/go-password-manager/internal/server/app"
	"github.com/dmitrymack/go-password-manager/internal/server/config"
	"go.uber.org/zap"
)

func main() {
	os.Exit(run())
}

// run is separate from main so its defers fire before os.Exit.
func run() int {
	fmt.Println(buildinfo.String())

	cfg, err := config.Parse(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}

	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger:", err)
		return 2
	}
	defer logger.Sync() //nolint:errcheck // nothing to do if flushing the log fails

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	a, err := app.New(cfg, logger)
	if err != nil {
		logger.Error("failed to start", zap.Error(err))
		return 1
	}

	if err := a.Run(ctx); err != nil {
		logger.Error("server failed", zap.Error(err))
		return 1
	}
	return 0
}

// newLogger builds a production (JSON) zap logger at the given level.
func newLogger(level string) (*zap.Logger, error) {
	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return nil, err
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = lvl
	return cfg.Build()
}
