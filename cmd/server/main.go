// Command server runs the GophKeeper server.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"syscall"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/dmitrymack/go-password-manager/internal/server/app"
	"github.com/dmitrymack/go-password-manager/internal/server/auth"
	"github.com/dmitrymack/go-password-manager/internal/server/config"
	"github.com/dmitrymack/go-password-manager/internal/server/encryption"
	"github.com/dmitrymack/go-password-manager/internal/server/secrets"
	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

func main() {
	os.Exit(run())
}

// run is separate from main so its defers fire before os.Exit.
func run() int {
	fmt.Println(buildinfo.String())

	// Load .env if present. Variables already set in the environment win.
	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, ".env:", err)
		return 2
	}

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

	db, err := storage.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		logger.Error("failed to open storage", zap.Error(err))
		return 1
	}
	defer db.Close()

	masterKey, err := encryption.ParseMasterKey(cfg.MasterKey)
	if err != nil {
		logger.Error("invalid master key", zap.Error(err))
		return 1
	}
	keys, err := encryption.LoadKeyring(ctx, db, masterKey)
	if err != nil {
		logger.Error("failed to load encryption keys", zap.Error(err))
		return 1
	}

	tokens := auth.NewTokens(cfg.JWTSecret, cfg.TokenTTL)
	services := app.Services{
		Auth:    auth.NewService(db, tokens),
		Tokens:  tokens,
		Secrets: secrets.NewService(db, keys),
	}

	a, err := app.New(cfg, logger, services)
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
