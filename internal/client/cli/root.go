// Package cli implements the gophkeeper command-line client (cobra).
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/spf13/cobra"
)

// API is what the commands need from the server connection.
type API interface {
	Register(ctx context.Context, login, password string) (string, error)
	Login(ctx context.Context, login, password string) (string, error)
	Sync(ctx context.Context, since int64) ([]secret.Info, int64, error)
	Get(ctx context.Context, id string) (secret.Secret, error)
	Create(ctx context.Context, s secret.Secret) (secret.Info, error)
	Update(ctx context.Context, s secret.Secret) (secret.Info, error)
	Delete(ctx context.Context, id string) error
	Close() error
}

// Deps are the outside-world dependencies of the commands; tests replace
// them with fakes.
type Deps struct {
	Connect      func(opts api.Options) (API, error)
	ReadPassword func(prompt string) (string, error)
}

// DefaultDeps are the real dependencies: the gRPC client and a terminal
// password prompt.
func DefaultDeps() Deps {
	return Deps{
		Connect: func(opts api.Options) (API, error) {
			return api.Dial(opts)
		},
		ReadPassword: newPasswordReader(os.Stdin, os.Stderr),
	}
}

// app is the state shared by all commands: dependencies and global flags.
type app struct {
	deps    Deps
	conn    api.Options
	dataDir string
}

// NewRootCmd builds the gophkeeper command tree.
func NewRootCmd(deps Deps) *cobra.Command {
	a := &app{deps: deps}

	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper is a client for the GophKeeper password manager",
		SilenceUsage:  true, // on error print only the error, not the help
		SilenceErrors: true, // main prints errors
	}

	flags := root.PersistentFlags()
	flags.StringVar(&a.conn.Address, "server", envOr("GOPHKEEPER_SERVER", "localhost:3200"),
		"server address [GOPHKEEPER_SERVER]")
	flags.StringVar(&a.conn.CACertFile, "ca-cert", os.Getenv("GOPHKEEPER_CA_CERT"),
		"CA certificate to verify the server [GOPHKEEPER_CA_CERT]")
	flags.StringVar(&a.dataDir, "data-dir", envOr("GOPHKEEPER_DATA_DIR", defaultDataDir()),
		"directory for the session and local data [GOPHKEEPER_DATA_DIR]")

	root.AddCommand(
		newVersionCmd(),
		a.newRegisterCmd(),
		a.newLoginCmd(),
		a.newLogoutCmd(),
		a.newSyncCmd(),
		a.newListCmd(),
		a.newGetCmd(),
		a.newAddCmd(),
		a.newEditCmd(),
		a.newDeleteCmd(),
	)

	return root
}

// newVersionCmd prints the version and build date.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client version and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
			return err
		},
	}
}

// envOr returns the env var key, or def if it's unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// defaultDataDir is the per-user config dir: ~/.config/gophkeeper on
// Linux, %AppData%\gophkeeper on Windows, ~/Library/Application Support/gophkeeper on macOS.
func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ".gophkeeper"
	}
	return filepath.Join(dir, "gophkeeper")
}
