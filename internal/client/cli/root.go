// Package cli implements the gophkeeper command-line client (cobra).
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/spf13/cobra"
)

// AuthAPI is what the commands need from the server connection.
type AuthAPI interface {
	Register(ctx context.Context, login, password string) (string, error)
	Login(ctx context.Context, login, password string) (string, error)
	Close() error
}

// Deps are the outside-world dependencies of the commands; tests replace
// them with fakes.
type Deps struct {
	Connect      func(opts api.Options) (AuthAPI, error)
	ReadPassword func(prompt string) (string, error)
}

// DefaultDeps are the real dependencies: the gRPC client and a terminal
// password prompt.
func DefaultDeps() Deps {
	return Deps{
		Connect: func(opts api.Options) (AuthAPI, error) {
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
	flags.BoolVar(&a.conn.Plaintext, "plaintext", false,
		"connect without TLS (development only)")
	flags.StringVar(&a.dataDir, "data-dir", envOr("GOPHKEEPER_DATA_DIR", defaultDataDir()),
		"directory for the session and local data [GOPHKEEPER_DATA_DIR]")

	root.AddCommand(
		newVersionCmd(),
		a.newRegisterCmd(),
		a.newLoginCmd(),
		a.newLogoutCmd(),
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
