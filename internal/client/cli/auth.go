package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/client/session"
	"github.com/spf13/cobra"
)

// requestTimeout bounds a single call to the server.
const requestTimeout = 10 * time.Second

func (a *app) newRegisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "register <login>",
		Short: "Create an account and log in",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login := args[0]

			password, err := a.deps.ReadPassword("Password: ")
			if err != nil {
				return err
			}
			repeat, err := a.deps.ReadPassword("Repeat password: ")
			if err != nil {
				return err
			}
			if password != repeat {
				return errors.New("passwords do not match")
			}

			if err := a.authenticate(cmd.Context(), login, password, true); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Registered and logged in as %s\n", login)
			return err
		},
	}
}

func (a *app) newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login <login>",
		Short: "Log in to an existing account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login := args[0]

			password, err := a.deps.ReadPassword("Password: ")
			if err != nil {
				return err
			}

			if err := a.authenticate(cmd.Context(), login, password, false); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Logged in as %s\n", login)
			return err
		},
	}
}

func (a *app) newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Forget the saved session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := session.Delete(a.dataDir); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Logged out")
			return err
		},
	}
}

// authenticate registers (register=true) or logs in, and saves the
// session on success.
func (a *app) authenticate(ctx context.Context, login, password string, register bool) error {
	client, err := a.deps.Connect(a.conn)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck // nothing useful to do if closing fails

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var token string
	if register {
		token, err = client.Register(ctx, login, password)
	} else {
		token, err = client.Login(ctx, login, password)
	}
	if err != nil {
		return err
	}

	return session.Save(a.dataDir, session.Session{
		Server: a.conn.Address,
		Login:  login,
		Token:  token,
	})
}
