// Package cli implements the gophkeeper command-line client (cobra).
package cli

import (
	"fmt"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/spf13/cobra"
)

// NewRootCmd builds the gophkeeper command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper is a client for the GophKeeper password manager",
		SilenceUsage:  true, // on error print only the error, not the help
		SilenceErrors: true, // main prints errors
	}

	root.AddCommand(newVersionCmd())

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
