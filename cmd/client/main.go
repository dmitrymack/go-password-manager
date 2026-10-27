// Command client is the gophkeeper CLI. It is built as the "gophkeeper"
// binary for Linux, Windows and macOS (see the Makefile).
package main

import (
	"fmt"
	"os"

	"github.com/dmitrymack/go-password-manager/internal/client/cli"
)

func main() {
	if err := cli.NewRootCmd(cli.DefaultDeps()).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
