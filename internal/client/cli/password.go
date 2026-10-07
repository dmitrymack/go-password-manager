package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// newPasswordReader returns a ReadPassword function. In a terminal it reads
// without echo; otherwise (pipe, script) it reads one line per call, so
// `printf 'pw\npw\n' | gophkeeper register alice` works.
func newPasswordReader(in *os.File, prompt io.Writer) func(string) (string, error) {
	lines := bufio.NewReader(in) // one reader for all calls: it buffers ahead

	return func(text string) (string, error) {
		_, _ = fmt.Fprint(prompt, text)

		fd := int(in.Fd()) //nolint:gosec // file descriptors fit in int
		if term.IsTerminal(fd) {
			password, err := term.ReadPassword(fd)
			_, _ = fmt.Fprintln(prompt) // the user's Enter wasn't echoed
			return string(password), err
		}

		line, err := lines.ReadString('\n')
		if errors.Is(err, io.EOF) && line != "" {
			err = nil // last line without a trailing newline
		}
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
}
