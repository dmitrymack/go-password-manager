// Package session stores the logged-in user's token on disk between
// CLI runs.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const fileName = "session.json"

// ErrNoSession is returned by Load when the user is not logged in.
var ErrNoSession = errors.New("not logged in: run `gophkeeper login` first")

// Session is the logged-in user's state.
type Session struct {
	Server string `json:"server"`
	Login  string `json:"login"`
	Token  string `json:"token"`
}

// Save writes s to dir, readable by the current OS user only.
func Save(dir string, s Session) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, fileName), data, 0o600); err != nil {
		return fmt.Errorf("writing session: %w", err)
	}
	return nil
}

// Load reads the session from dir, or returns ErrNoSession.
func Load(dir string) (Session, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileName)) //nolint:gosec // dir is the user's own data dir
	if errors.Is(err, fs.ErrNotExist) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("reading session: %w", err)
	}

	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return Session{}, fmt.Errorf("parsing session: %w", err)
	}
	return s, nil
}

// Delete removes the session. A missing session is not an error.
func Delete(dir string) error {
	err := os.Remove(filepath.Join(dir, fileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing session: %w", err)
	}
	return nil
}
