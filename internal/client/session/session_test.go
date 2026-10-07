package session

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveLoadDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gophkeeper")

	_, err := Load(dir)
	assert.ErrorIs(t, err, ErrNoSession)

	want := Session{Server: "localhost:3200", Login: "alice", Token: "tok"}
	require.NoError(t, Save(dir, want))

	got, err := Load(dir)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	if runtime.GOOS != "windows" { // Windows has no Unix permission bits
		info, err := os.Stat(filepath.Join(dir, fileName))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	require.NoError(t, Delete(dir))
	_, err = Load(dir)
	assert.ErrorIs(t, err, ErrNoSession)

	assert.NoError(t, Delete(dir), "deleting twice is fine")
}

func TestLoadCorrupted(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, fileName), []byte("{"), 0o600))

	_, err := Load(dir)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrNoSession)
}
