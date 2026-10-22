package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/client/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// field returns the value of a "Label:  value" line in get's output.
func field(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, label+":"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no %q in output:\n%s", label, out)
	return ""
}

// emptyAccount returns a logged-in env whose server has no secrets yet.
func emptyAccount(t *testing.T) *testEnv {
	t.Helper()
	env := loggedIn(t)
	env.api.secrets, env.api.revision = nil, 0
	return env
}

func TestAddLogin(t *testing.T) {
	env := emptyAccount(t)
	env.passwords = []string{"s3cret"}

	out, err := env.run("add", "login", "github", "--login", "alice", "--meta", "site=github.com")
	require.NoError(t, err)
	assert.Equal(t, "Added github\n", out)

	out, err = env.run("get", "github")
	require.NoError(t, err)
	assert.Equal(t, "alice", field(t, out, "Login"))
	assert.Equal(t, "s3cret", field(t, out, "Password"))
	assert.Equal(t, "site=github.com", field(t, out, "Metadata"))

	_, err = env.run("add", "login", "nologin")
	assert.EqualError(t, err, "--login is required")

	env.passwords = []string{""}
	_, err = env.run("add", "login", "nopass", "--login", "bob")
	assert.EqualError(t, err, "Password must not be empty")
}

func TestAddCard(t *testing.T) {
	env := emptyAccount(t)
	env.passwords = []string{"123"}

	_, err := env.run("add", "card", "visa", "--number", "4111 1111 1111 1111", "--holder", "ALICE", "--expiry", "12/29")
	require.NoError(t, err)

	out, err := env.run("get", "visa")
	require.NoError(t, err)
	assert.Equal(t, "4111 1111 1111 1111", field(t, out, "Number"))
	assert.Equal(t, "123", field(t, out, "CVV"))

	env.passwords = []string{"123"}
	_, err = env.run("add", "card", "bad", "--number", "4111111111111112", "--expiry", "12/29")
	assert.ErrorIs(t, err, payload.ErrCardNumber)
	assert.Len(t, env.api.secrets, 1, "an invalid card is not sent")
}

func TestAddText(t *testing.T) {
	env := emptyAccount(t)

	_, err := env.run("add", "text", "note", "--text", "buy milk")
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "poem.txt")
	require.NoError(t, os.WriteFile(file, []byte("roses are red"), 0o600))
	_, err = env.run("add", "text", "poem", "--file", file)
	require.NoError(t, err)

	out, err := env.run("get", "poem")
	require.NoError(t, err)
	assert.Equal(t, "roses are red", field(t, out, "Text"))

	_, err = env.run("add", "text", "empty")
	assert.EqualError(t, err, "--text or --file is required")
}

func TestAddBinaryAndSave(t *testing.T) {
	env := emptyAccount(t)
	dir := t.TempDir()

	in := filepath.Join(dir, "photo.jpg")
	content := []byte{0xff, 0xd8, 0x00, 0x01}
	require.NoError(t, os.WriteFile(in, content, 0o600))

	_, err := env.run("add", "binary", "photo", "--file", in, "--meta", "camera=phone")
	require.NoError(t, err)

	saved := filepath.Join(dir, "copy.jpg")
	out, err := env.run("get", "photo", "--out", saved)
	require.NoError(t, err)
	assert.Equal(t, "Saved 4 bytes to "+saved+"\n", out)

	got, err := os.ReadFile(saved)
	require.NoError(t, err)
	assert.Equal(t, content, got)

	_, err = env.run("add", "binary", "nofile")
	assert.EqualError(t, err, "--file is required")

	_, err = env.run("add", "binary", "missing", "--file", filepath.Join(dir, "nope"))
	assert.Error(t, err)

	big := filepath.Join(dir, "big.bin")
	require.NoError(t, os.WriteFile(big, nil, 0o600))
	require.NoError(t, os.Truncate(big, maxDataSize+1)) // sparse: no real 10 MB write
	_, err = env.run("add", "binary", "big", "--file", big)
	assert.ErrorContains(t, err, "larger than 10 MB")
}

func TestEdit(t *testing.T) {
	env := emptyAccount(t)
	env.passwords = []string{"old-pass"}
	_, err := env.run("add", "login", "github", "--login", "alice", "--meta", "site=github.com", "--meta", "env=work")
	require.NoError(t, err)

	// Rename, change metadata; the password stays without --password.
	out, err := env.run("edit", "github", "--name", "github-work", "--meta", "env=", "--meta", "team=core")
	require.NoError(t, err)
	assert.Equal(t, "Updated github-work\n", out)

	out, err = env.run("get", "github-work")
	require.NoError(t, err)
	assert.Equal(t, "site=github.com, team=core", field(t, out, "Metadata"))
	assert.Equal(t, "old-pass", field(t, out, "Password"))

	// New password.
	env.passwords = []string{"new-pass"}
	_, err = env.run("edit", "github-work", "--password")
	require.NoError(t, err)
	out, err = env.run("get", "github-work")
	require.NoError(t, err)
	assert.Equal(t, "new-pass", field(t, out, "Password"))

	_, err = env.run("edit", "github-work", "--number", "4111111111111111")
	assert.EqualError(t, err, "--number: not applicable to a login secret")

	_, err = env.run("edit", "nothing", "--name", "x")
	assert.EqualError(t, err, "secret not found")
}

func TestEditCardAndText(t *testing.T) {
	env := emptyAccount(t)
	env.passwords = []string{"123"}
	_, err := env.run("add", "card", "visa", "--number", "4111111111111111", "--expiry", "12/29")
	require.NoError(t, err)
	_, err = env.run("add", "text", "note", "--text", "v1")
	require.NoError(t, err)

	_, err = env.run("edit", "visa", "--expiry", "01/31")
	require.NoError(t, err)
	out, err := env.run("get", "visa")
	require.NoError(t, err)
	assert.Equal(t, "01/31", field(t, out, "Expiry"))
	assert.Equal(t, "123", field(t, out, "CVV"), "CVV kept")

	_, err = env.run("edit", "visa", "--expiry", "13/31")
	assert.ErrorIs(t, err, payload.ErrCardExpiry)

	_, err = env.run("edit", "note", "--text", "v2")
	require.NoError(t, err)
	out, err = env.run("get", "note")
	require.NoError(t, err)
	assert.Equal(t, "v2", field(t, out, "Text"))
}

func TestDelete(t *testing.T) {
	env := emptyAccount(t)
	_, err := env.run("add", "text", "note", "--text", "x")
	require.NoError(t, err)

	out, err := env.run("delete", "note")
	require.NoError(t, err)
	assert.Equal(t, "Deleted note\n", out)

	out, err = env.run("list")
	require.NoError(t, err)
	assert.Equal(t, "No secrets yet\n", out)

	_, err = env.run("delete", "note")
	assert.EqualError(t, err, "secret not found")
}

func TestWritesNeedServer(t *testing.T) {
	env := emptyAccount(t)
	_, err := env.run("add", "text", "note", "--text", "x")
	require.NoError(t, err)

	env.api.offline = true
	for _, args := range [][]string{
		{"add", "text", "other", "--text", "y"},
		{"edit", "note", "--text", "y"},
		{"delete", "note"},
	} {
		_, err := env.run(args...)
		assert.ErrorIs(t, err, errReadOnly, args[0])
	}
}

func TestApplyMeta(t *testing.T) {
	meta, err := applyMeta(map[string]string{"a": "1", "b": "2"}, []string{"a=", "c=3", "d=x=y"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"b": "2", "c": "3", "d": "x=y"}, meta)

	for _, bad := range []string{"novalue", "=v"} {
		_, err := applyMeta(nil, []string{bad})
		assert.Error(t, err, bad)
	}
}
