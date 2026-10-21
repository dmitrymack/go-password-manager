package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updated = time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)

func serverSecrets() []secret.Secret {
	return []secret.Secret{
		{
			Info: secret.Info{ID: "id-1", Type: secret.TypeLogin, Name: "github",
				Metadata: map[string]string{"site": "github.com", "env": "work"}, UpdatedAt: updated},
			Data: []byte(`{"login":"alice","password":"p"}`),
		},
		{
			Info: secret.Info{ID: "id-2", Type: secret.TypeBinary, Name: "photo", UpdatedAt: updated},
			Data: []byte{0, 1, 2},
		},
	}
}

// loggedIn returns an env with a saved session and the server's secrets.
func loggedIn(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t, "passw0rd")
	_, err := env.run("login", "alice")
	require.NoError(t, err)
	env.api.secrets, env.api.revision = serverSecrets(), 2
	return env
}

func TestSyncListGet(t *testing.T) {
	env := loggedIn(t)

	out, err := env.run("sync")
	require.NoError(t, err)
	assert.Equal(t, "Synced: 2 updated, 0 deleted\n", out)
	assert.Equal(t, "login-alice", env.api.connectedTo.Token, "token from the session is sent")

	out, err = env.run("list")
	require.NoError(t, err)
	assert.Equal(t, ""+
		"NAME    TYPE    METADATA                   UPDATED              ID\n"+
		"github  login   env=work, site=github.com  2026-10-01 12:00:00  id-1\n"+
		"photo   binary                             2026-10-01 12:00:00  id-2\n", out)

	out, err = env.run("get", "github")
	require.NoError(t, err)
	assert.Equal(t, ""+
		"Name:      github\n"+
		"Type:      login\n"+
		"ID:        id-1\n"+
		"Updated:   2026-10-01 12:00:00\n"+
		"Metadata:  env=work, site=github.com\n"+
		`Data:      {"login":"alice","password":"p"}`+"\n", out)

	out, err = env.run("get", "id-2")
	require.NoError(t, err)
	assert.Contains(t, out, "Data:     <3 bytes of binary data>")

	_, err = env.run("get", "nothing")
	assert.EqualError(t, err, "secret not found")
}

func TestOfflineReadOnly(t *testing.T) {
	env := loggedIn(t)
	_, err := env.run("sync")
	require.NoError(t, err)

	env.api.offline = true

	out, err := env.run("get", "github")
	require.NoError(t, err, "reads work from the cache")
	assert.Contains(t, out, "Warning: server unavailable, showing cached data (read-only mode)")
	assert.Contains(t, out, `"password":"p"`)

	out, err = env.run("list")
	require.NoError(t, err)
	assert.Contains(t, out, "photo")

	_, err = env.run("sync")
	assert.ErrorContains(t, err, "server unavailable", "an explicit sync must fail")
}

func TestListEmpty(t *testing.T) {
	env := loggedIn(t)
	env.api.secrets = nil

	out, err := env.run("list")
	require.NoError(t, err)
	assert.Equal(t, "No secrets yet\n", out)
}

func TestSecretCommandsNeedLogin(t *testing.T) {
	for _, args := range [][]string{{"sync"}, {"list"}, {"get", "x"}} {
		_, err := newTestEnv(t).run(args...)
		assert.ErrorContains(t, err, "not logged in", args[0])
	}
}

func TestLogoutRemovesCache(t *testing.T) {
	env := loggedIn(t)
	_, err := env.run("sync")
	require.NoError(t, err)

	cacheFile := filepath.Join(env.dataDir, cacheFileName)
	require.FileExists(t, cacheFile)

	_, err = env.run("logout")
	require.NoError(t, err)
	_, err = os.Stat(cacheFile)
	assert.True(t, os.IsNotExist(err))
}

func TestLoginResetsCache(t *testing.T) {
	env := loggedIn(t)
	_, err := env.run("sync")
	require.NoError(t, err)

	// Log in again (e.g. as another user): the old cache must not survive.
	env.passwords = []string{"passw0rd"}
	env.api.secrets = nil
	_, err = env.run("login", "bob")
	require.NoError(t, err)

	out, err := env.run("list")
	require.NoError(t, err)
	assert.Equal(t, "No secrets yet\n", out)
}
