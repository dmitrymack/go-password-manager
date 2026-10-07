package cli

import (
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/client/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	env := newTestEnv(t, "passw0rd", "passw0rd")

	out, err := env.run("register", "alice")
	require.NoError(t, err)
	assert.Equal(t, "Registered and logged in as alice\n", out)

	s, err := session.Load(env.dataDir)
	require.NoError(t, err)
	assert.Equal(t, session.Session{Server: "localhost:3200", Login: "alice", Token: "reg-alice"}, s)
}

func TestRegisterPasswordMismatch(t *testing.T) {
	env := newTestEnv(t, "passw0rd", "other")

	_, err := env.run("register", "alice")
	assert.EqualError(t, err, "passwords do not match")

	_, err = session.Load(env.dataDir)
	assert.ErrorIs(t, err, session.ErrNoSession)
}

func TestLoginAndLogout(t *testing.T) {
	env := newTestEnv(t, "passw0rd")

	out, err := env.run("login", "alice")
	require.NoError(t, err)
	assert.Equal(t, "Logged in as alice\n", out)

	s, err := session.Load(env.dataDir)
	require.NoError(t, err)
	assert.Equal(t, "login-alice", s.Token)

	out, err = env.run("logout")
	require.NoError(t, err)
	assert.Equal(t, "Logged out\n", out)

	_, err = session.Load(env.dataDir)
	assert.ErrorIs(t, err, session.ErrNoSession)
}

func TestLoginWrongPassword(t *testing.T) {
	env := newTestEnv(t, "wrong")

	_, err := env.run("login", "alice")
	assert.EqualError(t, err, "invalid login or password")

	_, err = session.Load(env.dataDir)
	assert.ErrorIs(t, err, session.ErrNoSession)
}

func TestAuthNeedsLogin(t *testing.T) {
	for _, cmd := range []string{"register", "login"} {
		_, err := newTestEnv(t).run(cmd)
		assert.Error(t, err, cmd)
	}
}

func TestPasswordInputError(t *testing.T) {
	_, err := newTestEnv(t).run("login", "alice")
	assert.Error(t, err)

	_, err = newTestEnv(t, "passw0rd").run("register", "alice")
	assert.Error(t, err)
}
