package cli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAPI is an AuthAPI that accepts only the password "passw0rd".
type fakeAPI struct {
	connectedTo api.Options
}

func (f *fakeAPI) Register(_ context.Context, login, _ string) (string, error) {
	return "reg-" + login, nil
}

func (f *fakeAPI) Login(_ context.Context, login, password string) (string, error) {
	if password != "passw0rd" {
		return "", errors.New("invalid login or password")
	}
	return "login-" + login, nil
}

func (f *fakeAPI) Close() error { return nil }

// testEnv runs commands against a fakeAPI, with passwords taken from a list
// and a temporary data dir.
type testEnv struct {
	api       *fakeAPI
	passwords []string
	dataDir   string
}

func newTestEnv(t *testing.T, passwords ...string) *testEnv {
	return &testEnv{api: &fakeAPI{}, passwords: passwords, dataDir: t.TempDir()}
}

// run executes the command line args and returns its output.
func (e *testEnv) run(args ...string) (string, error) {
	deps := Deps{
		Connect: func(opts api.Options) (AuthAPI, error) {
			e.api.connectedTo = opts
			return e.api, nil
		},
		ReadPassword: func(string) (string, error) {
			if len(e.passwords) == 0 {
				return "", errors.New("no more input")
			}
			p := e.passwords[0]
			e.passwords = e.passwords[1:]
			return p, nil
		},
	}

	root := NewRootCmd(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"--data-dir", e.dataDir}, args...))

	err := root.Execute()
	return out.String(), err
}

func TestVersion(t *testing.T) {
	out, err := newTestEnv(t).run("version")
	require.NoError(t, err)
	assert.Equal(t, buildinfo.String()+"\n", out)
}

func TestVersionRejectsArgs(t *testing.T) {
	_, err := newTestEnv(t).run("version", "extra")
	assert.Error(t, err)
}

func TestGlobalFlags(t *testing.T) {
	env := newTestEnv(t, "passw0rd")
	_, err := env.run("--server", "example.com:443", "--ca-cert", "ca.crt", "login", "alice")
	require.NoError(t, err)
	assert.Equal(t, api.Options{Address: "example.com:443", CACertFile: "ca.crt"}, env.api.connectedTo)
}
