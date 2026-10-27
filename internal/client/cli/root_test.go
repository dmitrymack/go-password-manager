package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAPI accepts only the password "passw0rd" and serves secrets.
type fakeAPI struct {
	connectedTo api.Options
	secrets     []secret.Secret // what the server has; Sync returns all of it
	revision    int64
	offline     bool // every call fails with ErrUnavailable
}

func (f *fakeAPI) Register(_ context.Context, login, _ string) (string, error) {
	if f.offline {
		return "", api.ErrUnavailable
	}
	return "reg-" + login, nil
}

func (f *fakeAPI) Login(_ context.Context, login, password string) (string, error) {
	if password != "passw0rd" {
		return "", errors.New("invalid login or password")
	}
	return "login-" + login, nil
}

func (f *fakeAPI) Sync(context.Context, int64) ([]secret.Info, int64, error) {
	if f.offline {
		return nil, 0, api.ErrUnavailable
	}
	infos := make([]secret.Info, 0, len(f.secrets))
	for _, s := range f.secrets {
		infos = append(infos, s.Info)
	}
	return infos, f.revision, nil
}

func (f *fakeAPI) Get(_ context.Context, id string) (secret.Secret, error) {
	for _, s := range f.secrets {
		if s.ID == id && !s.Deleted {
			return s, nil
		}
	}
	return secret.Secret{}, api.ErrNotFound
}

func (f *fakeAPI) Create(_ context.Context, s secret.Secret) (secret.Info, error) {
	if f.offline {
		return secret.Info{}, api.ErrUnavailable
	}
	f.revision++
	s.ID = fmt.Sprintf("id-%d", len(f.secrets)+1)
	s.Version, s.Revision, s.UpdatedAt = 1, f.revision, updated
	f.secrets = append(f.secrets, s)
	return s.Info, nil
}

func (f *fakeAPI) Update(_ context.Context, s secret.Secret) (secret.Info, error) {
	for i, old := range f.secrets {
		if old.ID != s.ID || old.Deleted {
			continue
		}
		if old.Version != s.Version {
			return secret.Info{}, api.ErrConflict
		}
		f.revision++
		s.Version, s.Revision, s.UpdatedAt = old.Version+1, f.revision, updated
		f.secrets[i] = s
		return s.Info, nil
	}
	return secret.Info{}, api.ErrNotFound
}

func (f *fakeAPI) Delete(_ context.Context, id string) error {
	for i, s := range f.secrets {
		if s.ID == id && !s.Deleted {
			f.revision++
			f.secrets[i].Deleted, f.secrets[i].Data, f.secrets[i].Revision = true, nil, f.revision
			return nil
		}
	}
	return api.ErrNotFound
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
		Connect: func(opts api.Options) (API, error) {
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
