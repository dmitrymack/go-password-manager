package syncer

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/aead"
	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/dmitrymack/go-password-manager/internal/client/cache"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRemote serves a fixed list of changes; data is "data-<id>".
type fakeRemote struct {
	changed  []secret.Info
	revision int64
	gone     map[string]bool // Get returns ErrNotFound for these
	err      error           // returned by Sync
	gotSince int64
}

func (f *fakeRemote) Sync(_ context.Context, since int64) ([]secret.Info, int64, error) {
	f.gotSince = since
	return f.changed, f.revision, f.err
}

func (f *fakeRemote) Get(_ context.Context, id string) (secret.Secret, error) {
	if f.gone[id] {
		return secret.Secret{}, api.ErrNotFound
	}
	for _, info := range f.changed {
		if info.ID == id {
			return secret.Secret{Info: info, Data: []byte("data-" + id)}, nil
		}
	}
	return secret.Secret{}, errors.New("unexpected Get")
}

func openCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.Open(filepath.Join(t.TempDir(), "cache.db"), bytes.Repeat([]byte{1}, aead.KeySize))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRun(t *testing.T) {
	ctx := context.Background()
	local := openCache(t)

	// First sync: two secrets arrive.
	remote := &fakeRemote{
		changed:  []secret.Info{{ID: "a", Name: "github"}, {ID: "b", Name: "mail"}},
		revision: 2,
	}
	res, err := Run(ctx, remote, local)
	require.NoError(t, err)
	assert.Equal(t, Result{Updated: 2}, res)
	assert.Equal(t, int64(0), remote.gotSince)

	got, err := local.Get(ctx, "github")
	require.NoError(t, err)
	assert.Equal(t, []byte("data-a"), got.Data)

	// Second sync starts from the saved revision: "a" deleted, "c" added
	// but deleted on the server before we could Get it.
	remote = &fakeRemote{
		changed:  []secret.Info{{ID: "a", Deleted: true}, {ID: "c", Name: "gone"}},
		revision: 4,
		gone:     map[string]bool{"c": true},
	}
	res, err = Run(ctx, remote, local)
	require.NoError(t, err)
	assert.Equal(t, Result{Deleted: 1}, res)
	assert.Equal(t, int64(2), remote.gotSince)

	list, err := local.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "mail", list[0].Name)

	rev, err := local.Revision(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), rev)
}

func TestRunServerError(t *testing.T) {
	ctx := context.Background()
	local := openCache(t)

	_, err := Run(ctx, &fakeRemote{err: api.ErrUnavailable}, local)
	assert.ErrorIs(t, err, api.ErrUnavailable)

	rev, err := local.Revision(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), rev, "revision must not move on failure")
}

func TestRunGetError(t *testing.T) {
	ctx := context.Background()
	local := openCache(t)

	remote := brokenGet{&fakeRemote{changed: []secret.Info{{ID: "x"}}, revision: 1}}

	_, err := Run(ctx, remote, local)
	assert.Error(t, err)

	rev, err := local.Revision(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), rev)
}

// brokenGet fails every Get.
type brokenGet struct{ *fakeRemote }

func (brokenGet) Get(context.Context, string) (secret.Secret, error) {
	return secret.Secret{}, errors.New("connection reset")
}
