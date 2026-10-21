package cache

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/aead"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestCache(t *testing.T) (*Cache, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cache.db")
	key := bytes.Repeat([]byte{3}, aead.KeySize)

	c, err := Open(path, key)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c, path
}

func newSecret(id, name, data string) secret.Secret {
	return secret.Secret{
		Info: secret.Info{
			ID: id, Type: secret.TypeLogin, Name: name, Metadata: map[string]string{"site": "x.com"},
			Version: 1, Revision: 1, UpdatedAt: time.Unix(1700000000, 0),
		},
		Data: []byte(data),
	}
}

func TestPutGetListDelete(t *testing.T) {
	c, path := openTestCache(t)
	ctx := context.Background()

	want := newSecret("id-1", "github", "top secret")
	require.NoError(t, c.Put(ctx, want))
	require.NoError(t, c.Put(ctx, newSecret("id-2", "aws", "other")))

	got, err := c.Get(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, want, got)

	got, err = c.Get(ctx, "github")
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)

	list, err := c.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "aws", list[0].Name, "sorted by name")
	assert.Equal(t, want.Info, list[1])

	// Data is encrypted on disk.
	file, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(file), "top secret")

	// Put replaces.
	want.Name, want.Data = "github work", []byte("changed")
	require.NoError(t, c.Put(ctx, want))
	got, err = c.Get(ctx, "id-1")
	require.NoError(t, err)
	assert.Equal(t, []byte("changed"), got.Data)

	require.NoError(t, c.Delete(ctx, "id-1"))
	_, err = c.Get(ctx, "id-1")
	assert.ErrorIs(t, err, ErrNotFound)
	assert.NoError(t, c.Delete(ctx, "id-1"), "deleting twice is fine")
}

func TestGetAmbiguousName(t *testing.T) {
	c, _ := openTestCache(t)
	ctx := context.Background()

	require.NoError(t, c.Put(ctx, newSecret("id-1", "mail", "a")))
	require.NoError(t, c.Put(ctx, newSecret("id-2", "mail", "b")))

	_, err := c.Get(ctx, "mail")
	assert.ErrorIs(t, err, ErrAmbiguous)

	got, err := c.Get(ctx, "id-2")
	require.NoError(t, err)
	assert.Equal(t, []byte("b"), got.Data)
}

func TestRevision(t *testing.T) {
	c, path := openTestCache(t)
	ctx := context.Background()

	rev, err := c.Revision(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), rev)

	require.NoError(t, c.SetRevision(ctx, 5))
	require.NoError(t, c.SetRevision(ctx, 7))

	// Survives reopening.
	require.NoError(t, c.Close())
	c2, err := Open(path, c.key)
	require.NoError(t, err)
	defer c2.Close()

	rev, err = c2.Revision(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(7), rev)
}

func TestWrongKey(t *testing.T) {
	c, path := openTestCache(t)
	ctx := context.Background()
	require.NoError(t, c.Put(ctx, newSecret("id-1", "github", "data")))

	other, err := Open(path, bytes.Repeat([]byte{4}, aead.KeySize))
	require.NoError(t, err)
	defer other.Close()

	_, err = other.Get(ctx, "id-1")
	assert.ErrorIs(t, err, aead.ErrDecrypt)
}

func TestOpenBadPath(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing-dir", "cache.db"), nil)
	assert.Error(t, err)
}
