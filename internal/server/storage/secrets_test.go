package storage

import (
	"context"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/server/encryption"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSecret returns a secret of userID ready for CreateSecret.
func newSecret(userID, name string) Secret {
	return Secret{
		ID:       uuid.NewString(),
		UserID:   userID,
		Type:     1,
		Name:     name,
		Metadata: map[string]string{"site": "example.com"},
		Sealed:   encryption.Sealed{Ciphertext: []byte("ct"), WrappedDEK: []byte("dek"), KEKVersion: 1},
	}
}

func TestKEKs(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	keks, err := db.KEKs(ctx)
	require.NoError(t, err)
	assert.Empty(t, keks)

	require.NoError(t, db.AddKEK(ctx, encryption.StoredKEK{Version: 2, Wrapped: []byte("b")}))
	require.NoError(t, db.AddKEK(ctx, encryption.StoredKEK{Version: 1, Wrapped: []byte("a")}))
	assert.Error(t, db.AddKEK(ctx, encryption.StoredKEK{Version: 1, Wrapped: []byte("dup")}))

	keks, err = db.KEKs(ctx)
	require.NoError(t, err)
	assert.Equal(t, []encryption.StoredKEK{{Version: 1, Wrapped: []byte("a")}, {Version: 2, Wrapped: []byte("b")}}, keks)
}

func TestSecretsLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	require.NoError(t, db.AddKEK(ctx, encryption.StoredKEK{Version: 1, Wrapped: []byte("k")}))
	alice, err := db.CreateUser(ctx, "alice", "hash")
	require.NoError(t, err)
	bob, err := db.CreateUser(ctx, "bob", "hash")
	require.NoError(t, err)

	// Create: version 1, revision 1.
	created, err := db.CreateSecret(ctx, newSecret(alice, "github"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), created.Version)
	assert.Equal(t, int64(1), created.Revision)

	got, err := db.GetSecret(ctx, alice, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.Sealed, got.Sealed)
	assert.Equal(t, created.Metadata, got.Metadata)

	// Other users don't see it.
	_, err = db.GetSecret(ctx, bob, created.ID)
	assert.ErrorIs(t, err, ErrNotFound)

	// Update with the right version.
	upd := created
	upd.Name = "github work"
	upd.Sealed.Ciphertext = []byte("ct2")
	updated, err := db.UpdateSecret(ctx, upd, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)
	assert.Equal(t, int64(2), updated.Revision)

	// Update with a stale version: conflict. Revision is not bumped.
	_, err = db.UpdateSecret(ctx, upd, 1)
	assert.ErrorIs(t, err, ErrVersionConflict)

	upd.ID = uuid.NewString()
	_, err = db.UpdateSecret(ctx, upd, 1)
	assert.ErrorIs(t, err, ErrNotFound)

	// Sync from 0 sees the secret once, with its latest state.
	changed, rev, err := db.SecretsChangedSince(ctx, alice, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), rev)
	require.Len(t, changed, 1)
	assert.Equal(t, "github work", changed[0].Name)

	// Nothing new since the current revision.
	changed, _, err = db.SecretsChangedSince(ctx, alice, rev)
	require.NoError(t, err)
	assert.Empty(t, changed)

	// Delete leaves a tombstone visible to Sync.
	deleted, err := db.DeleteSecret(ctx, alice, created.ID)
	require.NoError(t, err)
	assert.True(t, deleted.Deleted)
	assert.Equal(t, "github work", deleted.Name)

	_, err = db.GetSecret(ctx, alice, created.ID)
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = db.DeleteSecret(ctx, alice, created.ID)
	assert.ErrorIs(t, err, ErrNotFound)

	changed, rev, err = db.SecretsChangedSince(ctx, alice, rev)
	require.NoError(t, err)
	assert.Equal(t, int64(3), rev)
	require.Len(t, changed, 1)
	assert.True(t, changed[0].Deleted)

	// Bob's revision is untouched by Alice's changes.
	_, rev, err = db.SecretsChangedSince(ctx, bob, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), rev)

	_, _, err = db.SecretsChangedSince(ctx, uuid.NewString(), 0)
	assert.ErrorIs(t, err, ErrNotFound)
}
