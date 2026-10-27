package secrets

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/server/encryption"
	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore keeps secrets in a map; enough logic for the service tests.
type fakeStore struct {
	secrets map[string]storage.Secret // by ID
}

func (f *fakeStore) CreateSecret(_ context.Context, s storage.Secret) (storage.Secret, error) {
	s.Version = 1
	f.secrets[s.ID] = s
	return s, nil
}

func (f *fakeStore) UpdateSecret(_ context.Context, s storage.Secret, version int64) (storage.Secret, error) {
	old, ok := f.secrets[s.ID]
	if !ok || old.UserID != s.UserID {
		return storage.Secret{}, storage.ErrNotFound
	}
	if old.Version != version {
		return storage.Secret{}, storage.ErrVersionConflict
	}
	s.Type, s.Version = old.Type, old.Version+1
	f.secrets[s.ID] = s
	return s, nil
}

func (f *fakeStore) DeleteSecret(_ context.Context, userID, id string) (storage.Secret, error) {
	s, ok := f.secrets[id]
	if !ok || s.UserID != userID {
		return storage.Secret{}, storage.ErrNotFound
	}
	delete(f.secrets, id)
	s.Deleted = true
	return s, nil
}

func (f *fakeStore) GetSecret(_ context.Context, userID, id string) (storage.Secret, error) {
	s, ok := f.secrets[id]
	if !ok || s.UserID != userID {
		return storage.Secret{}, storage.ErrNotFound
	}
	return s, nil
}

func (f *fakeStore) SecretsChangedSince(context.Context, string, int64) ([]storage.Secret, int64, error) {
	return []storage.Secret{{ID: "x"}}, 7, nil
}

func newTestService(t *testing.T) (*Service, *fakeStore) {
	t.Helper()

	master := bytes.Repeat([]byte{1}, encryption.KeySize)
	kek, err := encryption.GenerateKEK(master, 1)
	require.NoError(t, err)
	keys, err := encryption.NewKeyring(master, []encryption.StoredKEK{kek})
	require.NoError(t, err)

	store := &fakeStore{secrets: map[string]storage.Secret{}}
	return NewService(store, keys), store
}

func TestCreateGetUpdateDelete(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	in := Input{Type: TypeLogin, Name: "github", Metadata: map[string]string{"site": "github.com"}, Data: []byte(`{"password":"p"}`)}
	created, err := svc.Create(ctx, "alice", in)
	require.NoError(t, err)
	assert.NoError(t, uuid.Validate(created.ID))
	assert.NotContains(t, string(store.secrets[created.ID].Sealed.Ciphertext), "password", "data must be encrypted")

	got, data, err := svc.Get(ctx, "alice", created.ID)
	require.NoError(t, err)
	assert.Equal(t, "github", got.Name)
	assert.Equal(t, in.Data, data)

	_, _, err = svc.Get(ctx, "bob", created.ID)
	assert.ErrorIs(t, err, ErrNotFound)

	in.Name, in.Data = "github work", []byte("new")
	updated, err := svc.Update(ctx, "alice", created.ID, created.Version, in)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)

	_, data, err = svc.Get(ctx, "alice", created.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), data)

	_, err = svc.Update(ctx, "alice", created.ID, created.Version, in)
	assert.ErrorIs(t, err, ErrVersionConflict)

	deleted, err := svc.Delete(ctx, "alice", created.ID)
	require.NoError(t, err)
	assert.True(t, deleted.Deleted)

	_, err = svc.Delete(ctx, "alice", created.ID)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestDataIsBoundToOwner(t *testing.T) {
	svc, store := newTestService(t)
	ctx := context.Background()

	a, err := svc.Create(ctx, "alice", Input{Type: TypeText, Name: "a", Data: []byte("alice's")})
	require.NoError(t, err)
	b, err := svc.Create(ctx, "bob", Input{Type: TypeText, Name: "b", Data: []byte("bob's")})
	require.NoError(t, err)

	// Someone with DB access copies Alice's encrypted data into Bob's row.
	stolen := store.secrets[b.ID]
	stolen.Sealed = store.secrets[a.ID].Sealed
	store.secrets[b.ID] = stolen

	_, _, err = svc.Get(ctx, "bob", b.ID)
	assert.ErrorIs(t, err, encryption.ErrDecrypt)
}

func TestValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	ok := Input{Type: TypeText, Name: "n"}

	tooMuchMeta := map[string]string{}
	for i := range maxMetadataEntries + 1 {
		tooMuchMeta[strings.Repeat("k", i+1)] = "v"
	}

	tests := []struct {
		name string
		in   func(in Input) Input
		want error
	}{
		{"no type", func(in Input) Input { in.Type = 0; return in }, ErrBadType},
		{"unknown type", func(in Input) Input { in.Type = 5; return in }, ErrBadType},
		{"empty name", func(in Input) Input { in.Name = ""; return in }, ErrBadName},
		{"long name", func(in Input) Input { in.Name = strings.Repeat("я", maxNameLen+1); return in }, ErrBadName},
		{"metadata", func(in Input) Input { in.Metadata = tooMuchMeta; return in }, ErrTooMuchMetadata},
		{"big data", func(in Input) Input { in.Data = make([]byte, MaxDataSize+1); return in }, ErrDataTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Create(ctx, "alice", tt.in(ok))
			assert.ErrorIs(t, err, tt.want)
		})
	}

	_, err := svc.Create(ctx, "alice", Input{Type: TypeText, Name: strings.Repeat("я", maxNameLen)})
	assert.NoError(t, err, "name limit counts characters, not bytes")
}

func TestInvalidID(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Update(ctx, "alice", "not-a-uuid", 1, Input{Name: "n"})
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = svc.Delete(ctx, "alice", "not-a-uuid")
	assert.ErrorIs(t, err, ErrNotFound)
	_, _, err = svc.Get(ctx, "alice", "not-a-uuid")
	assert.ErrorIs(t, err, ErrNotFound)

	_, err = svc.Update(ctx, "alice", uuid.NewString(), 1, Input{Name: ""})
	assert.ErrorIs(t, err, ErrBadName)
}

func TestSync(t *testing.T) {
	svc, _ := newTestService(t)
	changed, rev, err := svc.Sync(context.Background(), "alice", 0)
	require.NoError(t, err)
	assert.Len(t, changed, 1)
	assert.Equal(t, int64(7), rev)
}
