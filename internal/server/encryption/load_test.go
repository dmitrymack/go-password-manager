package encryption

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memKEKs is an in-memory KEKStore.
type memKEKs struct {
	keks []StoredKEK
	err  error
}

func (m *memKEKs) KEKs(context.Context) ([]StoredKEK, error) { return m.keks, m.err }

func (m *memKEKs) AddKEK(_ context.Context, k StoredKEK) error {
	m.keks = append(m.keks, k)
	return nil
}

func TestLoadKeyringFirstStart(t *testing.T) {
	store := &memKEKs{}

	k, err := LoadKeyring(context.Background(), store, masterKey)
	require.NoError(t, err)
	assert.Equal(t, 1, k.ActiveVersion())
	require.Len(t, store.keks, 1, "KEK v1 must be stored")

	// Next start reuses the stored KEK: old data stays readable.
	sealed, err := k.Encrypt([]byte("data"), nil)
	require.NoError(t, err)

	k2, err := LoadKeyring(context.Background(), store, masterKey)
	require.NoError(t, err)
	assert.Len(t, store.keks, 1)
	got, err := k2.Decrypt(sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

func TestLoadKeyringErrors(t *testing.T) {
	_, err := LoadKeyring(context.Background(), &memKEKs{err: errors.New("db is down")}, masterKey)
	assert.Error(t, err)

	_, err = LoadKeyring(context.Background(), &memKEKs{}, []byte("short"))
	assert.Error(t, err)
}
