package encryption

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memRotation is an in-memory RotationStore; secrets maps id → sealed data.
type memRotation struct {
	memKEKs
	secrets map[string]Sealed
	err     error
}

func (m *memRotation) DEKsBelow(_ context.Context, version, limit int) ([]WrappedDEK, error) {
	var deks []WrappedDEK
	for id, s := range m.secrets {
		if s.KEKVersion < version && len(deks) < limit {
			deks = append(deks, WrappedDEK{SecretID: id, Wrapped: s.WrappedDEK, KEKVersion: s.KEKVersion})
		}
	}
	return deks, m.err
}

func (m *memRotation) ReplaceDEK(_ context.Context, old WrappedDEK, wrapped []byte, kekVersion int) error {
	s := m.secrets[old.SecretID]
	s.WrappedDEK, s.KEKVersion = wrapped, kekVersion
	m.secrets[old.SecretID] = s
	return nil
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	store := &memRotation{secrets: map[string]Sealed{}}

	keys, err := LoadKeyring(ctx, store, masterKey)
	require.NoError(t, err)
	// More than one batch.
	for i := range rotateBatch + 5 {
		id := fmt.Sprint(i)
		store.secrets[id], err = keys.Encrypt([]byte("data "+id), []byte(id))
		require.NoError(t, err)
	}

	res, err := Rotate(ctx, store, masterKey)
	require.NoError(t, err)
	assert.Equal(t, RotateResult{Version: 2, Rewrapped: rotateBatch + 5}, res)

	// Everything is on KEK v2, the data is unchanged and still readable.
	keys, err = LoadKeyring(ctx, store, masterKey)
	require.NoError(t, err)
	for id, s := range store.secrets {
		assert.Equal(t, 2, s.KEKVersion)
		got, err := keys.Decrypt(s, []byte(id))
		require.NoError(t, err)
		assert.Equal(t, "data "+id, string(got))
	}

	// Second rotation: v3, nothing left on older KEKs.
	res, err = Rotate(ctx, store, masterKey)
	require.NoError(t, err)
	assert.Equal(t, 3, res.Version)
}

func TestRotateErrors(t *testing.T) {
	ctx := context.Background()

	_, err := Rotate(ctx, &memRotation{memKEKs: memKEKs{err: errors.New("db is down")}}, masterKey)
	assert.Error(t, err)

	_, err = Rotate(ctx, &memRotation{err: errors.New("db is down")}, masterKey)
	assert.Error(t, err)

	// A DEK that no KEK can open.
	store := &memRotation{secrets: map[string]Sealed{"x": {WrappedDEK: []byte("garbage"), KEKVersion: 1}}}
	_, err = Rotate(ctx, store, masterKey)
	assert.ErrorIs(t, err, ErrDecrypt)
}
