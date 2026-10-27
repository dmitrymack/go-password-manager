package aead

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealOpen(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)

	sealed, err := Seal(key, []byte("hello"), []byte("aad"))
	require.NoError(t, err)

	got, err := Open(key, sealed, []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)

	_, err = Open(key, sealed, []byte("other"))
	assert.ErrorIs(t, err, ErrDecrypt)

	_, err = Open(key, []byte{1, 2}, nil)
	assert.ErrorIs(t, err, ErrDecrypt)

	otherKey, err := NewKey()
	require.NoError(t, err)
	_, err = Open(otherKey, sealed, []byte("aad"))
	assert.ErrorIs(t, err, ErrDecrypt)
}

func TestBadKeySize(t *testing.T) {
	_, err := Seal([]byte("short"), nil, nil)
	assert.Error(t, err)
	_, err = Open([]byte("short"), make([]byte, 64), nil)
	assert.Error(t, err)
}
