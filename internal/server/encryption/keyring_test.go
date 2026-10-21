package encryption

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var masterKey = bytes.Repeat([]byte{7}, KeySize)

// newTestKeyring returns a keyring with KEKs of the given versions, plus
// the stored KEKs so tests can build other keyrings from them.
func newTestKeyring(t *testing.T, versions ...int) (*Keyring, []StoredKEK) {
	t.Helper()

	var stored []StoredKEK
	for _, v := range versions {
		s, err := GenerateKEK(masterKey, v)
		require.NoError(t, err)
		stored = append(stored, s)
	}

	k, err := NewKeyring(masterKey, stored)
	require.NoError(t, err)
	return k, stored
}

func TestEncryptDecrypt(t *testing.T) {
	k, _ := newTestKeyring(t, 1)
	plaintext := []byte("my secret password")
	aad := []byte("user-1/secret-1")

	sealed, err := k.Encrypt(plaintext, aad)
	require.NoError(t, err)
	assert.Equal(t, 1, sealed.KEKVersion)
	assert.NotContains(t, string(sealed.Ciphertext), "my secret password")

	got, err := k.Decrypt(sealed, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptUsesFreshKeys(t *testing.T) {
	k, _ := newTestKeyring(t, 1)

	a, err := k.Encrypt([]byte("same"), nil)
	require.NoError(t, err)
	b, err := k.Encrypt([]byte("same"), nil)
	require.NoError(t, err)

	assert.NotEqual(t, a.Ciphertext, b.Ciphertext)
	assert.NotEqual(t, a.WrappedDEK, b.WrappedDEK)
}

func TestDecryptRejects(t *testing.T) {
	k, _ := newTestKeyring(t, 1)
	aad := []byte("user-1/secret-1")
	sealed, err := k.Encrypt([]byte("data"), aad)
	require.NoError(t, err)

	tamperedData := sealed
	tamperedData.Ciphertext = bytes.Clone(sealed.Ciphertext)
	tamperedData.Ciphertext[len(tamperedData.Ciphertext)-1] ^= 1

	tamperedDEK := sealed
	tamperedDEK.WrappedDEK = bytes.Clone(sealed.WrappedDEK)
	tamperedDEK.WrappedDEK[0] ^= 1

	tooShort := sealed
	tooShort.Ciphertext = []byte{1, 2, 3}

	tests := []struct {
		name   string
		sealed Sealed
		aad    []byte
		want   error
	}{
		{name: "other owner", sealed: sealed, aad: []byte("user-2/secret-1"), want: ErrDecrypt},
		{name: "tampered data", sealed: tamperedData, aad: aad, want: ErrDecrypt},
		{name: "tampered DEK", sealed: tamperedDEK, aad: aad, want: ErrDecrypt},
		{name: "too short", sealed: tooShort, aad: aad, want: ErrDecrypt},
		{name: "unknown KEK", sealed: Sealed{KEKVersion: 99}, aad: aad, want: ErrUnknownKEK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := k.Decrypt(tt.sealed, tt.aad)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestRotation(t *testing.T) {
	// Data encrypted before rotation, with KEK v1.
	oldRing, stored := newTestKeyring(t, 1)
	aad := []byte("user-1/secret-1")
	sealed, err := oldRing.Encrypt([]byte("data"), aad)
	require.NoError(t, err)

	// Rotation: add KEK v2. The new keyring encrypts with v2 but still
	// decrypts v1 data.
	v2, err := GenerateKEK(masterKey, 2)
	require.NoError(t, err)
	newRing, err := NewKeyring(masterKey, append(stored, v2))
	require.NoError(t, err)
	assert.Equal(t, 2, newRing.ActiveVersion())

	got, err := newRing.Decrypt(sealed, aad)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)

	// Rewrap moves the DEK to v2 without touching the data.
	rewrapped, err := newRing.Rewrap(sealed)
	require.NoError(t, err)
	assert.Equal(t, 2, rewrapped.KEKVersion)
	assert.Equal(t, sealed.Ciphertext, rewrapped.Ciphertext)

	// After rewrapping everything, v1 can be dropped.
	onlyV2, err := NewKeyring(masterKey, []StoredKEK{v2})
	require.NoError(t, err)
	got, err = onlyV2.Decrypt(rewrapped, aad)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)

	_, err = onlyV2.Rewrap(sealed)
	assert.ErrorIs(t, err, ErrUnknownKEK)
}

func TestNewKeyringErrors(t *testing.T) {
	_, err := NewKeyring(masterKey, nil)
	assert.Error(t, err)

	stored, err := GenerateKEK(masterKey, 1)
	require.NoError(t, err)
	wrongMaster := bytes.Repeat([]byte{8}, KeySize)
	_, err = NewKeyring(wrongMaster, []StoredKEK{stored})
	assert.ErrorIs(t, err, ErrDecrypt)

	_, err = GenerateKEK([]byte("short"), 1)
	assert.Error(t, err)
}

func TestParseMasterKey(t *testing.T) {
	key, err := ParseMasterKey(strings.Repeat("ab", KeySize))
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte{0xab}, KeySize), key)

	for _, bad := range []string{"", "not hex", strings.Repeat("ab", KeySize-1)} {
		_, err := ParseMasterKey(bad)
		assert.Error(t, err, bad)
	}
}
