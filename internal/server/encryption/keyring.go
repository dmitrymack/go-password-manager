package encryption

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrUnknownKEK means the keyring has no KEK of the requested version.
var ErrUnknownKEK = errors.New("unknown KEK version")

// StoredKEK is a KEK encrypted with the master key, as stored in the DB.
type StoredKEK struct {
	Version int
	Wrapped []byte
}

// Sealed is encrypted data plus what's needed to decrypt it; stored in the DB.
type Sealed struct {
	Ciphertext []byte // the data, encrypted with the DEK
	WrappedDEK []byte // the DEK, encrypted with the KEK
	KEKVersion int    // which KEK encrypted the DEK
}

// Keyring holds decrypted KEKs. Immutable, so safe for concurrent use.
type Keyring struct {
	keks   map[int][]byte // version → plaintext KEK
	active int            // version used for new encryptions
}

// ParseMasterKey decodes a hex master key (64 characters).
func ParseMasterKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("master key is not valid hex: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes (%d hex characters), got %d bytes",
			KeySize, KeySize*2, len(key))
	}
	return key, nil
}

// GenerateKEK creates a random KEK encrypted with masterKey.
func GenerateKEK(masterKey []byte, version int) (StoredKEK, error) {
	kek, err := newKey()
	if err != nil {
		return StoredKEK{}, err
	}
	wrapped, err := seal(masterKey, kek, nil)
	if err != nil {
		return StoredKEK{}, err
	}
	return StoredKEK{Version: version, Wrapped: wrapped}, nil
}

// NewKeyring decrypts the KEKs; the highest version becomes active.
func NewKeyring(masterKey []byte, stored []StoredKEK) (*Keyring, error) {
	if len(stored) == 0 {
		return nil, errors.New("no KEKs: generate one first")
	}

	k := &Keyring{keks: make(map[int][]byte, len(stored))}
	for _, s := range stored {
		kek, err := open(masterKey, s.Wrapped, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypting KEK v%d (wrong master key?): %w", s.Version, err)
		}
		k.keks[s.Version] = kek
		k.active = max(k.active, s.Version)
	}
	return k, nil
}

// ActiveVersion returns the KEK version used for new encryptions.
func (k *Keyring) ActiveVersion() int {
	return k.active
}

// Encrypt encrypts with a fresh DEK; aad binds the result to its owner.
func (k *Keyring) Encrypt(plaintext, aad []byte) (Sealed, error) {
	dek, err := newKey()
	if err != nil {
		return Sealed{}, err
	}

	ciphertext, err := seal(dek, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}

	wrappedDEK, err := seal(k.keks[k.active], dek, nil)
	if err != nil {
		return Sealed{}, err
	}

	return Sealed{Ciphertext: ciphertext, WrappedDEK: wrappedDEK, KEKVersion: k.active}, nil
}

// Decrypt reverses Encrypt with the same aad.
func (k *Keyring) Decrypt(s Sealed, aad []byte) ([]byte, error) {
	dek, err := k.unwrapDEK(s)
	if err != nil {
		return nil, err
	}
	return open(dek, s.Ciphertext, aad)
}

// Rewrap re-encrypts only the DEK with the active KEK (for rotation).
func (k *Keyring) Rewrap(s Sealed) (Sealed, error) {
	dek, err := k.unwrapDEK(s)
	if err != nil {
		return Sealed{}, err
	}

	wrappedDEK, err := seal(k.keks[k.active], dek, nil)
	if err != nil {
		return Sealed{}, err
	}

	return Sealed{Ciphertext: s.Ciphertext, WrappedDEK: wrappedDEK, KEKVersion: k.active}, nil
}

// unwrapDEK decrypts the DEK of s.
func (k *Keyring) unwrapDEK(s Sealed) ([]byte, error) {
	kek, ok := k.keks[s.KEKVersion]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownKEK, s.KEKVersion)
	}
	return open(kek, s.WrappedDEK, nil)
}
