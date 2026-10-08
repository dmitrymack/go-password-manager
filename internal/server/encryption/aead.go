// Package encryption implements envelope encryption with AES-256-GCM:
// master key → KEKs (in DB) → DEKs (one per secret) → data.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the key size in bytes (AES-256).
const KeySize = 32

// ErrDecrypt means wrong key, wrong aad or tampered data.
var ErrDecrypt = errors.New("decryption failed")

// newKey returns a random key.
func newKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

// seal encrypts plaintext and returns nonce + ciphertext. aad is not
// encrypted, but open fails unless it gets the same aad.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends to its first argument: result is nonce + ciphertext.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// open reverses seal.
func open(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(sealed) < gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// newGCM creates an AES-GCM cipher.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
