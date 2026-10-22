package encryption

import (
	"context"
	"fmt"
)

// rotateBatch is how many DEKs Rotate reads at a time.
const rotateBatch = 100

// WrappedDEK is a secret's encrypted DEK, without the data itself.
type WrappedDEK struct {
	SecretID   string
	Wrapped    []byte
	KEKVersion int
}

// RotationStore is what Rotate needs from the DB.
type RotationStore interface {
	KEKStore
	// DEKsBelow returns up to limit DEKs wrapped with a KEK older than version.
	DEKsBelow(ctx context.Context, version, limit int) ([]WrappedDEK, error)
	// ReplaceDEK stores the rewrapped DEK unless the secret changed since old was read.
	ReplaceDEK(ctx context.Context, old WrappedDEK, wrapped []byte, kekVersion int) error
}

// RotateResult reports what Rotate did.
type RotateResult struct {
	Version   int // the new active KEK version
	Rewrapped int // how many DEKs were re-encrypted
}

// Rotate adds a new KEK and re-encrypts all DEKs with it. The data
// itself is not touched. Safe to rerun if it was interrupted.
func Rotate(ctx context.Context, store RotationStore, masterKey []byte) (RotateResult, error) {
	keys, err := LoadKeyring(ctx, store, masterKey)
	if err != nil {
		return RotateResult{}, err
	}

	kek, err := GenerateKEK(masterKey, keys.ActiveVersion()+1)
	if err != nil {
		return RotateResult{}, err
	}
	if err := store.AddKEK(ctx, kek); err != nil {
		return RotateResult{}, err
	}

	// Reload: the new KEK becomes active.
	if keys, err = LoadKeyring(ctx, store, masterKey); err != nil {
		return RotateResult{}, err
	}

	res := RotateResult{Version: keys.ActiveVersion()}
	for {
		deks, err := store.DEKsBelow(ctx, res.Version, rotateBatch)
		if err != nil {
			return res, err
		}
		if len(deks) == 0 {
			return res, nil
		}

		for _, d := range deks {
			sealed, err := keys.Rewrap(Sealed{WrappedDEK: d.Wrapped, KEKVersion: d.KEKVersion})
			if err != nil {
				return res, fmt.Errorf("rewrapping DEK of secret %s: %w", d.SecretID, err)
			}
			if err := store.ReplaceDEK(ctx, d, sealed.WrappedDEK, sealed.KEKVersion); err != nil {
				return res, err
			}
			res.Rewrapped++
		}
	}
}
