package encryption

import (
	"context"
	"fmt"
)

// KEKStore persists KEKs.
type KEKStore interface {
	KEKs(ctx context.Context) ([]StoredKEK, error)
	AddKEK(ctx context.Context, k StoredKEK) error
}

// LoadKeyring builds the keyring from stored KEKs, creating KEK v1 on first start.
func LoadKeyring(ctx context.Context, store KEKStore, masterKey []byte) (*Keyring, error) {
	keks, err := store.KEKs(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading KEKs: %w", err)
	}

	if len(keks) == 0 {
		kek, err := GenerateKEK(masterKey, 1)
		if err != nil {
			return nil, err
		}
		if err := store.AddKEK(ctx, kek); err != nil {
			return nil, err
		}
		keks = []StoredKEK{kek}
	}

	return NewKeyring(masterKey, keks)
}
