// Package secrets validates, encrypts and stores users' secrets.
package secrets

import (
	"context"
	"errors"
	"unicode/utf8"

	"github.com/dmitrymack/go-password-manager/internal/server/encryption"
	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"github.com/google/uuid"
)

// Limits on a single secret.
const (
	MaxDataSize        = 10 << 20 // 10 MB
	maxNameLen         = 255
	maxMetadataEntries = 50
)

// Secret types; the numbers match the SecretType enum in the proto.
const (
	TypeLogin  = 1
	TypeCard   = 2
	TypeText   = 3
	TypeBinary = 4
)

// Errors returned by Service; their text is shown to the user.
var (
	ErrBadType         = errors.New("unknown secret type")
	ErrBadName         = errors.New("name must be 1-255 characters")
	ErrDataTooLarge    = errors.New("data is larger than 10 MB")
	ErrTooMuchMetadata = errors.New("at most 50 metadata entries")
	ErrNotFound        = errors.New("secret not found")
	ErrVersionConflict = errors.New("secret was changed by another client: sync and try again")
)

// Store is the part of the storage the service needs.
type Store interface {
	CreateSecret(ctx context.Context, s storage.Secret) (storage.Secret, error)
	UpdateSecret(ctx context.Context, s storage.Secret, expectedVersion int64) (storage.Secret, error)
	DeleteSecret(ctx context.Context, userID, id string) (storage.Secret, error)
	GetSecret(ctx context.Context, userID, id string) (storage.Secret, error)
	SecretsChangedSince(ctx context.Context, userID string, since int64) ([]storage.Secret, int64, error)
}

// Input is a secret's content as sent by the client.
type Input struct {
	Type     int
	Name     string
	Metadata map[string]string
	Data     []byte
}

// Service implements operations on secrets.
type Service struct {
	store Store
	keys  *encryption.Keyring
}

// NewService creates a Service.
func NewService(store Store, keys *encryption.Keyring) *Service {
	return &Service{store: store, keys: keys}
}

// Create encrypts and stores a new secret.
func (s *Service) Create(ctx context.Context, userID string, in Input) (storage.Secret, error) {
	if in.Type < TypeLogin || in.Type > TypeBinary {
		return storage.Secret{}, ErrBadType
	}
	if err := validate(in); err != nil {
		return storage.Secret{}, err
	}

	id := uuid.NewString()
	sealed, err := s.keys.Encrypt(in.Data, aad(userID, id))
	if err != nil {
		return storage.Secret{}, err
	}

	return s.store.CreateSecret(ctx, storage.Secret{
		ID:       id,
		UserID:   userID,
		Type:     in.Type,
		Name:     in.Name,
		Metadata: in.Metadata,
		Sealed:   sealed,
	})
}

// Update replaces a secret's content if it's still at version. in.Type is ignored.
func (s *Service) Update(ctx context.Context, userID, id string, version int64, in Input) (storage.Secret, error) {
	if uuid.Validate(id) != nil {
		return storage.Secret{}, ErrNotFound
	}
	if err := validate(in); err != nil {
		return storage.Secret{}, err
	}

	sealed, err := s.keys.Encrypt(in.Data, aad(userID, id))
	if err != nil {
		return storage.Secret{}, err
	}

	updated, err := s.store.UpdateSecret(ctx, storage.Secret{
		ID:       id,
		UserID:   userID,
		Name:     in.Name,
		Metadata: in.Metadata,
		Sealed:   sealed,
	}, version)
	return updated, storeError(err)
}

// Delete deletes a secret.
func (s *Service) Delete(ctx context.Context, userID, id string) (storage.Secret, error) {
	if uuid.Validate(id) != nil {
		return storage.Secret{}, ErrNotFound
	}
	deleted, err := s.store.DeleteSecret(ctx, userID, id)
	return deleted, storeError(err)
}

// Get returns a secret and its decrypted data.
func (s *Service) Get(ctx context.Context, userID, id string) (storage.Secret, []byte, error) {
	if uuid.Validate(id) != nil {
		return storage.Secret{}, nil, ErrNotFound
	}

	secret, err := s.store.GetSecret(ctx, userID, id)
	if err != nil {
		return storage.Secret{}, nil, storeError(err)
	}

	data, err := s.keys.Decrypt(secret.Sealed, aad(userID, id))
	if err != nil {
		return storage.Secret{}, nil, err
	}
	return secret, data, nil
}

// Sync returns secrets changed after since and the user's current revision.
func (s *Service) Sync(ctx context.Context, userID string, since int64) ([]storage.Secret, int64, error) {
	return s.store.SecretsChangedSince(ctx, userID, since)
}

// validate checks the fields common to Create and Update.
func validate(in Input) error {
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > maxNameLen {
		return ErrBadName
	}
	if len(in.Metadata) > maxMetadataEntries {
		return ErrTooMuchMetadata
	}
	if len(in.Data) > MaxDataSize {
		return ErrDataTooLarge
	}
	return nil
}

// aad binds encrypted data to its owner and secret.
func aad(userID, secretID string) []byte {
	return []byte(userID + "/" + secretID)
}

// storeError translates storage errors into the service's own.
func storeError(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, storage.ErrVersionConflict):
		return ErrVersionConflict
	default:
		return err
	}
}
