package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/server/encryption"
	"github.com/jackc/pgx/v5"
)

// ErrVersionConflict means the secret was changed since the client read it.
var ErrVersionConflict = errors.New("version conflict")

// Secret is a stored secret. Sealed is empty when only metadata was read.
type Secret struct {
	ID        string
	UserID    string
	Type      int
	Name      string
	Metadata  map[string]string
	Sealed    encryption.Sealed
	Version   int64
	Revision  int64
	Deleted   bool
	UpdatedAt time.Time
}

// KEKs returns all stored KEKs.
func (p *Postgres) KEKs(ctx context.Context) ([]encryption.StoredKEK, error) {
	rows, err := p.pool.Query(ctx, `SELECT version, wrapped_key FROM keks ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("selecting KEKs: %w", err)
	}
	defer rows.Close()

	var keks []encryption.StoredKEK
	for rows.Next() {
		var k encryption.StoredKEK
		if err := rows.Scan(&k.Version, &k.Wrapped); err != nil {
			return nil, fmt.Errorf("scanning KEK: %w", err)
		}
		keks = append(keks, k)
	}
	return keks, rows.Err()
}

// AddKEK stores a new KEK.
func (p *Postgres) AddKEK(ctx context.Context, k encryption.StoredKEK) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO keks (version, wrapped_key) VALUES ($1, $2)`, k.Version, k.Wrapped)
	if err != nil {
		return fmt.Errorf("inserting KEK: %w", err)
	}
	return nil
}

// CreateSecret stores a new secret; version, revision and time come from the DB.
func (p *Postgres) CreateSecret(ctx context.Context, s Secret) (Secret, error) {
	if s.Metadata == nil {
		s.Metadata = map[string]string{}
	}

	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		rev, err := nextRevision(ctx, tx, s.UserID)
		if err != nil {
			return err
		}

		return tx.QueryRow(ctx, `
			INSERT INTO secrets (id, user_id, type, name, metadata, ciphertext, wrapped_dek, kek_version, revision)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING version, revision, updated_at`,
			s.ID, s.UserID, s.Type, s.Name, s.Metadata,
			s.Sealed.Ciphertext, s.Sealed.WrappedDEK, s.Sealed.KEKVersion, rev,
		).Scan(&s.Version, &s.Revision, &s.UpdatedAt)
	})
	if err != nil {
		return Secret{}, fmt.Errorf("creating secret: %w", err)
	}
	return s, nil
}

// UpdateSecret replaces a secret if it's still at expectedVersion, else ErrVersionConflict.
func (p *Postgres) UpdateSecret(ctx context.Context, s Secret, expectedVersion int64) (Secret, error) {
	if s.Metadata == nil {
		s.Metadata = map[string]string{}
	}

	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		rev, err := nextRevision(ctx, tx, s.UserID)
		if err != nil {
			return err
		}

		err = tx.QueryRow(ctx, `
			UPDATE secrets
			SET name = $1, metadata = $2, ciphertext = $3, wrapped_dek = $4, kek_version = $5,
			    version = version + 1, revision = $6, updated_at = now()
			WHERE id = $7 AND user_id = $8 AND NOT deleted AND version = $9
			RETURNING type, version, revision, updated_at`,
			s.Name, s.Metadata, s.Sealed.Ciphertext, s.Sealed.WrappedDEK, s.Sealed.KEKVersion,
			rev, s.ID, s.UserID, expectedVersion,
		).Scan(&s.Type, &s.Version, &s.Revision, &s.UpdatedAt)

		if errors.Is(err, pgx.ErrNoRows) {
			return notFoundOrConflict(ctx, tx, s.UserID, s.ID)
		}
		return err
	})
	if err != nil {
		return Secret{}, err
	}
	return s, nil
}

// DeleteSecret wipes the data but keeps the row, so Sync reports the deletion.
func (p *Postgres) DeleteSecret(ctx context.Context, userID, id string) (Secret, error) {
	s := Secret{ID: id, UserID: userID, Deleted: true}

	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		rev, err := nextRevision(ctx, tx, userID)
		if err != nil {
			return err
		}

		err = tx.QueryRow(ctx, `
			UPDATE secrets
			SET deleted = true, ciphertext = NULL, wrapped_dek = NULL, kek_version = NULL,
			    version = version + 1, revision = $1, updated_at = now()
			WHERE id = $2 AND user_id = $3 AND NOT deleted
			RETURNING type, name, metadata, version, revision, updated_at`,
			rev, id, userID,
		).Scan(&s.Type, &s.Name, &s.Metadata, &s.Version, &s.Revision, &s.UpdatedAt)

		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return Secret{}, err
	}
	return s, nil
}

// GetSecret returns a secret with its encrypted data, or ErrNotFound.
func (p *Postgres) GetSecret(ctx context.Context, userID, id string) (Secret, error) {
	s := Secret{ID: id, UserID: userID}

	err := p.pool.QueryRow(ctx, `
		SELECT type, name, metadata, ciphertext, wrapped_dek, kek_version, version, revision, updated_at
		FROM secrets
		WHERE id = $1 AND user_id = $2 AND NOT deleted`,
		id, userID,
	).Scan(&s.Type, &s.Name, &s.Metadata, &s.Sealed.Ciphertext, &s.Sealed.WrappedDEK, &s.Sealed.KEKVersion,
		&s.Version, &s.Revision, &s.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("selecting secret: %w", err)
	}
	return s, nil
}

// SecretsChangedSince returns secrets (no data) changed after since, and the current revision.
func (p *Postgres) SecretsChangedSince(ctx context.Context, userID string, since int64) ([]Secret, int64, error) {
	// Changes committed after this read get a higher revision: next sync.
	var current int64
	err := p.pool.QueryRow(ctx, `SELECT revision FROM users WHERE id = $1`, userID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("selecting revision: %w", err)
	}

	rows, err := p.pool.Query(ctx, `
		SELECT id::text, type, name, metadata, version, revision, deleted, updated_at
		FROM secrets
		WHERE user_id = $1 AND revision > $2 AND revision <= $3
		ORDER BY revision`,
		userID, since, current)
	if err != nil {
		return nil, 0, fmt.Errorf("selecting secrets: %w", err)
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		s := Secret{UserID: userID}
		err := rows.Scan(&s.ID, &s.Type, &s.Name, &s.Metadata, &s.Version, &s.Revision, &s.Deleted, &s.UpdatedAt)
		if err != nil {
			return nil, 0, fmt.Errorf("scanning secret: %w", err)
		}
		secrets = append(secrets, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return secrets, current, nil
}

// nextRevision bumps the user's revision; the row lock orders concurrent writes.
func nextRevision(ctx context.Context, tx pgx.Tx, userID string) (int64, error) {
	var rev int64
	err := tx.QueryRow(ctx,
		`UPDATE users SET revision = revision + 1 WHERE id = $1 RETURNING revision`, userID,
	).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("bumping revision: %w", err)
	}
	return rev, nil
}

// notFoundOrConflict tells why an update matched no rows.
func notFoundOrConflict(ctx context.Context, tx pgx.Tx, userID, id string) error {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM secrets WHERE id = $1 AND user_id = $2 AND NOT deleted)`, id, userID,
	).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrVersionConflict
	}
	return ErrNotFound
}
