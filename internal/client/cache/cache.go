// Package cache is the client's local copy of the user's secrets in
// SQLite. Data is encrypted with the session's cache key; metadata is not.
package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/aead"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go, no CGO
)

// Errors returned by Get.
var (
	ErrNotFound  = errors.New("secret not found")
	ErrAmbiguous = errors.New("several secrets have this name: use the ID")
)

const schema = `
CREATE TABLE IF NOT EXISTS secrets (
    id         TEXT PRIMARY KEY,
    type       INTEGER NOT NULL,
    name       TEXT NOT NULL,
    metadata   TEXT NOT NULL,
    data       BLOB NOT NULL,
    version    INTEGER NOT NULL,
    revision   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_state (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL
);`

// Cache is an open local cache.
type Cache struct {
	db  *sql.DB
	key []byte
}

// Open opens (creating if needed) the cache file at path.
func Open(path string, key []byte) (*Cache, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening cache: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating cache schema: %w", err)
	}
	return &Cache{db: db, key: key}, nil
}

// Close closes the cache.
func (c *Cache) Close() error {
	return c.db.Close()
}

// Revision returns the last synced server revision (0 if never synced).
func (c *Cache) Revision(ctx context.Context) (int64, error) {
	var rev int64
	err := c.db.QueryRowContext(ctx, `SELECT revision FROM sync_state WHERE id = 1`).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return rev, err
}

// SetRevision saves the last synced server revision.
func (c *Cache) SetRevision(ctx context.Context, rev int64) error {
	_, err := c.db.ExecContext(ctx, `
		INSERT INTO sync_state (id, revision) VALUES (1, ?)
		ON CONFLICT (id) DO UPDATE SET revision = excluded.revision`, rev)
	return err
}

// Put inserts or replaces a secret.
func (c *Cache) Put(ctx context.Context, s secret.Secret) error {
	metadata, err := json.Marshal(s.Metadata)
	if err != nil {
		return err
	}
	data, err := aead.Seal(c.key, s.Data, []byte(s.ID))
	if err != nil {
		return err
	}

	_, err = c.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO secrets (id, type, name, metadata, data, version, revision, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Type, s.Name, string(metadata), data, s.Version, s.Revision, s.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("saving secret: %w", err)
	}
	return nil
}

// Delete removes a secret; a missing one is not an error.
func (c *Cache) Delete(ctx context.Context, id string) error {
	_, err := c.db.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
	return err
}

// List returns all secrets without data, sorted by name.
func (c *Cache) List(ctx context.Context) ([]secret.Info, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT id, type, name, metadata, version, revision, updated_at
		FROM secrets ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read errors come from rows.Err()

	var list []secret.Info
	for rows.Next() {
		var (
			info      secret.Info
			metadata  string
			updatedAt int64
		)
		err := rows.Scan(&info.ID, &info.Type, &info.Name, &metadata, &info.Version, &info.Revision, &updatedAt)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(metadata), &info.Metadata); err != nil {
			return nil, err
		}
		info.UpdatedAt = time.Unix(updatedAt, 0)
		list = append(list, info)
	}
	return list, rows.Err()
}

// Get returns a secret by ID or by exact name, with decrypted data.
func (c *Cache) Get(ctx context.Context, idOrName string) (secret.Secret, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT id, type, name, metadata, data, version, revision, updated_at
		FROM secrets WHERE id = ? OR name = ?`, idOrName, idOrName)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("reading secret: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read errors come from rows.Err()

	var found []secret.Secret
	for rows.Next() {
		var (
			s         secret.Secret
			metadata  string
			sealed    []byte
			updatedAt int64
		)
		err := rows.Scan(&s.ID, &s.Type, &s.Name, &metadata, &sealed, &s.Version, &s.Revision, &updatedAt)
		if err != nil {
			return secret.Secret{}, err
		}
		if err := json.Unmarshal([]byte(metadata), &s.Metadata); err != nil {
			return secret.Secret{}, err
		}
		s.UpdatedAt = time.Unix(updatedAt, 0)

		s.Data, err = aead.Open(c.key, sealed, []byte(s.ID))
		if err != nil {
			return secret.Secret{}, fmt.Errorf("decrypting cached secret: %w", err)
		}

		// An exact ID match wins over name matches.
		if s.ID == idOrName {
			return s, nil
		}
		found = append(found, s)
	}
	if err := rows.Err(); err != nil {
		return secret.Secret{}, err
	}

	switch len(found) {
	case 0:
		return secret.Secret{}, ErrNotFound
	case 1:
		return found[0], nil
	default:
		return secret.Secret{}, ErrAmbiguous
	}
}
