package storage

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDB connects to TEST_DATABASE_DSN and empties the tables.
// Without the variable the test is skipped, so `go test ./...` works
// without a database.
func newTestDB(t *testing.T) *Postgres {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}

	db, err := New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(db.Close)

	_, err = db.pool.Exec(context.Background(), "TRUNCATE users, keks CASCADE")
	require.NoError(t, err)

	return db
}

func TestUsers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	id, err := db.CreateUser(ctx, "alice", "hash")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	_, err = db.CreateUser(ctx, "alice", "other")
	assert.ErrorIs(t, err, ErrLoginTaken)

	u, err := db.UserByLogin(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, User{ID: id, Login: "alice", PasswordHash: "hash"}, u)

	_, err = db.UserByLogin(ctx, "bob")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestNewBadDSN(t *testing.T) {
	_, err := New(context.Background(), "postgres://nobody@127.0.0.1:1/none?connect_timeout=1")
	assert.Error(t, err)
}
