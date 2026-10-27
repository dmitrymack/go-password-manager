// Package storage keeps server data in PostgreSQL.
package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/dmitrymack/go-password-manager/migrations"
	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Errors returned by the storage.
var (
	ErrNotFound   = errors.New("not found")
	ErrLoginTaken = errors.New("login already taken")
)

// User is a registered user.
type User struct {
	ID           string
	Login        string
	PasswordHash string
}

// Postgres is the PostgreSQL-backed storage.
type Postgres struct {
	pool *pgxpool.Pool
}

// New connects to dsn and applies pending migrations.
func New(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	if err := migrateUp(pool); err != nil {
		pool.Close()
		return nil, err
	}

	return &Postgres{pool: pool}, nil
}

// Close closes the connection pool.
func (p *Postgres) Close() {
	p.pool.Close()
}

// migrateUp applies the migrations embedded in the binary.
func migrateUp(pool *pgxpool.Pool) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("reading migrations: %w", err)
	}

	// golang-migrate works with database/sql, so wrap the pool in a *sql.DB.
	db := stdlib.OpenDBFromPool(pool)
	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{})
	if err != nil {
		return fmt.Errorf("creating migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer m.Close() //nolint:errcheck // migrations are already applied or failed

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

// CreateUser stores a new user and returns its ID.
// It returns ErrLoginTaken if the login is already registered.
func (p *Postgres) CreateUser(ctx context.Context, login, passwordHash string) (string, error) {
	var id string
	err := p.pool.QueryRow(ctx,
		`INSERT INTO users (login, password_hash) VALUES ($1, $2) RETURNING id::text`,
		login, passwordHash,
	).Scan(&id)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return "", ErrLoginTaken
	}
	if err != nil {
		return "", fmt.Errorf("inserting user: %w", err)
	}
	return id, nil
}

// UserByLogin returns the user with the given login, or ErrNotFound.
func (p *Postgres) UserByLogin(ctx context.Context, login string) (User, error) {
	u := User{Login: login}
	err := p.pool.QueryRow(ctx,
		`SELECT id::text, password_hash FROM users WHERE login = $1`,
		login,
	).Scan(&u.ID, &u.PasswordHash)

	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("selecting user: %w", err)
	}
	return u, nil
}
