package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUsers is an in-memory UserStore.
type fakeUsers struct {
	byLogin map[string]storage.User
	err     error // if set, every call fails with it
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byLogin: map[string]storage.User{}}
}

func (f *fakeUsers) CreateUser(_ context.Context, login, hash string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if _, ok := f.byLogin[login]; ok {
		return "", storage.ErrLoginTaken
	}
	id := "id-" + login
	f.byLogin[login] = storage.User{ID: id, Login: login, PasswordHash: hash}
	return id, nil
}

func (f *fakeUsers) UserByLogin(_ context.Context, login string) (storage.User, error) {
	if f.err != nil {
		return storage.User{}, f.err
	}
	u, ok := f.byLogin[login]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return u, nil
}

func newTestService() (*Service, *fakeUsers, *Tokens) {
	users := newFakeUsers()
	tokens := NewTokens("test-secret", time.Hour)
	return NewService(users, tokens), users, tokens
}

func TestRegisterAndLogin(t *testing.T) {
	svc, users, tokens := newTestService()
	ctx := context.Background()

	token, err := svc.Register(ctx, "alice", "passw0rd")
	require.NoError(t, err)
	userID, err := tokens.Verify(token)
	require.NoError(t, err)
	assert.Equal(t, "id-alice", userID)

	assert.NotEqual(t, "passw0rd", users.byLogin["alice"].PasswordHash, "password must be hashed")

	_, err = svc.Register(ctx, "alice", "passw0rd")
	assert.ErrorIs(t, err, ErrLoginTaken)

	token, err = svc.Login(ctx, "alice", "passw0rd")
	require.NoError(t, err)
	userID, err = tokens.Verify(token)
	require.NoError(t, err)
	assert.Equal(t, "id-alice", userID)

	_, err = svc.Login(ctx, "alice", "wrong-passw0rd")
	assert.ErrorIs(t, err, ErrInvalidCredentials)

	_, err = svc.Login(ctx, "bob", "passw0rd")
	assert.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestRegisterValidation(t *testing.T) {
	svc, _, _ := newTestService()

	tests := []struct {
		login, password string
		want            error
	}{
		{"al", "passw0rd", ErrBadLogin},
		{"al ice", "passw0rd", ErrBadLogin},
		{"alice", "pa55", ErrPasswordLength},
		{"alice", strings.Repeat("a1", 37), ErrPasswordLength},
		{"alice", "password", ErrPasswordTooWeak},
		{"alice", "12345678", ErrPasswordTooWeak},
	}

	for _, tt := range tests {
		t.Run(tt.login+"/"+tt.password, func(t *testing.T) {
			_, err := svc.Register(context.Background(), tt.login, tt.password)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestStorageErrors(t *testing.T) {
	svc, users, _ := newTestService()
	users.err = errors.New("db is down")

	_, err := svc.Register(context.Background(), "alice", "passw0rd")
	assert.ErrorIs(t, err, users.err)

	_, err = svc.Login(context.Background(), "alice", "passw0rd")
	assert.ErrorIs(t, err, users.err)
}

func TestVerifyRejects(t *testing.T) {
	tokens := NewTokens("secret", time.Hour)

	expired, err := NewTokens("secret", -time.Minute).Issue("u1")
	require.NoError(t, err)

	forged, err := NewTokens("other-secret", time.Hour).Issue("u1")
	require.NoError(t, err)

	noExpiry, err := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.RegisteredClaims{Subject: "u1"}).SignedString([]byte("secret"))
	require.NoError(t, err)

	for name, token := range map[string]string{
		"garbage":   "not-a-jwt",
		"expired":   expired,
		"forged":    forged,
		"no expiry": noExpiry,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tokens.Verify(token)
			assert.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}
