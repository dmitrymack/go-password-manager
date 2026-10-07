// Package auth registers and authenticates users and issues their tokens.
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"golang.org/x/crypto/bcrypt"
)

// Errors returned by Service besides the validation ones.
var (
	ErrLoginTaken         = errors.New("login already taken")
	ErrInvalidCredentials = errors.New("invalid login or password")
)

// UserStore is the part of the storage the service needs.
type UserStore interface {
	CreateUser(ctx context.Context, login, passwordHash string) (string, error)
	UserByLogin(ctx context.Context, login string) (storage.User, error)
}

// Service implements registration and login.
type Service struct {
	users  UserStore
	tokens *Tokens
}

// NewService creates a Service.
func NewService(users UserStore, tokens *Tokens) *Service {
	return &Service{users: users, tokens: tokens}
}

// Register creates a user and returns a token for them.
func (s *Service) Register(ctx context.Context, login, password string) (string, error) {
	if err := validateLogin(login); err != nil {
		return "", err
	}
	if err := validatePassword(password); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}

	id, err := s.users.CreateUser(ctx, login, string(hash))
	if errors.Is(err, storage.ErrLoginTaken) {
		return "", ErrLoginTaken
	}
	if err != nil {
		return "", err
	}

	return s.tokens.Issue(id)
}

// Login checks the credentials and returns a token. An unknown login and a
// wrong password give the same error, so logins can't be probed.
func (s *Service) Login(ctx context.Context, login, password string) (string, error) {
	user, err := s.users.UserByLogin(ctx, login)
	if errors.Is(err, storage.ErrNotFound) {
		return "", ErrInvalidCredentials
	}
	if err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	return s.tokens.Issue(user.ID)
}
