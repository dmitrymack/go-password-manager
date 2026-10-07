package auth

import (
	"errors"
	"regexp"
	"unicode"
)

// Credential limits. Passwords are capped at 72 bytes: bcrypt ignores
// anything longer.
const (
	minPasswordLen = 8
	maxPasswordLen = 72
)

var loginPattern = regexp.MustCompile(`^[a-zA-Z0-9._@-]{3,64}$`)

// Validation errors; their text is shown to the user as is.
var (
	ErrBadLogin        = errors.New("login must be 3-64 characters: latin letters, digits, . _ @ -")
	ErrPasswordLength  = errors.New("password must be 8-72 bytes long")
	ErrPasswordTooWeak = errors.New("password must contain a letter and a digit")
)

// validateLogin checks the login format.
func validateLogin(login string) error {
	if !loginPattern.MatchString(login) {
		return ErrBadLogin
	}
	return nil
}

// validatePassword checks the password length and that it mixes letters
// and digits.
func validatePassword(password string) error {
	if len(password) < minPasswordLen || len(password) > maxPasswordLen {
		return ErrPasswordLength
	}

	var hasLetter, hasDigit bool
	for _, r := range password {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return ErrPasswordTooWeak
	}
	return nil
}
