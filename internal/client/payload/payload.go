// Package payload defines what is stored inside a secret's data for each
// type, and how it is shown. The server never sees these formats.
package payload

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dmitrymack/go-password-manager/internal/client/secret"
)

// Login is the data of a login secret.
type Login struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Card is the data of a card secret.
type Card struct {
	Number string `json:"number"`
	Holder string `json:"holder"`
	Expiry string `json:"expiry"` // MM/YY
	CVV    string `json:"cvv"`
}

// Card validation errors.
var (
	ErrCardNumber = errors.New("card number must be 12-19 digits and pass the Luhn check")
	ErrCardExpiry = errors.New("card expiry must be MM/YY")
	ErrCardCVV    = errors.New("CVV must be 3 or 4 digits")
)

var (
	expiryPattern = regexp.MustCompile(`^(0[1-9]|1[0-2])/\d{2}$`)
	cvvPattern    = regexp.MustCompile(`^\d{3,4}$`)
)

// Validate checks the card fields. Spaces in the number are allowed.
func (c Card) Validate() error {
	if !luhnValid(strings.ReplaceAll(c.Number, " ", "")) {
		return ErrCardNumber
	}
	if !expiryPattern.MatchString(c.Expiry) {
		return ErrCardExpiry
	}
	if !cvvPattern.MatchString(c.CVV) {
		return ErrCardCVV
	}
	return nil
}

// luhnValid checks a card number with the Luhn algorithm: from the right,
// double every second digit (minus 9 if over 9); the sum must end in 0.
func luhnValid(number string) bool {
	if len(number) < 12 || len(number) > 19 {
		return false
	}

	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		d, err := strconv.Atoi(string(number[i]))
		if err != nil {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// Encode turns v into secret data.
func Encode(v any) ([]byte, error) {
	return json.Marshal(v)
}

// DecodeLogin parses login secret data.
func DecodeLogin(data []byte) (Login, error) {
	var l Login
	if err := json.Unmarshal(data, &l); err != nil {
		return Login{}, fmt.Errorf("corrupted login data: %w", err)
	}
	return l, nil
}

// DecodeCard parses card secret data.
func DecodeCard(data []byte) (Card, error) {
	var c Card
	if err := json.Unmarshal(data, &c); err != nil {
		return Card{}, fmt.Errorf("corrupted card data: %w", err)
	}
	return c, nil
}

// Field is one labelled value to show the user.
type Field struct {
	Label string
	Value string
}

// Fields returns the secret's data as labelled values for display.
func Fields(t secret.Type, data []byte) ([]Field, error) {
	switch t {
	case secret.TypeLogin:
		l, err := DecodeLogin(data)
		if err != nil {
			return nil, err
		}
		return []Field{{"Login", l.Login}, {"Password", l.Password}}, nil

	case secret.TypeCard:
		c, err := DecodeCard(data)
		if err != nil {
			return nil, err
		}
		return []Field{{"Number", c.Number}, {"Holder", c.Holder}, {"Expiry", c.Expiry}, {"CVV", c.CVV}}, nil

	case secret.TypeText:
		if !utf8.Valid(data) {
			return nil, errors.New("text is not valid UTF-8: use --out to save it")
		}
		return []Field{{"Text", string(data)}}, nil

	default:
		return []Field{{"Data", fmt.Sprintf("<%d bytes of binary data, use --out FILE to save>", len(data))}}, nil
	}
}
