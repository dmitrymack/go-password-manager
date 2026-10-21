// Package secret defines the client's view of a secret.
package secret

import (
	"fmt"
	"time"
)

// Type is the kind of a secret; values match the proto enum.
type Type int

// Secret types.
const (
	TypeLogin  Type = 1
	TypeCard   Type = 2
	TypeText   Type = 3
	TypeBinary Type = 4
)

var typeNames = map[Type]string{
	TypeLogin:  "login",
	TypeCard:   "card",
	TypeText:   "text",
	TypeBinary: "binary",
}

// String returns the type's name as used on the command line.
func (t Type) String() string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("type(%d)", int(t))
}

// ParseType is the reverse of String.
func ParseType(name string) (Type, error) {
	for t, n := range typeNames {
		if n == name {
			return t, nil
		}
	}
	return 0, fmt.Errorf("unknown secret type %q: want login, card, text or binary", name)
}

// Info is a secret without its data.
type Info struct {
	ID        string
	Type      Type
	Name      string
	Metadata  map[string]string
	Version   int64
	Revision  int64
	Deleted   bool
	UpdatedAt time.Time
}

// Secret is a secret with its decrypted data.
type Secret struct {
	Info
	Data []byte
}
