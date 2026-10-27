package payload

import (
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLuhn(t *testing.T) {
	for _, valid := range []string{"4111111111111111", "5555555555554444", "378282246310005"} {
		assert.True(t, luhnValid(valid), valid)
	}
	for _, invalid := range []string{"4111111111111112", "4111", "41111111111111111111", "4111x11111111111"} {
		assert.False(t, luhnValid(invalid), invalid)
	}
}

func TestCardValidate(t *testing.T) {
	ok := Card{Number: "4111 1111 1111 1111", Holder: "ALICE", Expiry: "12/29", CVV: "123"}
	assert.NoError(t, ok.Validate())

	tests := []struct {
		name string
		edit func(c *Card)
		want error
	}{
		{"bad number", func(c *Card) { c.Number = "4111111111111112" }, ErrCardNumber},
		{"month 13", func(c *Card) { c.Expiry = "13/29" }, ErrCardExpiry},
		{"no slash", func(c *Card) { c.Expiry = "1229" }, ErrCardExpiry},
		{"short CVV", func(c *Card) { c.CVV = "12" }, ErrCardCVV},
		{"letters in CVV", func(c *Card) { c.CVV = "12a" }, ErrCardCVV},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ok
			tt.edit(&c)
			assert.ErrorIs(t, c.Validate(), tt.want)
		})
	}
}

func TestEncodeDecode(t *testing.T) {
	data, err := Encode(Login{Login: "alice", Password: "p"})
	require.NoError(t, err)
	l, err := DecodeLogin(data)
	require.NoError(t, err)
	assert.Equal(t, Login{Login: "alice", Password: "p"}, l)

	data, err = Encode(Card{Number: "1", Holder: "A", Expiry: "01/30", CVV: "999"})
	require.NoError(t, err)
	c, err := DecodeCard(data)
	require.NoError(t, err)
	assert.Equal(t, "999", c.CVV)

	_, err = DecodeLogin([]byte("{"))
	assert.Error(t, err)
	_, err = DecodeCard([]byte("{"))
	assert.Error(t, err)
}

func TestFields(t *testing.T) {
	login, _ := Encode(Login{Login: "alice", Password: "p"})
	card, _ := Encode(Card{Number: "4111", Holder: "A", Expiry: "01/30", CVV: "999"})

	tests := []struct {
		typ  secret.Type
		data []byte
		want []Field
	}{
		{secret.TypeLogin, login, []Field{{"Login", "alice"}, {"Password", "p"}}},
		{secret.TypeCard, card, []Field{{"Number", "4111"}, {"Holder", "A"}, {"Expiry", "01/30"}, {"CVV", "999"}}},
		{secret.TypeText, []byte("hello"), []Field{{"Text", "hello"}}},
		{secret.TypeBinary, []byte{1, 2, 3}, []Field{{"Data", "<3 bytes of binary data, use --out FILE to save>"}}},
	}
	for _, tt := range tests {
		t.Run(tt.typ.String(), func(t *testing.T) {
			got, err := Fields(tt.typ, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	for _, typ := range []secret.Type{secret.TypeLogin, secret.TypeCard} {
		_, err := Fields(typ, []byte("not json"))
		assert.Error(t, err, typ.String())
	}
	_, err := Fields(secret.TypeText, []byte{0xff, 0xfe})
	assert.Error(t, err)
}
