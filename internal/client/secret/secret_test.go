package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeNames(t *testing.T) {
	for _, typ := range []Type{TypeLogin, TypeCard, TypeText, TypeBinary} {
		parsed, err := ParseType(typ.String())
		require.NoError(t, err)
		assert.Equal(t, typ, parsed)
	}

	assert.Equal(t, "type(9)", Type(9).String())
	_, err := ParseType("photo")
	assert.Error(t, err)
}
