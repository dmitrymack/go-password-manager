package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordReaderFromPipe(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer r.Close()

	_, err = w.WriteString("first\r\nsecond") // last line without newline
	require.NoError(t, err)
	require.NoError(t, w.Close())

	var prompt bytes.Buffer
	read := newPasswordReader(r, &prompt)

	p, err := read("A: ")
	require.NoError(t, err)
	assert.Equal(t, "first", p)

	p, err = read("B: ")
	require.NoError(t, err)
	assert.Equal(t, "second", p)

	_, err = read("C: ")
	assert.Error(t, err, "input is exhausted")

	assert.Equal(t, "A: B: C: ", prompt.String())
}
