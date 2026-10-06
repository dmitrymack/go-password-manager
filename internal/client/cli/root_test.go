package cli

import (
	"bytes"
	"testing"

	"github.com/dmitrymack/go-password-manager/internal/buildinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// execute runs the root command with args and returns its stdout.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func TestVersion(t *testing.T) {
	out, err := execute(t, "version")
	require.NoError(t, err)
	assert.Equal(t, buildinfo.String()+"\n", out)
}

func TestVersionRejectsArgs(t *testing.T) {
	_, err := execute(t, "version", "extra")
	assert.Error(t, err)
}
