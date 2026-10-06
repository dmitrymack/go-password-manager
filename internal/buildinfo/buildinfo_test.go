package buildinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestString(t *testing.T) {
	Version, Date, Commit = "v1.2.3", "2026-10-05T00:00:00Z", "abc1234"
	t.Cleanup(func() { Version, Date, Commit = "N/A", "N/A", "N/A" })

	assert.Equal(t, "Version: v1.2.3\nBuild date: 2026-10-05T00:00:00Z\nCommit: abc1234", String())
}
