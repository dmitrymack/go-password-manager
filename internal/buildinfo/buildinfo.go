// Package buildinfo holds build metadata, set by the Makefile via
// go build -ldflags "-X .../buildinfo.Version=...".
package buildinfo

import "fmt"

// Build metadata; "N/A" for a plain go build.
var (
	Version = "N/A" // Version is the release version (git describe).
	Date    = "N/A" // Date is the build date in UTC, RFC 3339.
	Commit  = "N/A" // Commit is the short git commit hash.
)

// String returns the build metadata as a multi-line human-readable text.
func String() string {
	return fmt.Sprintf("Version: %s\nBuild date: %s\nCommit: %s", Version, Date, Commit)
}
