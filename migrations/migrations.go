// Package migrations embeds the SQL migrations into the server binary.
package migrations

import "embed"

// FS holds the *.sql migration files.
//
//go:embed *.sql
var FS embed.FS
