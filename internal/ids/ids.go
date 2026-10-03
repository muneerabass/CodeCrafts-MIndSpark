// Package ids generates sortable unique identifiers.
package ids

import "github.com/oklog/ulid/v2"

// New returns a new ULID string.
func New() string { return ulid.Make().String() }
