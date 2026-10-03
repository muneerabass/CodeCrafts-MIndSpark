// Package scan turns lockfiles into enriched, policy-evaluated packages using
// safedep/vet as a library.
package scan

import (
	"fmt"

	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

// Lockfile is a dependency manifest written to local disk for parsing.
type Lockfile struct {
	// Path on local disk.
	Path string
	// RepoPath is the path inside the repository, used for display.
	RepoPath string
	// As overrides format detection (vet's --lockfile-as); empty means detect by name.
	As string
}

// Parse reads lockfiles with vet's parsers and returns their manifests.
func Parse(lockfiles []Lockfile) ([]*models.PackageManifest, error) {
	var out []*models.PackageManifest
	for _, lf := range lockfiles {
		r, err := readers.NewLockfileReader(readers.LockfileReaderConfig{
			Lockfiles:  []string{lf.Path},
			LockfileAs: lf.As,
		})
		if err != nil {
			return nil, fmt.Errorf("lockfile reader for %s: %w", lf.RepoPath, err)
		}
		err = r.EnumManifests(func(m *models.PackageManifest, _ readers.PackageReader) error {
			m.SetDisplayPath(lf.RepoPath)
			out = append(out, m)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", lf.RepoPath, err)
		}
	}
	return out, nil
}
