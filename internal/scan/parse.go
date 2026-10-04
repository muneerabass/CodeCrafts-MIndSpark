// Package scan turns lockfiles into enriched, policy-evaluated packages using
// safedep/vet as a library.
package scan

import (
	"fmt"
	"os"
	"regexp"

	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
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
		if lf.As == parser.LockfileAsBomCycloneDx {
			if err := downgradeCycloneDX(lf.Path); err != nil {
				return nil, fmt.Errorf("read %s: %w", lf.RepoPath, err)
			}
		}
		r, err := readers.NewLockfileReader(readers.LockfileReaderConfig{
			Lockfiles:  []string{lf.Path},
			LockfileAs: lf.As,
		})
		if err != nil {
			return nil, fmt.Errorf("lockfile reader for %s: %w", lf.RepoPath, err)
		}
		err = r.EnumManifests(func(m *models.PackageManifest, _ readers.PackageReader) error {
			m.SetDisplayPath(lf.RepoPath)
			// Local sources ignore DisplayPath and show Namespace/Path (the
			// temp dir); point them at the repo path instead.
			if m.Source.Type == models.ManifestSourceLocal {
				m.Source.Namespace, m.Source.Path = "", lf.RepoPath
			}
			out = append(out, m)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", lf.RepoPath, err)
		}
	}
	return out, nil
}

var newerCycloneDX = regexp.MustCompile(`("specVersion"\s*:\s*")1\.(7|8|9)(")`)

// downgradeCycloneDX relabels CycloneDX 1.7+ (syft's default) as 1.6, the
// newest version vet's decoder accepts; the component list is unchanged.
// ponytail: drop when vet moves to cyclonedx-go >= v0.12.
func downgradeCycloneDX(p string) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if loc := newerCycloneDX.FindIndex(b); loc != nil && loc[0] < 4096 {
		return os.WriteFile(p, newerCycloneDX.ReplaceAll(b, []byte("${1}1.6${3}")), 0o600)
	}
	return nil
}
