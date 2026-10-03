package license

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/scan"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func pkg(eco, name string, lic ...string) *models.Package {
	p := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", eco)}
	p.Name, p.Version = name, "1.0.0"
	l := make([]insightapi.License, len(lic))
	for i, s := range lic {
		l[i] = insightapi.License(s)
	}
	p.Insights = &insightapi.PackageVersionInsight{Licenses: &l}
	return p
}

func run(t *testing.T, cfg Config, project, usage string, ctx map[*models.Package]scan.PackageContext, pkgs ...*models.Package) []scan.Finding {
	t.Helper()
	fs, err := New(cfg).Check(context.Background(), scan.CheckInput{
		Project: scan.Project{License: project, UsageModel: usage}, Packages: pkgs, Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Category != scan.CategoryLicense || f.Package == nil || f.Summary == "" || f.Details["usage_model"] == nil {
			t.Fatalf("malformed finding %+v", f)
		}
	}
	return fs
}

func summary(fs []scan.Finding) string {
	var s []string
	for _, f := range fs {
		b := ""
		if f.Blocking {
			b = "!"
		}
		s = append(s, f.Rule+":"+f.Severity+b)
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

const (
	bin  = scan.UsageDistributedBinary
	src  = scan.UsageDistributedSource
	saas = scan.UsageSaaS
	intl = scan.UsageInternal
)

func TestRules(t *testing.T) {
	for _, c := range []struct {
		project, usage, eco, lic string
		want                     string
	}{
		// license-unknown
		{"MIT", bin, "npm", "non-standard", "license-unknown:medium"}, // unclassified license text: review, not block
		{"MIT", bin, "npm", "", "license-unknown:high!"},
		{"MIT", src, "npm", "", "license-unknown:high!"},
		{"MIT", saas, "npm", "NOASSERTION", "license-unknown:medium"},
		{"MIT", intl, "npm", "non-standard", "license-unknown:medium"},
		{"MIT", bin, "npm", "MIT OR non-standard", ""},
		// license-network-copyleft
		{"MIT", bin, "npm", "AGPL-3.0-only", "license-network-copyleft:high!"},
		{"MIT", src, "npm", "SSPL-1.0", "license-network-copyleft:high!"},
		{"MIT", saas, "npm", "AGPL-3.0-or-later", "license-network-copyleft:high!"},
		{"MIT", intl, "npm", "AGPL-3.0-only", "license-network-copyleft:info"},
		{"AGPL-3.0-only", saas, "npm", "AGPL-3.0-only", "license-network-copyleft:info"},
		// license-copyleft-distributed
		{"MIT", bin, "npm", "GPL-3.0-only", "license-copyleft-distributed:high!"},
		{"MIT", src, "npm", "GPL-2.0", "license-copyleft-distributed:high!"},
		{"", bin, "npm", "GPL-3.0-only", "license-copyleft-distributed:high!"},
		{"GPL-3.0-only", bin, "npm", "GPL-3.0-or-later", "license-copyleft-distributed:info"},
		{"GPL-3.0-only", bin, "npm", "GPL-2.0-only", "license-copyleft-distributed:high!"},
		{"MIT", saas, "npm", "GPL-3.0-only", "license-copyleft-distributed:info"},
		{"MIT", intl, "npm", "GPL-3.0-only", "license-copyleft-distributed:info"},
		{"MIT", bin, "npm", "MIT OR GPL-3.0-only", ""},
		{"GPL-2.0-only", bin, "npm", "Apache-2.0 OR GPL-2.0-or-later", "license-copyleft-distributed:info"}, // picks the compatible choice
		// license-weak-copyleft
		{"MIT", bin, "npm", "LGPL-2.1-only", "license-weak-copyleft:medium"},
		{"MIT", bin, "Go", "LGPL-3.0-only", "license-weak-copyleft:high!"},
		{"MIT", bin, "Cargo", "GPL-2.0-only WITH Classpath-exception-2.0", "license-weak-copyleft:high!"},
		{"MIT", src, "npm", "LGPL-2.1-only", "license-weak-copyleft:low"},
		{"MIT", saas, "npm", "LGPL-2.1-only", ""},
		{"MIT", bin, "PyPI", "MPL-2.0", "license-weak-copyleft:low"},
		{"MIT", src, "Maven", "EPL-2.0", "license-weak-copyleft:low"},
		{"MIT", intl, "Maven", "CDDL-1.1", ""},
		// license-noncommercial
		{"MIT", bin, "npm", "BUSL-1.1", "license-noncommercial:high!"},
		{"MIT", saas, "npm", "Elastic-2.0", "license-noncommercial:high!"},
		{"MIT", src, "npm", "Apache-2.0 WITH Commons-Clause", "license-noncommercial:high!"},
		{"MIT", intl, "npm", "CC-BY-NC-4.0", "license-noncommercial:medium"},
		// license-incompatible (project leading, dep subordinate)
		{"GPL-2.0-only", bin, "npm", "Apache-2.0", "license-incompatible:high!"},
		{"GPL-3.0-only", bin, "npm", "Apache-2.0", ""},
		{"GPL-2.0-only", saas, "npm", "Apache-2.0", ""},
		{"MIT", bin, "npm", "MS-PL", "license-incompatible:low"},
		{"", bin, "npm", "MS-PL", ""},
		{"GPL-2.0-only OR Apache-2.0", bin, "npm", "Apache-2.0", ""},
		{"GPL-3.0-only", bin, "npm", "MPL-1.1", "license-incompatible:high!,license-weak-copyleft:low"}, // weak dep under copyleft project
		{"MIT", bin, "npm", "MPL-1.1", "license-weak-copyleft:low"},                                     // permissive project: weak rule only
		// clean
		{"MIT", bin, "npm", "MIT", ""},
		{"MIT", bin, "npm", "Apache-2.0 AND BSD-3-Clause", ""},
	} {
		got := summary(run(t, Config{}, c.project, c.usage, nil, pkg(c.eco, "dep", c.lic)))
		if got != c.want {
			t.Errorf("project=%q usage=%s eco=%s lic=%q: got %q, want %q", c.project, c.usage, c.eco, c.lic, got, c.want)
		}
	}
}

func TestDefaultsDevDenyBlocking(t *testing.T) {
	gpl := pkg("npm", "gpl", "GPL-3.0-only")
	// empty usage model → distributed_binary
	if got := summary(run(t, Config{}, "MIT", "", nil, gpl)); got != "license-copyleft-distributed:high!" {
		t.Errorf("default usage: %q", got)
	}
	// dev-only → info, not blocking
	dev := map[*models.Package]scan.PackageContext{gpl: {Dev: true}}
	fs := run(t, Config{}, "MIT", bin, dev, gpl)
	if got := summary(fs); got != "license-copyleft-distributed:info" || !strings.Contains(fs[0].Summary, "dev-only") {
		t.Errorf("dev: %q %q", got, fs[0].Summary)
	}
	// deny prefix (case-insensitive), not capped for dev
	if got := summary(run(t, Config{Deny: []string{"gpl-"}}, "MIT", bin, dev, gpl)); got != "license-copyleft-distributed:info,license-denied:high!" {
		t.Errorf("deny: %q", got)
	}
	// deny steers the OR choice
	if got := summary(run(t, Config{Deny: []string{"MIT"}}, "MIT", saas, nil, pkg("npm", "x", "MIT OR Apache-2.0"))); got != "" {
		t.Errorf("deny OR: %q", got)
	}
	// blocking threshold
	if got := summary(run(t, Config{BlockingSeverity: "medium"}, "MIT", bin, nil, pkg("npm", "l", "LGPL-2.1-only"))); got != "license-weak-copyleft:medium!" {
		t.Errorf("blocking medium: %q", got)
	}
	if got := summary(run(t, Config{BlockingSeverity: "critical"}, "MIT", bin, nil, gpl)); got != "license-copyleft-distributed:high" {
		t.Errorf("blocking critical: %q", got)
	}
	// summary wording and details
	f := run(t, Config{}, "MIT", bin, nil, gpl)[0]
	if f.Summary != "GPL-3.0-only requires releasing your source when you distribute this app; your project is MIT." {
		t.Errorf("summary %q", f.Summary)
	}
	if f.Details["license"] != "GPL-3.0-only" || f.Details["category"] != CatStrongCopyleft || f.Details["project_license"] != "MIT" || f.Details["osadl"] != "No" {
		t.Errorf("details %+v", f.Details)
	}
	// one finding per rule per package (worst term wins)
	if got := summary(run(t, Config{}, "MIT", bin, nil, pkg("npm", "x", "GPL-2.0-only AND GPL-3.0-only"))); got != "license-copyleft-distributed:high!" {
		t.Errorf("per-rule dedup: %q", got)
	}
}

func TestConflicts(t *testing.T) {
	gpl2 := pkg("npm", "gpl2", "GPL-2.0-only")
	apache := pkg("npm", "apache", "Apache-2.0")
	gpl3 := pkg("npm", "gpl3", "GPL-3.0-only")
	nc := pkg("npm", "nc", "CC-BY-NC-4.0")
	mit := pkg("npm", "mit", "MIT")
	conf := func(fs []scan.Finding) []string {
		var s []string
		for _, f := range fs {
			if f.Rule == RuleConflict {
				s = append(s, f.Package.GetName()+"~"+strings.Join(f.Details["conflicts_with"].([]string), "|"))
			}
		}
		slices.Sort(s)
		return s
	}
	got := conf(run(t, Config{}, "GPL-3.0-or-later", bin, nil, gpl2, apache, gpl3, nc, mit))
	// One finding per package holding the stricter license, listing what it clashes with.
	want := []string{"gpl2~apache@1.0.0 (Apache-2.0)|gpl3@1.0.0 (GPL-3.0-only)", "nc~gpl2@1.0.0 (GPL-2.0-only)|gpl3@1.0.0 (GPL-3.0-only)"}
	if !slices.Equal(got, want) {
		t.Errorf("conflicts %v, want %v", got, want)
	}
	// only distributed usage models
	if got := conf(run(t, Config{}, "MIT", saas, nil, gpl2, apache)); len(got) != 0 {
		t.Errorf("saas conflicts: %v", got)
	}
	// dev-only packages excluded
	if got := conf(run(t, Config{}, "MIT", bin, map[*models.Package]scan.PackageContext{gpl2: {Dev: true}}, gpl2, apache)); len(got) != 0 {
		t.Errorf("dev conflicts: %v", got)
	}
	// one finding per GPL package however many permissive deps it clashes with
	var many []*models.Package
	for i := range 20 {
		many = append(many, pkg("npm", fmt.Sprintf("g%02d", i), "GPL-2.0-only"), pkg("npm", fmt.Sprintf("a%02d", i), "Apache-2.0"))
	}
	many = append(many, pkg("npm", "g00", "GPL-2.0-only"))
	if got := conf(run(t, Config{}, "GPL-2.0-only", bin, nil, many...)); len(got) != 20 {
		t.Errorf("aggregation: %d findings", len(got))
	}
	if got := conf(run(t, Config{}, "GPL-2.0-only", bin, nil, gpl2, apache, pkg("npm", "gpl2", "GPL-2.0-only"))); len(got) != 1 {
		t.Errorf("dedup: %v", got)
	}
}

func TestMultipleLicensesPreferPermissive(t *testing.T) {
	// deps.dev lists every license file (code + docs, or dual licensing).
	dual := pkg("Go", "github.com/spdx/tools-golang", "Apache-2.0", "GPL-2.0", "CC-BY-4.0")
	docs := pkg("Go", "github.com/opencontainers/go-digest", "Apache-2.0", "CC-BY-SA-4.0")
	strict := pkg("npm", "gpl-only", "GPL-3.0-only", "GPL-3.0-only")
	fs := run(t, Config{}, "MIT", bin, nil, dual, docs, strict)
	rules := map[string][]string{}
	for _, f := range fs {
		rules[f.Package.GetName()] = append(rules[f.Package.GetName()], f.Rule+":"+f.Severity)
	}
	for _, name := range []string{"github.com/spdx/tools-golang", "github.com/opencontainers/go-digest"} {
		if !slices.Equal(rules[name], []string{"license-multiple:low"}) {
			t.Errorf("%s: %v, want only a low review note", name, rules[name])
		}
	}
	if !slices.Contains(rules["gpl-only"], "license-copyleft-distributed:high") {
		t.Errorf("gpl-only: %v, want copyleft finding", rules["gpl-only"])
	}
}
