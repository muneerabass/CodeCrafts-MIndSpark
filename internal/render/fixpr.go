package render

import (
	"fmt"
	"strings"
)

// FixAdvisory is one advisory fixed by a fix pull request.
type FixAdvisory struct{ ID, Risk string }

// FixPRBody is the description of a fix pull request opened by depguard.
func FixPRBody(eco, name, from, to, manifest string, direct bool, advs []FixAdvisory, link string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## depguard fix: `%s` %s → %s\n\n", Escape(name), Escape(from), Escape(to))
	kind := "direct"
	if !direct {
		kind = "transitive"
	}
	fmt.Fprintf(&b, "Upgrades a %s %s dependency in `%s` to the first version without these known vulnerabilities:\n\n", kind, Escape(eco), Escape(manifest))
	b.WriteString("| Advisory | Risk |\n|---|---|\n")
	for _, a := range advs {
		fmt.Fprintf(&b, "| [%s](https://osv.dev/vulnerability/%s) | %s |\n", Escape(a.ID), a.ID, Escape(strings.ToLower(a.Risk)))
	}
	b.WriteString("\nOnly the manifest and lockfile changed; package install scripts were not run. Check your tests before merging.\n")
	if link != "" {
		fmt.Fprintf(&b, "\n[View in depguard →](%s)\n", link)
	}
	b.WriteString("\n<sub>Opened by depguard auto-fix</sub>\n")
	return b.String()
}
