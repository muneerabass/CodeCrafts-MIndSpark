// Package license classifies SPDX license expressions, detects the project
// license and checks dependencies for license compliance against the project
// license and usage model (see New).
package license

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/github/go-spdx/v2/spdxexp/spdxlicenses"
)

// License categories, least to most restrictive (see rank).
const (
	CatUnencumbered    = "unencumbered"     // public-domain like: no conditions
	CatPermissive      = "permissive"       // notice/attribution only
	CatOther           = "other"            // valid SPDX id we have no category for
	CatWeakCopyleft    = "weak_copyleft"    // file/library-level copyleft (LGPL, MPL, EPL, GPL WITH linking exception)
	CatUnknown         = "unknown"          // missing, NOASSERTION, non-standard, unparsable
	CatStrongCopyleft  = "strong_copyleft"  // whole-program copyleft on distribution (GPL)
	CatNetworkCopyleft = "network_copyleft" // copyleft triggered by network use (AGPL, SSPL, EUPL, OSL)
	CatNoncommercial   = "noncommercial"    // non-commercial / source-available / no-derivatives
)

var rank = map[string]int{
	CatUnencumbered: 0, CatPermissive: 1, CatOther: 1, CatWeakCopyleft: 2, CatUnknown: 3,
	CatStrongCopyleft: 4, CatNetworkCopyleft: 5, CatNoncommercial: 6,
}

// categories: curated SPDX id → category. Unlisted ids fall back to prefix
// heuristics in classify. Decisions: 0BSD/MIT-0 are unencumbered; WTFPL is
// permissive (licenseclassifier calls it "forbidden" for vagueness, but it
// imposes no obligations); EUPL and OSL are network copyleft (their
// "communication"/"external deployment" clauses cover network use);
// CC-BY-ND is grouped with non-commercial (no derivatives = restricted).
var categories = func() map[string]string {
	m := map[string]string{}
	add := func(c string, ids ...string) {
		for _, id := range ids {
			m[id] = c
		}
	}
	add(CatUnencumbered, "CC0-1.0", "Unlicense", "0BSD", "MIT-0", "PDDL-1.0", "SAX-PD", "blessing")
	add(CatPermissive, "MIT", "MIT-CMU", "X11", "ISC", "BSD-1-Clause", "BSD-2-Clause", "BSD-2-Clause-Patent",
		"BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause", "Apache-1.0", "Apache-1.1", "Apache-2.0",
		"Zlib", "zlib-acknowledgement", "BSL-1.0", "PSF-2.0", "Python-2.0", "Python-2.0.1", "CNRI-Python",
		"Unicode-DFS-2015", "Unicode-DFS-2016", "Unicode-3.0", "PostgreSQL", "NCSA", "curl", "Artistic-2.0",
		"BlueOak-1.0.0", "UPL-1.0", "W3C", "W3C-20150513", "OpenSSL", "ICU", "Libpng", "libpng-2.0",
		"AFL-2.1", "AFL-3.0", "MS-PL", "CC-BY-3.0", "CC-BY-4.0", "HPND", "ECL-2.0", "EFL-2.0", "FSFAP",
		"Info-ZIP", "NTP", "TCL", "XFree86-1.1", "ZPL-2.0", "ZPL-2.1", "Ruby", "PHP-3.0", "PHP-3.01",
		"MirOS", "WTFPL", "Beerware", "bzip2-1.0.6", "libtiff", "Spencer-86", "SSH-OpenSSH")
	add(CatWeakCopyleft, "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
		"LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL-2.0-no-copyleft-exception",
		"EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "IPL-1.0", "MS-RL", "APSL-2.0",
		"Artistic-1.0", "Artistic-1.0-Perl", "OFL-1.0", "OFL-1.1", "ErlPL-1.1", "NPL-1.1", "SPL-1.0", "CECILL-C")
	add(CatStrongCopyleft, "GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0-only", "GPL-2.0-or-later",
		"GPL-3.0-only", "GPL-3.0-or-later", "Sleepycat", "CC-BY-SA-3.0", "CC-BY-SA-4.0", "CECILL-2.1", "QPL-1.0")
	add(CatNetworkCopyleft, "AGPL-1.0-only", "AGPL-1.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
		"SSPL-1.0", "OSL-1.0", "OSL-2.0", "OSL-2.1", "OSL-3.0", "EUPL-1.0", "EUPL-1.1", "EUPL-1.2",
		"CPAL-1.0", "RPL-1.1", "RPL-1.5", "Parity-6.0.0", "Parity-7.0.0")
	add(CatNoncommercial, "BUSL-1.1", "Elastic-2.0", "PolyForm-Noncommercial-1.0.0",
		"PolyForm-Small-Business-1.0.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0", "CC-BY-ND-4.0")
	return m
}()

// prefixes classify SPDX ids missing from categories (first match wins).
var prefixes = []struct{ p, c string }{
	{"AGPL", CatNetworkCopyleft}, {"LGPL", CatWeakCopyleft}, {"GPL", CatStrongCopyleft},
	{"CC-BY-NC", CatNoncommercial}, {"CC-BY-ND", CatNoncommercial}, {"PolyForm", CatNoncommercial},
	{"CC-BY-SA", CatStrongCopyleft}, {"GFDL", CatStrongCopyleft}, {"CC-BY-", CatPermissive},
	{"MPL", CatWeakCopyleft}, {"EPL", CatWeakCopyleft}, {"CDDL", CatWeakCopyleft}, {"OFL", CatWeakCopyleft},
	{"EUPL", CatNetworkCopyleft}, {"OSL", CatNetworkCopyleft}, {"CECILL", CatStrongCopyleft},
	{"MIT", CatPermissive}, {"BSD", CatPermissive}, {"Apache", CatPermissive}, {"X11", CatPermissive},
}

// aliases maps deprecated SPDX ids and common free-text names (lowercase,
// as found in pom.xml / package.json / PyPI) to SPDX expressions.
var aliases = map[string]string{
	"gpl-1.0": "GPL-1.0-only", "gpl-2.0": "GPL-2.0-only", "gpl-3.0": "GPL-3.0-only",
	"lgpl-2.0": "LGPL-2.0-only", "lgpl-2.1": "LGPL-2.1-only", "lgpl-3.0": "LGPL-3.0-only",
	"agpl-1.0": "AGPL-1.0-only", "agpl-3.0": "AGPL-3.0-only", "gfdl-1.3": "GFDL-1.3-only",
	"gpl-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
	"gpl-2.0-with-gcc-exception":       "GPL-2.0-only WITH GCC-exception-2.0",
	"gpl-2.0-with-autoconf-exception":  "GPL-2.0-only WITH Autoconf-exception-2.0",
	"gpl-2.0-with-bison-exception":     "GPL-2.0-only WITH Bison-exception-2.2",
	"gpl-2.0-with-font-exception":      "GPL-2.0-only WITH Font-exception-2.0",
	"gpl-3.0-with-gcc-exception":       "GPL-3.0-only WITH GCC-exception-3.1",
	"gpl-3.0-with-autoconf-exception":  "GPL-3.0-only WITH Autoconf-exception-3.0",
	"standardml-nj":                    "SMLNJ", "bsd-2-clause-freebsd": "BSD-2-Clause", "bsd-2-clause-netbsd": "BSD-2-Clause",
	"mit license": "MIT", "the mit license": "MIT", "mit/x11": "MIT", "expat": "MIT",
	"apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache2": "Apache-2.0", "apache 2": "Apache-2.0",
	"apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0", "apache license version 2.0": "Apache-2.0",
	"the apache software license, version 2.0": "Apache-2.0", "the apache license, version 2.0": "Apache-2.0",
	"apache software license": "Apache-2.0", "apache software license 2.0": "Apache-2.0",
	"bsd license": "BSD-3-Clause", "new bsd license": "BSD-3-Clause", "the new bsd license": "BSD-3-Clause",
	"bsd 3-clause": "BSD-3-Clause", "3-clause bsd license": "BSD-3-Clause", "modified bsd license": "BSD-3-Clause",
	"bsd 2-clause": "BSD-2-Clause", "simplified bsd license": "BSD-2-Clause", "isc license": "ISC",
	"gplv2": "GPL-2.0-only", "gplv2+": "GPL-2.0-or-later", "gplv3": "GPL-3.0-only", "gplv3+": "GPL-3.0-or-later",
	"lgplv2": "LGPL-2.0-only", "lgplv2.1": "LGPL-2.1-only", "lgplv3": "LGPL-3.0-only", "lgplv3+": "LGPL-3.0-or-later",
	"agplv3": "AGPL-3.0-only", "mpl 2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
	"mozilla public license, version 2.0": "MPL-2.0", "eclipse public license 2.0": "EPL-2.0",
	"eclipse public license - v 2.0": "EPL-2.0", "eclipse public license - v 1.0": "EPL-1.0",
	"gnu general public license v3.0": "GPL-3.0-only", "gnu general public license v2.0": "GPL-2.0-only",
	"gnu lesser general public license v3.0": "LGPL-3.0-only", "gnu lesser general public license v2.1": "LGPL-2.1-only",
	"gnu affero general public license v3.0": "AGPL-3.0-only", "cddl + gplv2 with classpath exception": "CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0",
	"cc0": "CC0-1.0", "public domain (cc0)": "CC0-1.0", "the unlicense": "Unlicense", "zlib license": "Zlib",
	"python software foundation license": "PSF-2.0", "psf": "PSF-2.0", "boost software license 1.0": "BSL-1.0",
}

// unknownValues are explicit "no license information" markers.
var unknownValues = map[string]bool{"": true, "noassertion": true, "none": true, "non-standard": true,
	"unknown": true, "unlicensed": true, "see license": true, "see license in license": true, "other": true, "proprietary": true}

// term is one license of an expression; ID "" means unrecognised (Raw kept).
type term struct{ ID, Exc, Raw string }

func (t term) String() string {
	switch {
	case t.ID == "":
		if t.Raw == "" {
			return "unknown"
		}
		return t.Raw
	case t.Exc != "":
		return t.ID + " WITH " + t.Exc
	}
	return t.ID
}

// category of one term. WITH exceptions downgrade strong copyleft to weak
// (linking/runtime exceptions such as Classpath, GCC, LLVM); Commons-Clause
// turns anything non-commercial.
func (t term) category() string {
	if strings.EqualFold(t.Exc, "Commons-Clause") {
		return CatNoncommercial
	}
	c := classify(t.ID)
	if t.Exc != "" && c == CatStrongCopyleft {
		c = CatWeakCopyleft
	}
	return c
}

func classify(id string) string {
	if id == "" || strings.HasPrefix(id, "LicenseRef-") {
		return CatUnknown
	}
	if c, ok := categories[id]; ok {
		return c
	}
	for _, p := range prefixes {
		if strings.HasPrefix(id, p.p) {
			return p.c
		}
	}
	return CatOther
}

// alt is one choice of an expression (all its terms apply); dnf is a set of
// choices (any one may be picked): OR → choose, AND → all apply.
type (
	alt []term
	dnf []alt
)

func (a alt) String() string {
	s := make([]string, len(a))
	for i, t := range a {
		s[i] = t.String()
	}
	return strings.Join(s, " AND ")
}

func (d dnf) String() string {
	s := make([]string, len(d))
	for i, a := range d {
		s[i] = a.String()
		if len(a) > 1 && len(d) > 1 {
			s[i] = "(" + s[i] + ")"
		}
	}
	return strings.Join(s, " OR ")
}

// worst returns the most restrictive category in the alternative.
func (a alt) worst() string {
	w := CatUnencumbered
	for _, t := range a {
		if c := t.category(); rank[c] > rank[w] {
			w = c
		}
	}
	return w
}

func (d dnf) known() bool {
	for _, a := range d {
		if a.worst() != CatUnknown {
			return true
		}
	}
	return false
}

const maxAlts = 32 // ponytail: caps AND-of-OR cross products; real expressions never get close

// parse turns a license string (SPDX expression, deprecated id, free-text
// name, comma list) into DNF. Never fails: unparsable input is one unknown term.
func parse(raw string) dnf {
	s := strings.TrimSpace(raw)
	if unknownValues[strings.ToLower(s)] {
		return dnf{{{Raw: s}}}
	}
	if a, ok := aliases[strings.ToLower(s)]; ok {
		s = a
	}
	p := &parser{toks: tokenize(s)}
	d, ok := p.or()
	if !ok || p.i != len(p.toks) {
		return dnf{{{Raw: s}}}
	}
	return d
}

func tokenize(s string) []string {
	var toks []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case '(', ')', ',', '/':
			flush()
			toks = append(toks, string(r))
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

type parser struct {
	toks []string
	i    int
}

func (p *parser) peek(ops ...string) bool {
	if p.i >= len(p.toks) {
		return false
	}
	for _, op := range ops {
		if strings.EqualFold(p.toks[p.i], op) {
			return true
		}
	}
	return false
}

func (p *parser) or() (dnf, bool) {
	d, ok := p.and()
	for ok && p.peek("OR", "/") {
		p.i++
		var r dnf
		if r, ok = p.and(); ok {
			d = append(d, r...)
		}
	}
	if len(d) > maxAlts {
		d = d[:maxAlts]
	}
	return d, ok
}

func (p *parser) and() (dnf, bool) {
	d, ok := p.with()
	for ok && p.peek("AND", ",") {
		p.i++
		var r dnf
		if r, ok = p.with(); ok {
			d = cross(d, r)
		}
	}
	return d, ok
}

func (p *parser) with() (dnf, bool) {
	if p.peek("(") {
		p.i++
		d, ok := p.or()
		if !ok || !p.peek(")") {
			return nil, false
		}
		p.i++
		return d, true
	}
	if p.i >= len(p.toks) || p.peek("AND", "OR", "WITH", ")", ",", "/") {
		return nil, false
	}
	t := normID(p.toks[p.i])
	p.i++
	if p.peek("WITH") {
		p.i++
		if p.i >= len(p.toks) {
			return nil, false
		}
		exc := p.toks[p.i]
		if ok, canon := inList(spdxlicenses.GetExceptions(), exc); ok {
			exc = canon
		}
		t.Exc = exc
		p.i++
	}
	return dnf{{t}}, true
}

// normID canonicalises one license id: deprecated aliases (GPL-2.0 →
// GPL-2.0-only), "+" → -or-later, case-insensitive SPDX lookup.
func normID(raw string) term {
	id := raw
	plus := false
	if _, ok := aliases[strings.ToLower(id)]; !ok && strings.HasSuffix(id, "+") {
		id, plus = strings.TrimSuffix(id, "+"), true
	}
	if a, ok := aliases[strings.ToLower(id)]; ok {
		if base, exc, ok := strings.Cut(a, " WITH "); ok {
			return term{ID: base, Exc: exc, Raw: raw}
		}
		id = a
	}
	ok, canon := spdxexp.ActiveLicense(id)
	if !ok {
		if ok, canon = inList(spdxlicenses.GetDeprecated(), id); !ok {
			return term{Raw: raw}
		}
	}
	id = canon
	if plus {
		if ok, c := spdxexp.ActiveLicense(strings.TrimSuffix(id, "-only") + "-or-later"); ok {
			id = c
		}
	}
	return term{ID: id, Raw: raw}
}

func inList(list []string, id string) (bool, string) {
	for _, l := range list {
		if strings.EqualFold(l, id) {
			return true, l
		}
	}
	return false, id
}

// parseList parses deps.dev's license list. Multiple entries all apply (AND):
// deps.dev lists every license it found (e.g. several LICENSE files), so the
// conservative reading is that all govern.
func parseList(ls []string) dnf {
	var d dnf
	for _, l := range ls {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if d == nil {
			d = parse(l)
		} else {
			d = cross(d, parse(l))
		}
	}
	if d == nil {
		return dnf{{{}}}
	}
	return d
}

// cross is AND over two DNFs: every pairing of alternatives, terms deduped.
func cross(x, y dnf) dnf {
	var out dnf
	for _, a := range x {
		for _, b := range y {
			if len(out) == maxAlts {
				return out
			}
			c := append(alt{}, a...)
			for _, t := range b {
				if !slices.ContainsFunc(c, func(u term) bool { return u.String() == t.String() }) {
					c = append(c, t)
				}
			}
			out = append(out, c)
		}
	}
	return out
}

// --- OSADL compatibility matrix ---

//go:embed data/osadl-matrix.json
var osadlJSON []byte

var osadl = func() map[string]map[string]string {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(osadlJSON, &raw); err != nil {
		panic("license: bad embedded OSADL matrix: " + err.Error())
	}
	m := map[string]map[string]string{}
	for k, v := range raw {
		row := map[string]string{}
		if json.Unmarshal(v, &row) == nil {
			m[k] = row
		}
	}
	return m
}()

// OSADL verdicts ordered best → worst; "" = pair not covered by the matrix.
var verdictRank = map[string]int{"": 0, "Same": 0, "Yes": 0, "Check dependency": 1, "Unknown": 2, "No": 3}

// osadlLookup returns the OSADL verdict for including subordinate under leading.
func osadlLookup(leading, subordinate term) string {
	key := func(t term) []string {
		if t.Exc != "" {
			return []string{t.String(), t.ID}
		}
		return []string{t.ID}
	}
	for _, l := range key(leading) {
		row, ok := osadl[l]
		if !ok {
			continue
		}
		for _, s := range key(subordinate) {
			if v, ok := row[s]; ok {
				return v
			}
		}
	}
	return ""
}

// projectVerdict: the project may pick any of its alternatives (best wins);
// within one alternative every leading license must accept the dep (worst wins).
func projectVerdict(project dnf, dep term) string {
	best := "No"
	for _, a := range project {
		worst := ""
		for _, l := range a {
			if v := osadlLookup(l, dep); verdictRank[v] > verdictRank[worst] || worst == "" {
				worst = v
			}
		}
		if verdictRank[worst] < verdictRank[best] || (verdictRank[worst] == verdictRank[best] && best == "") {
			best = worst
		}
	}
	return best
}

// conflicts reports whether two dependency licenses cannot be combined in one
// distributed work: neither may lead with the other included (OSADL "No" both
// ways), or copyleft meets non-commercial.
func conflicts(a, b term) bool {
	ca, cb := a.category(), b.category()
	copyleft := func(c string) bool { return c == CatStrongCopyleft || c == CatNetworkCopyleft }
	if (copyleft(ca) && cb == CatNoncommercial) || (copyleft(cb) && ca == CatNoncommercial) {
		return true
	}
	return osadlLookup(a, b) == "No" && osadlLookup(b, a) == "No"
}

// --- Explain ---

var catSummary = map[string]string{
	CatUnencumbered:    "Public-domain style license: no conditions on use or distribution.",
	CatPermissive:      "Permissive license: free to use and distribute; keep the copyright and license notice.",
	CatOther:           "Recognised SPDX license without a known category; review its terms manually.",
	CatWeakCopyleft:    "Weak copyleft: changes to this library's own files must be shared under the same license; your code may stay closed (LGPL also requires that users can relink).",
	CatUnknown:         "No recognised license: by default nobody may use or redistribute it until the license is clarified.",
	CatStrongCopyleft:  "Strong copyleft: if you distribute software containing it, the whole program must be released as source under a compatible GPL license.",
	CatNetworkCopyleft: "Network copyleft: even offering the software over a network (SaaS) requires releasing your complete source code.",
	CatNoncommercial:   "Non-commercial or source-available license: commercial use, hosting or derivatives are restricted.",
}

// Explain returns the category of an SPDX expression and a plain-English
// summary for UI and reports. For OR expressions the least restrictive
// alternative is explained.
func Explain(spdx string) (category, summary string) {
	d := parse(spdx)
	a := pick(d, func(a alt) int { return rank[a.worst()] })
	category = a.worst()
	return category, catSummary[category]
}

// pick returns the alternative with the lowest score (first on ties).
func pick(d dnf, score func(alt) int) alt {
	best, bs := d[0], score(d[0])
	for _, a := range d[1:] {
		if s := score(a); s < bs {
			best, bs = a, s
		}
	}
	return best
}
