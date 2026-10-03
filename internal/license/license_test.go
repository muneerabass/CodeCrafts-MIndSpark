package license

import "testing"

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"MIT":                                  "MIT",
		"mit":                                  "MIT",
		"apache-2.0":                           "Apache-2.0",
		"GPL-2.0":                              "GPL-2.0-only",
		"GPL-2.0+":                             "GPL-2.0-or-later",
		"LGPL-2.1":                             "LGPL-2.1-only",
		"LGPL-3.0+":                            "LGPL-3.0-or-later",
		"AGPL-3.0":                             "AGPL-3.0-only",
		"GPL-2.0-with-classpath-exception":     "GPL-2.0-only WITH Classpath-exception-2.0",
		"MIT OR Apache-2.0":                    "MIT OR Apache-2.0",
		"MIT/Apache-2.0":                       "MIT OR Apache-2.0",
		"(MIT and BSD-3-Clause)":               "MIT AND BSD-3-Clause",
		"MIT, Apache-2.0":                      "MIT AND Apache-2.0",
		"Apache-2.0 WITH llvm-exception":       "Apache-2.0 WITH LLVM-exception",
		"MIT AND (Apache-2.0 OR BSD-2-Clause)": "(MIT AND Apache-2.0) OR (MIT AND BSD-2-Clause)",
		"The Apache Software License, Version 2.0": "Apache-2.0",
		"MIT License":         "MIT",
		"non-standard":        "",
		"NOASSERTION":         "",
		"":                    "",
		"UNLICENSED":          "",
		"Some Custom License": "",
		"LicenseRef-foo":      "",
		"MIT OR (":            "",
	} {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCategories(t *testing.T) {
	for in, want := range map[string]string{
		"MIT":                            CatPermissive,
		"0BSD":                           CatUnencumbered,
		"CC0-1.0":                        CatUnencumbered,
		"WTFPL":                          CatPermissive,
		"LGPL-2.1-only":                  CatWeakCopyleft,
		"MPL-2.0":                        CatWeakCopyleft,
		"GPL-3.0-or-later":               CatStrongCopyleft,
		"AGPL-3.0-only":                  CatNetworkCopyleft,
		"SSPL-1.0":                       CatNetworkCopyleft,
		"EUPL-1.2":                       CatNetworkCopyleft,
		"BUSL-1.1":                       CatNoncommercial,
		"CC-BY-NC-SA-3.0":                CatNoncommercial, // prefix fallback
		"Apache-2.0 WITH Commons-Clause": CatNoncommercial,
		"GPL-2.0-only WITH Classpath-exception-2.0": CatWeakCopyleft, // WITH downgrades
		"GPL-3.0-only WITH GCC-exception-3.1":       CatWeakCopyleft,
		"Apache-2.0 WITH LLVM-exception":            CatPermissive, // never upgrades
		"non-standard":                              CatUnknown,
		"Glide":                                     CatOther,
		// OR → least restrictive alternative; AND → most restrictive governs.
		"MIT OR GPL-3.0-only":           CatPermissive,
		"MIT AND GPL-3.0-only":          CatStrongCopyleft,
		"non-standard OR MIT":           CatPermissive,
		"MIT AND non-standard":          CatUnknown,
		"(MIT OR GPL-2.0) AND LGPL-3.0": CatWeakCopyleft,
	} {
		if got, sum := Explain(in); got != want || sum == "" {
			t.Errorf("Explain(%q) = %q (%q), want %q", in, got, sum, want)
		}
	}
}

func TestParseList(t *testing.T) {
	if got := parseList([]string{"MIT", "GPL-3.0"}).String(); got != "MIT AND GPL-3.0-only" {
		t.Errorf("list = %q", got)
	}
	if got := parseList([]string{"MIT", "MIT"}).String(); got != "MIT" {
		t.Errorf("dedup = %q", got)
	}
	if got := parseList(nil); got.known() {
		t.Errorf("empty list should be unknown: %v", got)
	}
}

func TestOSADL(t *testing.T) {
	id := func(s string) term { return parse(s)[0][0] }
	for _, c := range []struct{ lead, sub, want string }{
		{"GPL-2.0-only", "Apache-2.0", "No"},
		{"GPL-3.0-only", "MIT", "Yes"},
		{"GPL-3.0-only", "Apache-2.0", "Yes"},
		{"MIT", "GPL-3.0-only", "No"},
		{"MIT", "MIT", "Same"},
		{"GPL-2.0-only WITH Classpath-exception-2.0", "MIT", "Yes"}, // exact WITH row
		{"MIT", "BUSL-1.1", ""},                                     // not in matrix
	} {
		if got := osadlLookup(id(c.lead), id(c.sub)); got != c.want {
			t.Errorf("osadl[%s][%s] = %q, want %q", c.lead, c.sub, got, c.want)
		}
	}
	// project OR: the project may pick the compatible alternative.
	if v := projectVerdict(parse("MIT OR GPL-3.0-only"), id("GPL-3.0-only")); v != "Same" {
		t.Errorf("projectVerdict OR = %q", v)
	}
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"GPL-2.0-only", "Apache-2.0", true},
		{"GPL-2.0-only", "GPL-3.0-only", true},
		{"GPL-3.0-only", "Apache-2.0", false},
		{"GPL-3.0-only", "MIT", false},
		{"GPL-3.0-only", "CC-BY-NC-4.0", true},
		{"MIT", "Apache-2.0", false},
	} {
		if got := conflicts(id(c.a), id(c.b)); got != c.want {
			t.Errorf("conflicts(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
