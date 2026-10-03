package feeds

import "testing"

func TestNormalizeName(t *testing.T) {
	cases := []struct{ eco, in, want string }{
		{"PyPI", "Django_REST.framework", "django-rest-framework"},
		{"PyPI", "zope..interface__x", "zope-interface-x"},
		{"npm", "@Scope/Pkg", "@scope/pkg"},
		{"Maven", "org.Apache:Log4j", "org.Apache:Log4j"},
		{"Go", "github.com/Foo/Bar", "github.com/Foo/Bar"},
	}
	for _, c := range cases {
		if got := NormalizeName(c.eco, c.in); got != c.want {
			t.Errorf("NormalizeName(%s, %s) = %s, want %s", c.eco, c.in, got, c.want)
		}
	}
}

func TestRisk(t *testing.T) {
	v3 := func(s string) []Severity { return []Severity{{Type: "CVSS_V3", Score: s}} }
	cases := []struct {
		name, id string
		sev      []Severity
		db, want string
	}{
		{"malware", "MAL-2024-1", nil, "", "CRITICAL"},
		{"v3.1 critical", "GHSA-1", v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), "LOW", "CRITICAL"},
		{"v3.0 medium", "GHSA-2", v3("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"), "", "MEDIUM"},
		{"v3.1 low", "GHSA-3", v3("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), "", "LOW"},
		{"v4 high", "GHSA-4", []Severity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}}, "", "HIGH"},
		{"best of v3/v4", "GHSA-5", []Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
			{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
		}, "", "HIGH"},
		{"db moderate", "GHSA-6", nil, "MODERATE", "MEDIUM"},
		{"db high", "GHSA-7", v3("garbage"), "HIGH", "HIGH"},
		{"unknown", "PYSEC-1", nil, "", "UNKNOWN"},
	}
	for _, c := range cases {
		if got := Risk(c.id, c.sev, c.db); got != c.want {
			t.Errorf("%s: Risk = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestStripNUL(t *testing.T) {
	cases := map[string]string{
		`{"a":"x\u0000y"}`:         `{"a":"xy"}`,
		`{"a":"\\u0000;"}`:         `{"a":"\\u0000;"}`, // escaped backslash, not a NUL
		`{"a":"\\\u0000\u0000\""}`: `{"a":"\\\""}`,
		`{"a":"plain"}`:            `{"a":"plain"}`,
	}
	for in, want := range cases {
		if got := string(stripNUL([]byte(in))); got != want {
			t.Errorf("stripNUL(%s) = %s, want %s", in, got, want)
		}
	}
}
