package enrich

import "testing"

func TestDepsDevVersion(t *testing.T) {
	for _, c := range []struct{ sys, in, want string }{
		{"go", "1.83.2", "v1.83.2"}, {"go", "v1.2.3", "v1.2.3"}, {"go", "0.0.0-20260304060910-4fcedbd3c18b", "v0.0.0-20260304060910-4fcedbd3c18b"},
		{"npm", "4.17.21", "4.17.21"}, {"pypi", "2.19.0", "2.19.0"}, {"go", "", ""},
	} {
		if got := depsDevVersion(c.sys, c.in); got != c.want {
			t.Errorf("depsDevVersion(%s,%s)=%s want %s", c.sys, c.in, got, c.want)
		}
	}
}
