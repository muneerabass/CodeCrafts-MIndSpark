package render

import "testing"

func TestFixAdvicePicksHighestFixedVersion(t *testing.T) {
	p := PathItem{Target: PathNode{Name: "urllib3"}, Depth: 1,
		Advisories: []Vuln{{ID: "A", FixedIn: "2.6.0"}, {ID: "B", FixedIn: "2.8.0"}, {ID: "C", FixedIn: "1.26.17"}, {ID: "D"}}}
	got := fixAdvice(p, false, "")
	want := "Upgrade urllib3 to ≥2.8.0; 1 advisory(ies) have no fix yet"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"2.8.0", "2.6.0", 1}, {"1.26.17", "1.26.9", 1}, {"2023.7.22", "2022.12.07", 1}, {"1.0", "1.0.1", -1}, {"v1.2.3", "1.2.3", 0}, {"6.16.0", "6.7.3", 1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
