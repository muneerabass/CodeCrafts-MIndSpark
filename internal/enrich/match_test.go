package enrich

import "testing"

func TestAffects(t *testing.T) {
	rng := func(typ string, evs ...osvEvent) []osvRange { return []osvRange{{Type: typ, Events: evs}} }
	in := func(v string) osvEvent { return osvEvent{Introduced: v} }
	fix := func(v string) osvEvent { return osvEvent{Fixed: v} }
	last := func(v string) osvEvent { return osvEvent{LastAffected: v} }

	lodash := rng("SEMVER", in("0"), fix("4.17.21"))
	twoWindows := rng("SEMVER", in("2.0.0"), fix("1.0.5"), fix("2.1.0"), in("1.0.0")) // unsorted on purpose
	lastAff := rng("ECOSYSTEM", in("1.0.0"), last("1.2.0"))
	pypi := rng("ECOSYSTEM", in("0"), fix("2.0.0rc1"))
	pypiEq := rng("ECOSYSTEM", in("1.0"), fix("1.0.1"))
	log4j := rng("ECOSYSTEM", in("2.0-beta9"), fix("2.15.0"))
	goRng := rng("SEMVER", in("0"), fix("1.9.1"))
	gitOnly := rng("GIT", in("0"), fix("abc123"))

	cases := []struct {
		name, eco, ver string
		versions       []string
		ranges         []osvRange
		want           bool
	}{
		{"npm below fix", "npm", "4.17.20", nil, lodash, true},
		{"npm at fix", "npm", "4.17.21", nil, lodash, false},
		{"npm prerelease of fix", "npm", "4.17.21-beta.1", nil, lodash, true},
		{"npm second window", "npm", "2.0.1", nil, twoWindows, true},
		{"npm between windows", "npm", "1.0.6", nil, twoWindows, false},
		{"npm first window", "npm", "1.0.4", nil, twoWindows, true},
		{"last_affected inclusive", "npm", "1.2.0", nil, lastAff, true},
		{"after last_affected", "npm", "1.2.1", nil, lastAff, false},
		{"before introduced", "npm", "0.9.0", nil, lastAff, false},
		{"pypi beta < rc fix", "PyPI", "2.0.0b1", nil, pypi, true},
		{"pypi release >= rc fix", "PyPI", "2.0.0", nil, pypi, false},
		{"pypi post release", "PyPI", "1.9.post1", nil, pypi, true},
		{"pypi 1.0.0 == 1.0", "PyPI", "1.0.0", nil, pypiEq, true},
		{"maven affected", "Maven", "2.14.1", nil, log4j, true},
		{"maven rc before fix", "Maven", "2.15.0-rc1", nil, log4j, true},
		{"maven fixed", "Maven", "2.15.0", nil, log4j, false},
		{"maven later", "Maven", "2.16.0", nil, log4j, false},
		{"maven before beta9", "Maven", "2.0-beta8", nil, log4j, false},
		{"go v prefix", "Go", "v1.9.0", nil, goRng, true},
		{"go v prefix fixed", "Go", "v1.9.1", nil, goRng, false},
		{"git ranges ignored", "npm", "1.0.0", nil, gitOnly, false},
		{"explicit version", "npm", "1.0.0", []string{"0.9.0", "1.0.0"}, nil, true},
		{"explicit version miss", "npm", "1.0.1", []string{"1.0.0"}, nil, false},
		{"explicit go v", "Go", "v1.2.3", []string{"1.2.3"}, nil, true},
		{"gh actions fallback semver", "GitHub Actions", "45.0.6", nil, rng("ECOSYSTEM", in("0"), fix("46.0.1")), true},
	}
	for _, c := range cases {
		if got := affects(c.eco, c.ver, c.versions, c.ranges); got != c.want {
			t.Errorf("%s: affects(%s %s) = %v, want %v", c.name, c.eco, c.ver, got, c.want)
		}
	}
}
