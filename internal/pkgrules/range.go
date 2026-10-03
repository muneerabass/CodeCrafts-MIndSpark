package pkgrules

import (
	"fmt"
	"strings"

	"github.com/depguard/depguard/internal/enrich"
)

// Range is an allowed-version expression: alternatives separated by "||",
// each a list of comparisons (>=, >, <=, <, =, !=) separated by spaces or
// commas, all of which must hold. A bare version means "=". Empty = any.
type Range [][]comparison

type comparison struct{ op, version string }

var ops = []string{">=", "<=", "!=", "==", ">", "<", "="}

func ParseRange(s string) (Range, error) {
	var r Range
	for _, alt := range strings.Split(s, "||") {
		fields := strings.FieldsFunc(alt, func(c rune) bool { return c == ' ' || c == ',' })
		var cs []comparison
		for i := 0; i < len(fields); i++ {
			f, op := fields[i], "="
			for _, o := range ops {
				if strings.HasPrefix(f, o) {
					op, f = o, f[len(o):]
					break
				}
			}
			if f == "" && i+1 < len(fields) { // ">= 1.2" written with a space
				i++
				f = fields[i]
			}
			if f == "" || strings.ContainsAny(f, "<>=!") {
				return nil, fmt.Errorf("invalid version range %q", s)
			}
			if op == "==" {
				op = "="
			}
			cs = append(cs, comparison{op, f})
		}
		if len(cs) > 0 {
			r = append(r, cs)
		}
	}
	if strings.TrimSpace(s) != "" && len(r) == 0 {
		return nil, fmt.Errorf("invalid version range %q", s)
	}
	return r, nil
}

// Contains reports whether version satisfies the range in the ecosystem's
// version scheme. An empty range contains everything.
func (r Range) Contains(osvEco, version string) (bool, error) {
	if len(r) == 0 {
		return true, nil
	}
	var lastErr error
	for _, alt := range r {
		ok := true
		for _, c := range alt {
			cmp, err := enrich.CompareVersions(osvEco, goV(osvEco, version), goV(osvEco, c.version))
			if err != nil {
				lastErr, ok = err, false
				break
			}
			switch c.op {
			case ">=":
				ok = cmp >= 0
			case ">":
				ok = cmp > 0
			case "<=":
				ok = cmp <= 0
			case "<":
				ok = cmp < 0
			case "!=":
				ok = cmp != 0
			default:
				ok = cmp == 0
			}
			if !ok {
				break
			}
		}
		if ok {
			return true, nil
		}
	}
	return false, lastErr
}

// goV adds the "v" Go module versions carry, so rules may omit it.
func goV(eco, v string) string {
	if eco == "Go" && v != "" && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}
