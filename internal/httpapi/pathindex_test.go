package httpapi

import (
	"slices"
	"strings"
	"testing"
)

func TestPathIndex(t *testing.T) {
	// app -> a -> b -> t ; app -> c -> t ; app -> a -> d -> b ; orphan -> x
	parents := map[string][]string{
		"a": {""}, "c": {""}, "b": {"a", "d"}, "d": {"a"}, "t": {"b", "c"}, "x": {"orphan"},
	}
	ix := newPathIndex(parents)
	join := func(cs [][]string) []string {
		var out []string
		for _, c := range cs {
			out = append(out, strings.Join(c, ">"))
		}
		return out
	}
	if got := join(ix.paths("t", 3)); !slices.Equal(got, []string{"c>t", "a>b>t", "a>d>b>t"}) {
		t.Errorf("t: %v (shortest first, then longer alternatives)", got)
	}
	if got := join(ix.paths("t", 1)); !slices.Equal(got, []string{"c>t"}) {
		t.Errorf("t k=1: %v", got)
	}
	if got := join(ix.paths("b", 3)); !slices.Equal(got, []string{"a>b", "a>d>b"}) {
		t.Errorf("b: %v", got)
	}
	if got := ix.paths("x", 3); got != nil {
		t.Errorf("unreachable x: %v", got)
	}
	// diamond: two equally short chains
	ix = newPathIndex(map[string][]string{"a": {""}, "b": {""}, "t": {"a", "b"}})
	if got := join(ix.paths("t", 3)); !slices.Equal(got, []string{"a>t", "b>t"}) {
		t.Errorf("diamond: %v", got)
	}
	if got := ix.paths("t", 1); len(got) != 1 {
		t.Errorf("k=1: %v", got)
	}
}
