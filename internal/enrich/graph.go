package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5"
)

// GraphNode is a node of a deps.dev resolved dependency graph.
type GraphNode = scan.GraphNode

type graphEdge struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// DepsDevGraph returns the resolved dependency graph of a package version
// from deps.dev (nodes[0] is the package itself; edges are node index pairs
// from→to), cached in depsdev_graph for CacheTTL. eco is a vet or OSV
// ecosystem. Unknown packages, unsupported ecosystems and disabled deps.dev
// (on a cache miss) return nil, nil.
func (e *Enricher) DepsDevGraph(ctx context.Context, eco, name, version string) ([]GraphNode, [][2]int, error) {
	system := depsDevSystems[eco]
	if system == "" {
		system = depsDevSystems[osvEcosystems[eco]]
	}
	if system == "" || name == "" || version == "" {
		return nil, nil, nil
	}
	var nodesJSON, edgesJSON []byte
	var found bool
	err := e.pool.QueryRow(ctx, `SELECT nodes, edges, found FROM depsdev_graph
		WHERE system=$1 AND name=$2 AND version=$3 AND fetched_at > $4`, system, name, version, time.Now().Add(-e.o.CacheTTL)).
		Scan(&nodesJSON, &edgesJSON, &found)
	switch {
	case err == nil:
		if !found {
			return nil, nil, nil
		}
		var nodes []GraphNode
		var edges []graphEdge
		if err := errors.Join(json.Unmarshal(nodesJSON, &nodes), json.Unmarshal(edgesJSON, &edges)); err != nil {
			return nil, nil, err
		}
		return nodes, pairs(edges), nil
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, nil, err
	}
	if e.o.DisableDepsDev {
		return nil, nil, nil
	}

	var v struct {
		Nodes []struct {
			VersionKey struct {
				System, Name, Version string
			} `json:"versionKey"`
			Relation string `json:"relation"`
		} `json:"nodes"`
		Edges []struct {
			FromNode int `json:"fromNode"`
			ToNode   int `json:"toNode"`
		} `json:"edges"`
	}
	u := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s:dependencies", e.o.DepsDevURL,
		system, url.PathEscape(name), url.PathEscape(depsDevVersion(system, version)))
	err = e.getJSON(ctx, u, &v)
	if err != nil && !errors.Is(err, errNotFound) {
		return nil, nil, err // not cached: transient
	}
	found = err == nil
	nodes := make([]GraphNode, 0, len(v.Nodes))
	for _, n := range v.Nodes {
		nodes = append(nodes, GraphNode{Name: n.VersionKey.Name, Version: n.VersionKey.Version, Relation: n.Relation})
	}
	edges := make([]graphEdge, 0, len(v.Edges))
	for _, ed := range v.Edges {
		if ed.FromNode >= 0 && ed.ToNode >= 0 && ed.FromNode < len(nodes) && ed.ToNode < len(nodes) {
			edges = append(edges, graphEdge{ed.FromNode, ed.ToNode})
		}
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO depsdev_graph (system, name, version, nodes, edges, found, fetched_at)
		VALUES ($1,$2,$3,$4,$5,$6,now()) ON CONFLICT (system, name, version) DO UPDATE
		SET nodes=EXCLUDED.nodes, edges=EXCLUDED.edges, found=EXCLUDED.found, fetched_at=now()`,
		system, name, version, mustJSON(nodes), mustJSON(edges), found); err != nil {
		e.o.Logger.Warn("enrich: depsdev_graph cache write failed", "err", err)
	}
	if !found {
		return nil, nil, nil
	}
	return nodes, pairs(edges), nil
}

func pairs(es []graphEdge) [][2]int {
	out := make([][2]int, len(es))
	for i, e := range es {
		out[i] = [2]int{e.From, e.To}
	}
	return out
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// depsDevVersion adapts a version to deps.dev's form: Go module versions carry a
// leading "v" there (v1.2.3), while lockfile parsers report them without it.
func depsDevVersion(system, v string) string {
	if system == "go" && v != "" && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}
