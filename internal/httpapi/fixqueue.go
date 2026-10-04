package httpapi

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/teamcfg"
	"github.com/jackc/pgx/v5"
)

// slaDays is the deadline in days for a risk expression, from the tenant's sla
// settings with the same defaults as teamcfg.DefaultSLA.
func slaDays(risk string) string {
	return `(SELECT COALESCE((ts.sla->>lower(` + risk + `))::int, CASE lower(` + risk + `) WHEN 'critical' THEN 7 WHEN 'high' THEN 30 WHEN 'medium' THEN 90 ELSE 0 END) FROM tenant_settings ts)`
}

type queueAdvisory struct {
	ID      string `json:"id"`
	Risk    string `json:"risk"`
	FixedIn string `json:"fixed_in"`
	KEV     bool   `json:"kev"`
}

type queueProject struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Manifest string `json:"manifest_path"`
	Direct   bool   `json:"direct"`
}

type queueItem struct {
	Ecosystem  string          `json:"ecosystem"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	FixedIn    string          `json:"fixed_in"`
	Command    string          `json:"command"`
	Risk       string          `json:"risk"`
	KEV        bool            `json:"kev"`
	EPSS       *float64        `json:"epss"`
	Advisories []queueAdvisory `json:"advisories"`
	Projects   []queueProject  `json:"projects"`
	FirstSeen  time.Time       `json:"first_seen"`
	DueAt      *time.Time      `json:"due_at"`
	Overdue    bool            `json:"overdue"`
	Weight     float64         `json:"weight"`
	Share      float64         `json:"share"` // cumulative % of total risk removed by fixing this and everything above it
}

var riskPoints = map[string]float64{"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
var riskOrderMap = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

// fixQueue ranks current vulnerable packages across all projects by how much
// risk fixing each one removes.
func (s *Server) fixQueue(w http.ResponseWriter, r *http.Request) error {
	project := r.URL.Query().Get("project_id")
	var items []*queueItem
	var sla teamcfg.SLA
	err := s.tx(r, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), `SELECT sla FROM tenant_settings`).Scan(&raw); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		sla = teamcfg.ParseSLA(raw)
		// Exploit data (KEV, EPSS) is looked up once per advisory, not per package × project row.
		rows, err := tx.Query(r.Context(), `
WITH cur AS (SELECT pvc.component_id, pvc.manifest_path, COALESCE(pvc.direct, false) AS direct, p.id AS pid, p.name AS pname
  FROM project_version_components pvc JOIN project_versions pv ON pv.id = pvc.project_version_id JOIN projects p ON p.id = pv.project_id
  WHERE ($1 = '' OR p.id = $1)),
vul AS (SELECT cv.component_id, cv.advisory_id, cv.risk, COALESCE(cv.fixed_in, '') AS fixed, cv.first_seen FROM component_vulnerabilities cv
  WHERE cv.advisory_id NOT LIKE 'MAL-%' AND cv.component_id IN (SELECT component_id FROM cur)),
ids AS (SELECT DISTINCT advisory_id, advisory_id AS cve FROM vul
  UNION SELECT DISTINCT v.advisory_id, aa.alias FROM vul v JOIN advisory_alias aa ON aa.advisory_id = v.advisory_id),
score AS (SELECT ids.advisory_id, bool_or(cs.kev) AS kev, max(cs.epss)::float8 AS epss FROM ids JOIN cve_score cs ON cs.cve = ids.cve GROUP BY 1)
SELECT c.ecosystem, c.name, c.version, v.advisory_id, v.risk, v.fixed, v.first_seen, COALESCE(s.kev, false), s.epss,
  cur.pid, cur.pname, cur.manifest_path, cur.direct
FROM cur JOIN vul v ON v.component_id = cur.component_id JOIN components c ON c.id = cur.component_id
LEFT JOIN score s ON s.advisory_id = v.advisory_id
ORDER BY c.ecosystem, c.name, c.version`, project)
		if err != nil {
			return err
		}
		defer rows.Close()
		byKey := map[string]*queueItem{}
		seenAdv := map[string]bool{}
		seenProj := map[string]bool{}
		for rows.Next() {
			var eco, name, version, adv, risk, fixed string
			var first time.Time
			var kev bool
			var epss *float64
			var pr queueProject
			if err := rows.Scan(&eco, &name, &version, &adv, &risk, &fixed, &first, &kev, &epss, &pr.ID, &pr.Name, &pr.Manifest, &pr.Direct); err != nil {
				return err
			}
			k := eco + "\x00" + name + "\x00" + version
			it := byKey[k]
			if it == nil {
				it = &queueItem{Ecosystem: eco, Name: name, Version: version, FirstSeen: first}
				byKey[k] = it
				items = append(items, it)
			}
			if first.Before(it.FirstSeen) {
				it.FirstSeen = first
			}
			if !seenAdv[k+"\x00"+adv] {
				seenAdv[k+"\x00"+adv] = true
				it.Advisories = append(it.Advisories, queueAdvisory{ID: adv, Risk: risk, FixedIn: fixed, KEV: kev})
				it.KEV = it.KEV || kev
				if riskOrderMap[risk] > riskOrderMap[it.Risk] {
					it.Risk = risk
				}
				if epss != nil && (it.EPSS == nil || *epss > *it.EPSS) {
					it.EPSS = epss
				}
				if fixed != "" {
					if it.FixedIn == "" {
						it.FixedIn = fixed
					} else if c, err := enrich.CompareVersions(enrich.OSVEcosystemName(eco), fixed, it.FixedIn); err == nil && c > 0 {
						it.FixedIn = fixed
					}
				}
			}
			if pk := k + "\x00" + pr.ID + "\x00" + pr.Manifest; !seenProj[pk] {
				seenProj[pk] = true
				it.Projects = append(it.Projects, pr)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	now := time.Now()
	var total float64
	sum := map[string]int{"overdue": 0, "due_soon": 0, "fixable": 0}
	for _, it := range items {
		var pts float64
		for _, a := range it.Advisories {
			pts += riskPoints[a.Risk]
		}
		projects := map[string]bool{}
		for _, p := range it.Projects {
			projects[p.ID] = true
		}
		it.Weight = pts * float64(len(projects))
		if it.KEV {
			it.Weight *= 2
		}
		total += it.Weight
		if d := sla.Days(it.Risk); d > 0 {
			due := it.FirstSeen.Add(time.Duration(d) * 24 * time.Hour)
			it.DueAt = &due
			it.Overdue = due.Before(now)
			if it.Overdue {
				sum["overdue"]++
			} else if due.Before(now.Add(7 * 24 * time.Hour)) {
				sum["due_soon"]++
			}
		}
		if it.FixedIn != "" {
			sum["fixable"]++
			it.Command = render.UpgradeCommand(it.Ecosystem, it.Name, it.FixedIn, it.Projects[0].Manifest)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Weight != items[j].Weight {
			return items[i].Weight > items[j].Weight
		}
		return items[i].Name < items[j].Name
	})
	var cum float64
	for _, it := range items {
		cum += it.Weight
		if total > 0 {
			it.Share = math.Round(cum/total*1000) / 10
		}
	}
	n := len(items)
	if n > 100 {
		items = items[:100]
	}
	if items == nil {
		items = []*queueItem{}
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": n, "total_weight": total, "summary": sum, "sla": sla})
}

func (s *Server) getSLA(w http.ResponseWriter, r *http.Request) error {
	var raw []byte
	err := s.tx(r, func(tx pgx.Tx) error { return tx.QueryRow(r.Context(), `SELECT sla FROM tenant_settings`).Scan(&raw) })
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return writeJSON(w, http.StatusOK, teamcfg.ParseSLA(raw))
}

func (s *Server) putSLA(w http.ResponseWriter, r *http.Request) error {
	set := teamcfg.DefaultSLA()
	if err := decode(w, r, jsonLimit, &set); err != nil {
		return err
	}
	if err := set.Validate(); err != nil {
		return badRequest("%v", err)
	}
	b, _ := json.Marshal(set)
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET sla=$1, updated_at=now()`, b)
		if err == nil && tag.RowsAffected() == 0 {
			return errf(http.StatusNotFound, "tenant not provisioned")
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.getSLA(w, r)
}
