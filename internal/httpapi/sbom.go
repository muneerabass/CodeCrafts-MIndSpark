package httpapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/depguard/depguard/internal/sbom"
	"github.com/jackc/pgx/v5"
)

// projectSBOM exports the current inventory of a project version as CycloneDX
// or SPDX JSON. The web uses /projects/{id}/sbom?version=; CI uses
// /v1/sbom?project=<name>&branch= with an API key.
func (s *Server) projectSBOM(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "cyclonedx"
	}
	if format != "cyclonedx" && format != "spdx" {
		return badRequest("format must be cyclonedx or spdx")
	}
	if r.PathValue("id") == "" && q.Get("project") == "" {
		return badRequest("project is required (the project name, e.g. acme/web)")
	}
	var d sbom.Doc
	var versionID string
	err := s.tx(r, func(tx pgx.Tx) error {
		var scanID *string
		var updated time.Time
		err := tx.QueryRow(r.Context(), `SELECT pv.id, pv.name, p.name, pv.last_scan_id, pv.updated_at
			FROM project_versions pv JOIN projects p ON p.id = pv.project_id
			WHERE (p.id = $1 OR ($1 = '' AND p.name = $2)) AND ($3 = '' OR pv.id = $3 OR pv.name = $3)
			ORDER BY (pv.last_scan_id IS NULL), pv.updated_at DESC LIMIT 1`,
			r.PathValue("id"), q.Get("project"), firstNonEmpty(q.Get("version"), q.Get("branch"))).Scan(&versionID, &d.Version, &d.Project, &scanID, &updated)
		if err != nil {
			return err
		}
		d.Serial, d.Created = versionID, time.Now()
		if scanID != nil {
			d.Serial = *scanID
		}
		rows, err := tx.Query(r.Context(), `SELECT c.id, c.ecosystem, c.name, c.version, c.purl, COALESCE(c.licenses, '{}'),
			bool_or(COALESCE(pvc.direct, false)), bool_and(COALESCE(pvc.dev, false)), array_agg(DISTINCT pvc.manifest_path ORDER BY pvc.manifest_path)
			FROM project_version_components pvc JOIN components c ON c.id = pvc.component_id
			WHERE pvc.project_version_id = $1 GROUP BY c.id ORDER BY c.ecosystem, c.name, c.version`, versionID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var c sbom.Component
			if err := rows.Scan(&c.ID, &c.Ecosystem, &c.Name, &c.Version, &c.PURL, &c.Licenses, &c.Direct, &c.Dev, &c.Manifests); err != nil {
				rows.Close()
				return err
			}
			d.Components = append(d.Components, c)
		}
		rows.Close()
		rows, err = tx.Query(r.Context(), `SELECT DISTINCT COALESCE(parent_component_id, ''), child_component_id
			FROM project_version_dependencies WHERE project_version_id = $1`, versionID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e sbom.Edge
			if err := rows.Scan(&e.Parent, &e.Child); err != nil {
				rows.Close()
				return err
			}
			d.Edges = append(d.Edges, e)
		}
		rows.Close()
		rows, err = tx.Query(r.Context(), `SELECT DISTINCT cv.component_id, cv.advisory_id, cv.risk, COALESCE(cv.fixed_in, '')
			FROM component_vulnerabilities cv JOIN project_version_components pvc ON pvc.component_id = cv.component_id
			WHERE pvc.project_version_id = $1 ORDER BY 2, 1`, versionID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v sbom.Vuln
			if err := rows.Scan(&v.ComponentID, &v.ID, &v.Risk, &v.FixedIn); err != nil {
				return err
			}
			d.Vulns = append(d.Vulns, v)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	var b []byte
	ext := "cdx.json"
	if format == "spdx" {
		b, err = sbom.SPDX(d)
		ext = "spdx.json"
	} else {
		b, err = sbom.CycloneDX(d)
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, safeFilename(d.Project), safeFilename(d.Version), ext))
	_, err = w.Write(b)
	return err
}
