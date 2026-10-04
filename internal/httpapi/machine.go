package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/jackc/pgx/v5"
)

// Upload caps for POST /v1/scans.
const (
	maxUploadFiles = 50
	maxUploadFile  = 10 << 20
	maxUploadTotal = 50 << 20
)

var sources = map[string]bool{"cli": true, "gitlab": true, "bitbucket": true, "github": true, "container": true}

// cleanRepoPath validates a lockfile path relative to the repository root.
func cleanRepoPath(p string) (string, error) {
	if p == "" || len(p) > 512 || strings.ContainsAny(p, "\\\x00") || strings.HasPrefix(p, "/") {
		return "", badRequest("invalid lockfile path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", badRequest("invalid lockfile path %q", p)
		}
	}
	c := path.Clean(p)
	if c == "." {
		return "", badRequest("invalid lockfile path %q", p)
	}
	return c, nil
}

type upload struct {
	path    string
	content []byte
}

func (s *Server) uploadScan(w http.ResponseWriter, r *http.Request) error {
	if s.d.Jobs == nil {
		return unavailable("job queue")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadTotal+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		return badRequest("multipart/form-data body required")
	}
	fields := map[string]string{}
	var files []upload
	seen := map[string]bool{}
	total := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return err
			}
			return badRequest("malformed multipart body")
		}
		switch name := part.FormName(); name {
		case "project", "version", "source", "project_license", "usage_model":
			b, err := io.ReadAll(io.LimitReader(part, 513))
			if err != nil {
				return err
			}
			if len(b) > 512 {
				return badRequest("%s too long", name)
			}
			fields[name] = strings.TrimSpace(string(b))
		case "lockfile":
			// part.FileName() strips directories; the repo path is the point here.
			_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			p, err := cleanRepoPath(params["filename"])
			if err != nil {
				return err
			}
			if seen[p] {
				return badRequest("duplicate lockfile path %q", p)
			}
			if len(files) == maxUploadFiles {
				return errf(http.StatusRequestEntityTooLarge, "at most %d lockfiles", maxUploadFiles)
			}
			b, err := io.ReadAll(io.LimitReader(part, maxUploadFile+1))
			if err != nil {
				return err
			}
			if len(b) > maxUploadFile {
				return errf(http.StatusRequestEntityTooLarge, "lockfile %q exceeds 10 MB", p)
			}
			if total += len(b); total > maxUploadTotal {
				return errf(http.StatusRequestEntityTooLarge, "upload exceeds 50 MB")
			}
			seen[p] = true
			files = append(files, upload{p, b})
		default:
			return badRequest("unexpected form field %q", name)
		}
	}
	project, version, source := fields["project"], fields["version"], fields["source"]
	if source == "" {
		source = "cli"
	}
	if version == "" {
		version = "main"
	}
	if project == "" || !sources[source] {
		return badRequest("project is required; source must be cli, gitlab, bitbucket, github or container")
	}
	if len(files) == 0 {
		return badRequest("at least one lockfile is required")
	}
	license, usage := fields["project_license"], fields["usage_model"]
	if license != "" && !validLicense(license) {
		return badRequest("project_license must be an SPDX expression such as MIT or Apache-2.0 OR MIT")
	}
	if usage != "" && !usageModels[usage] {
		return badRequest("usage_model must be internal, saas, distributed_binary or distributed_source")
	}
	tid := principal(r).TenantID
	scanID := ids.New()
	err = s.tx(r, func(tx pgx.Tx) error {
		ctx := r.Context()
		projectID, versionID, err := upsertProjectVersion(ctx, tx, tid, source, project, "", nil, version)
		if err != nil {
			return err
		}
		if license != "" || usage != "" {
			if _, err := tx.Exec(ctx, `UPDATE projects SET
				license = COALESCE(NULLIF($2, ''), license),
				license_source = CASE WHEN $2 <> '' THEN 'override' ELSE license_source END,
				usage_model = COALESCE(NULLIF($3, ''), usage_model) WHERE id = $1`, projectID, license, usage); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status)
			VALUES ($1,$2,$3,$4,'cli','queued')`, scanID, tid, projectID, versionID); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, f := range files {
			b.Queue(`INSERT INTO scan_uploads (tenant_id, scan_id, path, content) VALUES ($1,$2,$3,$4)`, tid, scanID, f.path, f.content)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		_, err = s.d.Jobs.InsertTx(ctx, tx, jobs.ScanUpload{TenantID: tid, ScanID: scanID}, s.d.JobOpts)
		return err
	})
	if err != nil {
		return err
	}
	if r.URL.Query().Get("wait") == "true" {
		return s.waitScan(w, r, scanID)
	}
	return s.writeMachineScan(w, r, scanID)
}

// ScanWaitTimeout bounds ?wait=true.
var ScanWaitTimeout = 120 * time.Second

func (s *Server) waitScan(w http.ResponseWriter, r *http.Request, scanID string) error {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(ScanWaitTimeout + 15*time.Second))
	deadline := time.Now().Add(ScanWaitTimeout)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for time.Now().Before(deadline) {
		var status string
		err := s.tx(r, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(), `SELECT status FROM scans WHERE id = $1`, scanID).Scan(&status)
		})
		if err != nil {
			return err
		}
		if status != "queued" && status != "running" {
			break
		}
		select {
		case <-r.Context().Done():
			return r.Context().Err()
		case <-t.C:
		}
	}
	return s.writeMachineScan(w, r, scanID)
}

func (s *Server) machineScan(r *http.Request, scanID string) (map[string]any, error) {
	var status string
	var conclusion, report *string
	err := s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT status, conclusion, report_md FROM scans WHERE id = $1`, scanID).Scan(&status, &conclusion, &report)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"scan_id": scanID, "status": status, "conclusion": conclusion, "report_md": report,
		"url": strings.TrimRight(s.d.PublicURL, "/") + "/scans/" + scanID}, nil
}

func (s *Server) writeMachineScan(w http.ResponseWriter, r *http.Request, scanID string) error {
	out, err := s.machineScan(r, scanID)
	if err != nil {
		return err
	}
	code := http.StatusOK
	if st := out["status"]; st == "queued" || st == "running" {
		code = http.StatusAccepted
	}
	return writeJSON(w, code, out)
}

func (s *Server) machineGetScan(w http.ResponseWriter, r *http.Request) error {
	return s.writeMachineScan(w, r, r.PathValue("id"))
}

// --------------------------------------------------------- endpoint ingest

var endpointTypes = map[string]bool{"developer": true, "ci": true, "agent_sandbox": true}

func (s *Server) checkin(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Identifier   string `json:"identifier"`
		EndpointType string `json:"endpoint_type"`
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		AgentVersion string `json:"agent_version"`
	}
	if err := decode(w, r, jsonLimit, &b); err != nil {
		return err
	}
	if b.EndpointType == "" {
		b.EndpointType = "developer"
	}
	if b.Identifier == "" || len(b.Identifier) > 200 || !endpointTypes[b.EndpointType] ||
		len(b.Hostname) > 255 || len(b.OS) > 100 || len(b.AgentVersion) > 100 {
		return badRequest("identifier required; endpoint_type must be developer, ci or agent_sandbox")
	}
	tid := principal(r).TenantID
	var id string
	err := s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `INSERT INTO endpoints (id, tenant_id, identifier, endpoint_type, hostname, os, agent_version, last_sync_at)
			VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),now())
			ON CONFLICT (tenant_id, identifier) DO UPDATE SET endpoint_type = EXCLUDED.endpoint_type,
			  hostname = EXCLUDED.hostname, os = EXCLUDED.os, agent_version = EXCLUDED.agent_version, last_sync_at = now()
			RETURNING id`, ids.New(), tid, b.Identifier, b.EndpointType, b.Hostname, b.OS, b.AgentVersion).Scan(&id)
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]string{"endpoint_id": id})
}

// touchEndpoint checks the endpoint belongs to the tenant and records a sync.
func touchEndpoint(ctx context.Context, tx pgx.Tx, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE endpoints SET last_sync_at = now() WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return errNotFound
	}
	return err
}

var inventoryKinds = map[string]bool{"coding_agent": true, "mcp_server": true, "agent_skill": true, "ide_extension": true, "cli_tool": true}

const maxIngestItems = 10000

func (s *Server) ingestInventory(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Items []struct {
			Kind       string          `json:"kind"`
			Name       string          `json:"name"`
			Version    string          `json:"version"`
			Scope      string          `json:"scope"`
			ConfigPath string          `json:"config_path"`
			Details    json.RawMessage `json:"details"`
		} `json:"items"`
	}
	if err := decode(w, r, ingestLimit, &body); err != nil {
		return err
	}
	if len(body.Items) > maxIngestItems {
		return errf(http.StatusRequestEntityTooLarge, "at most %d items", maxIngestItems)
	}
	for i, it := range body.Items {
		if !inventoryKinds[it.Kind] || it.Name == "" || len(it.Name) > 500 || len(it.ConfigPath) > 2000 {
			return badRequest("item %d: kind must be one of coding_agent, mcp_server, agent_skill, ide_extension, cli_tool and name is required", i)
		}
		if len(it.Details) == 0 || string(it.Details) == "null" {
			body.Items[i].Details = json.RawMessage(`{}`)
		} else if it.Details[0] != '{' {
			return badRequest("item %d: details must be an object", i)
		}
	}
	tid, eid := principal(r).TenantID, r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := touchEndpoint(ctx, tx, eid); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, it := range body.Items {
			b.Queue(`INSERT INTO inventory_items (id, tenant_id, endpoint_id, kind, name, version, scope, config_path, details)
				VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9)
				ON CONFLICT (endpoint_id, kind, name, config_path) DO UPDATE SET version = EXCLUDED.version,
				  scope = EXCLUDED.scope, details = EXCLUDED.details, last_seen = now()`,
				ids.New(), tid, eid, it.Kind, it.Name, it.Version, it.Scope, it.ConfigPath, it.Details)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		// Replace semantics: everything not seen in this transaction is gone.
		_, err := tx.Exec(ctx, `DELETE FROM inventory_items WHERE endpoint_id = $1 AND last_seen < now()`, eid)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]int{"items": len(body.Items)})
}

// pmgEvent is a line of pmg's event log (pmg/internal/eventlog.Event).
type pmgEvent struct {
	Timestamp   time.Time      `json:"timestamp"`
	EventType   string         `json:"event_type"`
	Message     string         `json:"message"`
	PackageName string         `json:"package_name"`
	Version     string         `json:"version"`
	Ecosystem   string         `json:"ecosystem"`
	Details     map[string]any `json:"details"`
}

func (s *Server) ingestPMG(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, ingestLimit))
	if err != nil {
		return err
	}
	var events []pmgEvent
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), ingestLimit)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e pmgEvent
		if err := json.Unmarshal(line, &e); err != nil || e.EventType == "" || e.Timestamp.IsZero() {
			return badRequest("line %d: invalid pmg event (timestamp and event_type required)", n)
		}
		if e.Details == nil {
			e.Details = map[string]any{}
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return badRequest("invalid JSONL: %v", err)
	}
	if len(events) > maxIngestItems {
		return errf(http.StatusRequestEntityTooLarge, "at most %d events", maxIngestItems)
	}
	tid, eid := principal(r).TenantID, r.PathValue("id")
	err = s.tx(r, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := touchEndpoint(ctx, tx, eid); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, e := range events {
			b.Queue(`INSERT INTO package_guard_events (tenant_id, endpoint_id, ts, event_type, ecosystem, package_name, version, message, details)
				VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),$9)`,
				tid, eid, e.Timestamp, e.EventType, e.Ecosystem, e.PackageName, e.Version, e.Message, e.Details)
		}
		return tx.SendBatch(ctx, b).Close()
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]int{"inserted": len(events)})
}

// gryphEvent holds the indexed fields of a gryph event (schema/event.schema.json);
// the whole event is kept as payload.
type gryphEvent struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	Timestamp    time.Time `json:"timestamp"`
	AgentName    string    `json:"agent_name"`
	ActionType   string    `json:"action_type"`
	ResultStatus string    `json:"result_status"`
	ToolName     string    `json:"tool_name"`
	IsSensitive  bool      `json:"is_sensitive"`
}

// ingestAgentEvents accepts a JSON array (contract) or JSONL (gryph export output).
func (s *Server) ingestAgentEvents(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, ingestLimit))
	if err != nil {
		return err
	}
	var raws []json.RawMessage
	if t := bytes.TrimSpace(body); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &raws); err != nil {
			return badRequest("invalid JSON array: %v", err)
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(body))
		for {
			var m json.RawMessage
			if err := dec.Decode(&m); err == io.EOF {
				break
			} else if err != nil {
				return badRequest("invalid JSONL: %v", err)
			}
			raws = append(raws, m)
		}
	}
	if len(raws) > maxIngestItems {
		return errf(http.StatusRequestEntityTooLarge, "at most %d events", maxIngestItems)
	}
	events := make([]gryphEvent, len(raws))
	for i, raw := range raws {
		e := &events[i]
		if err := json.Unmarshal(raw, e); err != nil || e.ID == "" || e.SessionID == "" || e.Timestamp.IsZero() ||
			e.AgentName == "" || e.ActionType == "" || e.ResultStatus == "" || len(e.ID) > 100 {
			return badRequest("event %d: id, session_id, timestamp, agent_name, action_type, result_status are required", i)
		}
	}
	tid, eid := principal(r).TenantID, r.PathValue("id")
	inserted := 0
	err = s.tx(r, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := touchEndpoint(ctx, tx, eid); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for i, e := range events {
			b.Queue(`INSERT INTO agent_events (id, tenant_id, endpoint_id, session_id, ts, agent_name, action_type, result_status, tool_name, is_sensitive, payload)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11) ON CONFLICT (id) DO NOTHING`,
				e.ID, tid, eid, e.SessionID, e.Timestamp, e.AgentName, e.ActionType, e.ResultStatus, e.ToolName, e.IsSensitive, raws[i])
		}
		br := tx.SendBatch(ctx, b)
		for range events {
			tag, err := br.Exec()
			if err != nil {
				br.Close()
				return err
			}
			inserted += int(tag.RowsAffected())
		}
		return br.Close()
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]int{"inserted": inserted, "duplicates": len(events) - inserted})
}

// ------------------------------------------------------- endpoints (web)

const endpointInner = `SELECT e.id, e.identifier, e.endpoint_type, e.hostname, e.os, e.agent_version, e.last_sync_at, e.created_at,
  (SELECT count(*) FROM inventory_items i WHERE i.endpoint_id = e.id) AS inventory_count FROM endpoints e`

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", endpointInner,
		filterSpec{eq: map[string]string{"endpoint_type": "t.endpoint_type"}, ilike: map[string]string{"hostname": "t.hostname"}},
		"t.last_sync_at DESC NULLS LAST, t.id", nil)(w, r)
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT to_jsonb(t) FROM (`+endpointInner+`) t WHERE t.id = $1`, r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func byEndpoint(r *http.Request, w *where) error {
	w.add("t.endpoint_id = ?", r.PathValue("id"))
	return nil
}

func (s *Server) endpointInventory(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `SELECT id, endpoint_id, kind, name, version, scope, config_path, details, first_seen, last_seen FROM inventory_items`,
		filterSpec{eq: map[string]string{"kind": "t.kind"}, ilike: map[string]string{"name": "t.name"}},
		"t.kind, t.name, t.id", byEndpoint, "endpoint_id")(w, r)
}

func (s *Server) endpointPackageEvents(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `SELECT id, endpoint_id, ts, event_type, ecosystem, package_name, version, message, details FROM package_guard_events`,
		filterSpec{eq: map[string]string{"event_type": "t.event_type", "ecosystem": "t.ecosystem"}, ilike: map[string]string{"name": "t.package_name"}, dateCol: "t.ts"},
		"t.ts DESC, t.id DESC", byEndpoint, "endpoint_id")(w, r)
}

func (s *Server) endpointAgentEvents(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `SELECT id, endpoint_id, session_id, ts, agent_name, action_type, result_status, tool_name, is_sensitive, payload FROM agent_events`,
		filterSpec{eq: map[string]string{"agent_name": "t.agent_name", "action_type": "t.action_type", "result_status": "t.result_status", "session_id": "t.session_id"}, dateCol: "t.ts"},
		"t.ts DESC, t.id", byEndpoint, "endpoint_id")(w, r)
}
