package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/depguard/depguard/internal/engine"
	"github.com/depguard/depguard/internal/scan"
)

const checkLimit = 40 << 20 // lockfiles before/after plus manifests

// checkPackages is the pre-install verdict used by `depguard <npm|pip|go|cargo> ...`.
func (s *Server) checkPackages(w http.ResponseWriter, r *http.Request) error {
	if s.d.CheckPackages == nil {
		return unavailable("package checks")
	}
	var req engine.CheckRequest
	if err := decode(w, r, checkLimit, &req); err != nil {
		return err
	}
	if len(req.Packages) == 0 && len(req.After) == 0 {
		return badRequest("packages or lockfiles (after) required")
	}
	res, err := s.d.CheckPackages(r.Context(), principal(r).TenantID, req)
	if err != nil {
		if errors.Is(err, r.Context().Err()) {
			return err
		}
		return badRequest("%v", err)
	}
	if res.Packages == nil {
		res.Packages = []engine.CheckVerdict{}
	}
	return writeJSON(w, http.StatusOK, res)
}

// me identifies the API key's tenant and summarises its policy (depguard login/init).
func (s *Server) me(w http.ResponseWriter, r *http.Request) error {
	var domain string
	var blockMode bool
	var raw []byte
	err := s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT domain, block_mode, policy FROM tenant_settings`).Scan(&domain, &blockMode, &raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errf(http.StatusNotFound, "tenant not provisioned")
	}
	if err != nil {
		return err
	}
	pc, _ := scan.ParsePolicy(raw)
	summary := map[string]any{"vulnerability_min_risk": "HIGH", "malware": true, "package_rules": 0, "custom_rules": len(pc.Custom)}
	if pc.Presets != nil {
		summary["vulnerability_min_risk"] = pc.Presets.Vulnerability.MinRisk
		summary["malware"] = pc.Presets.Malware.Enabled
		summary["package_rules"] = len(pc.Presets.Packages)
	}
	p := principal(r)
	return writeJSON(w, http.StatusOK, map[string]any{"tenant_id": p.TenantID, "domain": domain, "block_mode": blockMode,
		"api_key_id": p.APIKeyID, "policy": json.RawMessage(mustJSON(summary))})
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
