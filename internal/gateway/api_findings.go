package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/findings"
)

// --- Row/request types ---

type findingPathIgnoreRuleRow struct {
	ID        int64  `db:"id" json:"id"`
	Substring string `db:"substring" json:"substring"`
	Enabled   bool   `db:"enabled" json:"enabled"`
	Note      string `db:"note" json:"note"`
	CreatedAt string `db:"created_at" json:"created_at"`
	UpdatedAt string `db:"updated_at" json:"updated_at"`
}

type findingPathIgnoreRuleUpsertRequest struct {
	Substring string `json:"substring"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Note      string `json:"note"`
}

type jobUnifiedFinding struct {
	ID           int64  `json:"id"`
	ScanJobID    int64  `json:"scan_job_id"`
	Kind         string `json:"kind"`
	Scanner      string `json:"scanner,omitempty"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	FilePath     string `json:"file_path"`
	Line         int    `json:"line,omitempty"`
	Message      string `json:"message,omitempty"`
	Package      string `json:"package,omitempty"`
	Version      string `json:"version,omitempty"`
	Fix          string `json:"fix,omitempty"`
	Status       string `json:"status"`
	FirstSeen    string `json:"first_seen"`
	Introduced   bool   `json:"introduced,omitempty"`
	Reintroduced bool   `json:"reintroduced,omitempty"`
}

// findingRow is a unified view row across sca/sast/secrets/iac tables.
type findingRow struct {
	ID        int64  `db:"id"          json:"id"`
	ScanJobID int64  `db:"scan_job_id" json:"scan_job_id"`
	Kind      string `db:"-"           json:"kind"`
	Severity  string `db:"severity"    json:"severity"`
	Title     string `db:"title"       json:"title"`
	FilePath  string `db:"file_path"   json:"file_path"`
	Status    string `db:"status"      json:"status"`
	FirstSeen string `db:"first_seen"  json:"first_seen"`
}

// --- Path-ignore schema helpers ---

func (gw *Gateway) ensureFindingIgnoreSchema(ctx context.Context) error {
	return gw.db.Migrate(ctx)
}

func (gw *Gateway) loadEnabledPathIgnoreSubstrings(ctx context.Context) []string {
	_ = gw.ensureFindingIgnoreSchema(ctx)
	var rows []struct {
		Substring string `db:"substring"`
	}
	if err := gw.db.Select(ctx, &rows, `SELECT substring FROM finding_path_ignore_rules WHERE enabled = 1 ORDER BY id ASC`); err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		s := strings.ToLower(strings.TrimSpace(r.Substring))
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func shouldIgnoreFindingPath(path string, rules []string) bool {
	if len(rules) == 0 {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(path, "\\", "/")))
	if p == "" {
		return false
	}
	for _, sub := range rules {
		if sub == "" {
			continue
		}
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// --- Findings handlers ---

func (gw *Gateway) handleListJobFindings(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	kind := q.Get("kind")
	scanner := strings.TrimSpace(q.Get("scanner"))
	severity := strings.TrimSpace(q.Get("severity"))
	titleFilter := strings.ToLower(strings.TrimSpace(q.Get("title")))
	pathFilter := strings.ToLower(strings.TrimSpace(q.Get("path")))
	searchQ := strings.ToLower(strings.TrimSpace(q.Get("q")))
	status := strings.TrimSpace(q.Get("status"))
	pg := parsePaginationParams(r, 25, 500)
	if status == "" {
		status = "open"
	}

	var results []jobUnifiedFinding
	addFilter := func(base string) string {
		var clauses []string
		clauses = append(clauses, fmt.Sprintf("scan_job_id = %d", id))
		if severity != "" {
			clauses = append(clauses, "severity = '"+strings.ReplaceAll(severity, "'", "")+"'")
		}
		if status != "" {
			clauses = append(clauses, "status = '"+strings.ReplaceAll(status, "'", "")+"'")
		}
		return base + " WHERE " + strings.Join(clauses, " AND ")
	}

	// Prefer unified normalized findings persisted at scan time when available.
	// Fall back to legacy per-table rows and finally raw-output parsing.
	{
		sqlq := `SELECT id, scan_job_id, kind, scanner, severity, title, file_path, line, message,
			                package_name, package_version, fix_hint, status, first_seen_at, introduced, reintroduced
			         FROM scan_job_findings WHERE scan_job_id = ?`
		args := []any{id}
		if kind != "" {
			sqlq += ` AND kind = ?`
			args = append(args, kind)
		}
		if scanner != "" {
			sqlq += ` AND scanner = ?`
			args = append(args, scanner)
		}
		if severity != "" {
			sqlq += ` AND severity = ?`
			args = append(args, severity)
		}
		if status != "" {
			sqlq += ` AND status = ?`
			args = append(args, status)
		}
		sqlq += ` ORDER BY id DESC`
		type row struct {
			ID           int64  `db:"id"`
			ScanJobID    int64  `db:"scan_job_id"`
			Kind         string `db:"kind"`
			Scanner      string `db:"scanner"`
			Severity     string `db:"severity"`
			Title        string `db:"title"`
			FilePath     string `db:"file_path"`
			Line         int    `db:"line"`
			Message      string `db:"message"`
			Package      string `db:"package_name"`
			Version      string `db:"package_version"`
			Fix          string `db:"fix_hint"`
			Status       string `db:"status"`
			FirstSeen    string `db:"first_seen_at"`
			Introduced   int    `db:"introduced"`
			Reintroduced int    `db:"reintroduced"`
		}
		var rows []row
		if err := gw.db.Select(ctx, &rows, sqlq, args...); err == nil && len(rows) > 0 {
			for _, r := range rows {
				results = append(results, jobUnifiedFinding{
					ID: r.ID, ScanJobID: r.ScanJobID, Kind: r.Kind, Scanner: r.Scanner,
					Severity: r.Severity, Title: r.Title, FilePath: r.FilePath, Line: r.Line,
					Message: r.Message, Package: r.Package, Version: r.Version, Fix: r.Fix,
					Status: r.Status, FirstSeen: r.FirstSeen,
					Introduced: r.Introduced != 0, Reintroduced: r.Reintroduced != 0,
				})
			}
		}
	}

	if len(results) == 0 && (kind == "" || kind == "sca") {
		type row struct {
			ID        int64  `db:"id"`
			ScanJobID int64  `db:"scan_job_id"`
			Severity  string `db:"severity"`
			Title     string `db:"vulnerability_id"`
			FilePath  string `db:"package_name"`
			Status    string `db:"status"`
			FirstSeen string `db:"first_seen_at"`
		}
		var rows []row
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, vulnerability_id, package_name, status, first_seen_at FROM sca_vulns")+" ORDER BY id DESC")
		for _, row := range rows {
			results = append(results, jobUnifiedFinding{ID: row.ID, ScanJobID: row.ScanJobID, Kind: "sca", Scanner: "grype", Severity: row.Severity, Title: row.Title, FilePath: row.FilePath, Package: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen})
		}
	}
	if len(results) == 0 && (kind == "" || kind == "sast") {
		type row struct {
			ID        int64  `db:"id"`
			ScanJobID int64  `db:"scan_job_id"`
			Severity  string `db:"severity"`
			Title     string `db:"check_id"`
			FilePath  string `db:"file_path"`
			Status    string `db:"status"`
			FirstSeen string `db:"first_seen_at"`
		}
		var rows []row
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, check_id, file_path, status, first_seen_at FROM sast_findings")+" ORDER BY id DESC")
		for _, row := range rows {
			results = append(results, jobUnifiedFinding{ID: row.ID, ScanJobID: row.ScanJobID, Kind: "sast", Scanner: "opengrep", Severity: row.Severity, Title: row.Title, FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen})
		}
	}
	if len(results) == 0 && (kind == "" || kind == "secrets") {
		type row struct {
			ID        int64  `db:"id"`
			ScanJobID int64  `db:"scan_job_id"`
			Severity  string `db:"severity"`
			Title     string `db:"detector_name"`
			FilePath  string `db:"file_path"`
			Status    string `db:"status"`
			FirstSeen string `db:"first_seen_at"`
		}
		var rows []row
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, detector_name, file_path, status, first_seen_at FROM secrets_findings")+" ORDER BY id DESC")
		for _, row := range rows {
			results = append(results, jobUnifiedFinding{ID: row.ID, ScanJobID: row.ScanJobID, Kind: "secrets", Scanner: "trufflehog", Severity: row.Severity, Title: row.Title, FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen})
		}
	}
	if len(results) == 0 && (kind == "" || kind == "iac") {
		type row struct {
			ID        int64  `db:"id"`
			ScanJobID int64  `db:"scan_job_id"`
			Severity  string `db:"severity"`
			Title     string `db:"title"`
			FilePath  string `db:"file_path"`
			Status    string `db:"status"`
			FirstSeen string `db:"first_seen_at"`
		}
		var rows []row
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, title, file_path, status, first_seen_at FROM iac_findings")+" ORDER BY id DESC")
		for _, row := range rows {
			results = append(results, jobUnifiedFinding{ID: row.ID, ScanJobID: row.ScanJobID, Kind: "iac", Scanner: "trivy", Severity: row.Severity, Title: row.Title, FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen})
		}
	}
	if len(results) == 0 {
		if parsed, err := gw.loadFindingsFromRawOutputs(ctx, id); err == nil && len(parsed) > 0 {
			results = parsed
		}
	}
	if rules := gw.loadEnabledPathIgnoreSubstrings(ctx); len(rules) > 0 {
		filtered := make([]jobUnifiedFinding, 0, len(results))
		for _, f := range results {
			if shouldIgnoreFindingPath(firstNonEmpty(f.FilePath, f.Package), rules) {
				continue
			}
			filtered = append(filtered, f)
		}
		results = filtered
	}
	if titleFilter != "" || pathFilter != "" || searchQ != "" {
		filtered := make([]jobUnifiedFinding, 0, len(results))
		for _, f := range results {
			titleVal := strings.ToLower(strings.TrimSpace(f.Title))
			pathVal := strings.ToLower(strings.TrimSpace(firstNonEmpty(f.FilePath, f.Package)))
			if titleFilter != "" && !strings.Contains(titleVal, titleFilter) {
				continue
			}
			if pathFilter != "" && !strings.Contains(pathVal, pathFilter) {
				continue
			}
			if searchQ != "" {
				hay := strings.ToLower(strings.Join([]string{
					f.Kind,
					f.Scanner,
					f.Severity,
					f.Title,
					f.FilePath,
					f.Package,
					f.Version,
					f.Message,
					f.Fix,
				}, " "))
				if !strings.Contains(hay, searchQ) {
					continue
				}
			}
			filtered = append(filtered, f)
		}
		results = filtered
	}
	if len(results) > 0 && scanner != "" {
		filtered := make([]jobUnifiedFinding, 0, len(results))
		for _, f := range results {
			if strings.EqualFold(strings.TrimSpace(f.Scanner), scanner) {
				filtered = append(filtered, f)
			}
		}
		results = filtered
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].ID == results[j].ID {
			return results[i].Title > results[j].Title
		}
		return results[i].ID > results[j].ID
	})
	if results == nil {
		results = []jobUnifiedFinding{}
	}
	type findingFacets struct {
		Kinds      []string `json:"kinds"`
		Scanners   []string `json:"scanners"`
		Severities []string `json:"severities"`
	}
	type findingSeverityTotals struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	}
	kindSet := map[string]struct{}{}
	scannerSet := map[string]struct{}{}
	sevSet := map[string]struct{}{}
	sevTotals := findingSeverityTotals{}
	for _, f := range results {
		if k := strings.TrimSpace(f.Kind); k != "" {
			kindSet[k] = struct{}{}
		}
		if s := strings.TrimSpace(f.Scanner); s != "" {
			scannerSet[s] = struct{}{}
		}
		if s := normalizeFindingSeverityBucket(f.Severity); s != "" {
			sevSet[s] = struct{}{}
			switch s {
			case "CRITICAL":
				sevTotals.Critical++
			case "HIGH":
				sevTotals.High++
			case "MEDIUM":
				sevTotals.Medium++
			case "LOW":
				sevTotals.Low++
			}
		}
	}
	toSorted := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	facets := findingFacets{
		Kinds:      toSorted(kindSet),
		Scanners:   toSorted(scannerSet),
		Severities: toSorted(sevSet),
	}
	// Severity sort order should be human-readable, not alpha.
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.Slice(facets.Severities, func(i, j int) bool {
		ai, aok := order[facets.Severities[i]]
		aj, bok := order[facets.Severities[j]]
		if aok && bok {
			return ai < aj
		}
		if aok != bok {
			return aok
		}
		return facets.Severities[i] < facets.Severities[j]
	})
	total := len(results)
	totalPages := 1
	if total > 0 {
		totalPages = (total + pg.PageSize - 1) / pg.PageSize
	}
	start := pg.Offset
	if start > total {
		start = total
	}
	end := start + pg.PageSize
	if end > total {
		end = total
	}
	pageItems := results[start:end]
	if pageItems == nil {
		pageItems = []jobUnifiedFinding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           pageItems,
		"page":            pg.Page,
		"page_size":       pg.PageSize,
		"total":           total,
		"total_pages":     totalPages,
		"facets":          facets,
		"severity_totals": sevTotals,
	})
}

func normalizeFindingSeverityBucket(v string) string {
	s := strings.ToUpper(strings.TrimSpace(v))
	switch s {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH", "ERROR":
		return "HIGH"
	case "MEDIUM", "WARNING", "WARN":
		return "MEDIUM"
	case "LOW", "INFO":
		return "LOW"
	default:
		return s
	}
}

func (gw *Gateway) handleListFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	kind := q.Get("kind") // sca | sast | secrets | iac
	severity := q.Get("severity")
	status := q.Get("status")
	if status == "" {
		status = "open"
	}

	type scaRow struct {
		ID        int64  `db:"id"           json:"id"`
		ScanJobID int64  `db:"scan_job_id"  json:"scan_job_id"`
		Severity  string `db:"severity"     json:"severity"`
		Title     string `db:"vulnerability_id" json:"title"`
		FilePath  string `db:"package_name" json:"file_path"`
		Status    string `db:"status"       json:"status"`
		FirstSeen string `db:"first_seen_at" json:"first_seen"`
	}
	type sastRow struct {
		ID        int64  `db:"id"           json:"id"`
		ScanJobID int64  `db:"scan_job_id"  json:"scan_job_id"`
		Severity  string `db:"severity"     json:"severity"`
		Title     string `db:"check_id"     json:"title"`
		FilePath  string `db:"file_path"    json:"file_path"`
		Status    string `db:"status"       json:"status"`
		FirstSeen string `db:"first_seen_at" json:"first_seen"`
	}
	type secretsRow struct {
		ID        int64  `db:"id"              json:"id"`
		ScanJobID int64  `db:"scan_job_id"     json:"scan_job_id"`
		Severity  string `db:"severity"        json:"severity"`
		Title     string `db:"detector_name"   json:"title"`
		FilePath  string `db:"file_path"       json:"file_path"`
		Status    string `db:"status"          json:"status"`
		FirstSeen string `db:"first_seen_at"   json:"first_seen"`
	}
	type iacRow struct {
		ID        int64  `db:"id"           json:"id"`
		ScanJobID int64  `db:"scan_job_id"  json:"scan_job_id"`
		Severity  string `db:"severity"     json:"severity"`
		Title     string `db:"title"        json:"title"`
		FilePath  string `db:"file_path"    json:"file_path"`
		Status    string `db:"status"       json:"status"`
		FirstSeen string `db:"first_seen_at" json:"first_seen"`
	}

	type unifiedFinding struct {
		ID        int64  `json:"id"`
		ScanJobID int64  `json:"scan_job_id"`
		Kind      string `json:"kind"`
		Severity  string `json:"severity"`
		Title     string `json:"title"`
		FilePath  string `json:"file_path"`
		Status    string `json:"status"`
		FirstSeen string `json:"first_seen"`
	}

	var results []unifiedFinding

	addWhere := func(base, sevCol, statusCol string) string {
		var clauses []string
		if severity != "" {
			clauses = append(clauses, sevCol+" = '"+strings.ReplaceAll(severity, "'", "")+"'")
		}
		if status != "" {
			clauses = append(clauses, statusCol+" = '"+strings.ReplaceAll(status, "'", "")+"'")
		}
		if len(clauses) > 0 {
			return base + " WHERE " + strings.Join(clauses, " AND ")
		}
		return base
	}

	if kind == "" || kind == "sca" {
		var rows []scaRow
		q := addWhere("SELECT id, scan_job_id, severity, vulnerability_id, package_name, status, first_seen_at FROM sca_vulns", "severity", "status")
		_ = gw.db.Select(ctx, &rows, q+" LIMIT 200")
		for _, row := range rows {
			results = append(results, unifiedFinding{
				ID: row.ID, ScanJobID: row.ScanJobID, Kind: "sca",
				Severity: row.Severity, Title: row.Title,
				FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen,
			})
		}
	}
	if kind == "" || kind == "sast" {
		var rows []sastRow
		q := addWhere("SELECT id, scan_job_id, severity, check_id, file_path, status, first_seen_at FROM sast_findings", "severity", "status")
		_ = gw.db.Select(ctx, &rows, q+" LIMIT 200")
		for _, row := range rows {
			results = append(results, unifiedFinding{
				ID: row.ID, ScanJobID: row.ScanJobID, Kind: "sast",
				Severity: row.Severity, Title: row.Title,
				FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen,
			})
		}
	}
	if kind == "" || kind == "secrets" {
		var rows []secretsRow
		q := addWhere("SELECT id, scan_job_id, severity, detector_name, file_path, status, first_seen_at FROM secrets_findings", "severity", "status")
		_ = gw.db.Select(ctx, &rows, q+" LIMIT 200")
		for _, row := range rows {
			results = append(results, unifiedFinding{
				ID: row.ID, ScanJobID: row.ScanJobID, Kind: "secrets",
				Severity: row.Severity, Title: row.Title,
				FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen,
			})
		}
	}
	if kind == "" || kind == "iac" {
		var rows []iacRow
		q := addWhere("SELECT id, scan_job_id, severity, title, file_path, status, first_seen_at FROM iac_findings", "severity", "status")
		_ = gw.db.Select(ctx, &rows, q+" LIMIT 200")
		for _, row := range rows {
			results = append(results, unifiedFinding{
				ID: row.ID, ScanJobID: row.ScanJobID, Kind: "iac",
				Severity: row.Severity, Title: row.Title,
				FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen,
			})
		}
	}

	if results == nil {
		results = []unifiedFinding{}
	}
	writeJSON(w, http.StatusOK, results)
}

// --- Path-ignore rule handlers ---

func (gw *Gateway) handleListFindingPathIgnores(w http.ResponseWriter, r *http.Request) {
	if err := gw.ensureFindingIgnoreSchema(r.Context()); err != nil {
		slog.Warn("Failed ensuring finding path ignore schema", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to prepare finding path ignore schema")
		return
	}
	var rows []findingPathIgnoreRuleRow
	if err := gw.db.Select(r.Context(), &rows, `SELECT id, substring, enabled, note, created_at, updated_at FROM finding_path_ignore_rules ORDER BY id ASC`); err != nil {
		slog.Warn("Failed to list finding path ignore rules", "error", err)
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []findingPathIgnoreRuleRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleCreateFindingPathIgnore(w http.ResponseWriter, r *http.Request) {
	if err := gw.ensureFindingIgnoreSchema(r.Context()); err != nil {
		slog.Warn("Failed ensuring finding path ignore schema", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to prepare finding path ignore schema")
		return
	}
	var req findingPathIgnoreRuleUpsertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sub := strings.TrimSpace(strings.ReplaceAll(req.Substring, "\\", "/"))
	if sub == "" {
		writeError(w, http.StatusBadRequest, "substring is required")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	rec := struct {
		Substring string `db:"substring"`
		Enabled   bool   `db:"enabled"`
		Note      string `db:"note"`
		CreatedAt string `db:"created_at"`
		UpdatedAt string `db:"updated_at"`
	}{
		Substring: sub,
		Enabled:   enabled,
		Note:      strings.TrimSpace(req.Note),
		CreatedAt: now,
		UpdatedAt: now,
	}
	id, err := gw.db.Insert(r.Context(), "finding_path_ignore_rules", rec)
	if err != nil {
		slog.Warn("Failed to create finding path ignore rule", "error", err)
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, http.StatusConflict, "substring already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (gw *Gateway) handleUpdateFindingPathIgnore(w http.ResponseWriter, r *http.Request) {
	if err := gw.ensureFindingIgnoreSchema(r.Context()); err != nil {
		slog.Warn("Failed ensuring finding path ignore schema", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to prepare finding path ignore schema")
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req findingPathIgnoreRuleUpsertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sub := strings.TrimSpace(strings.ReplaceAll(req.Substring, "\\", "/"))
	if sub == "" {
		writeError(w, http.StatusBadRequest, "substring is required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if err := gw.db.Exec(r.Context(),
		`UPDATE finding_path_ignore_rules SET substring = ?, enabled = ?, note = ?, updated_at = ? WHERE id = ?`,
		sub, enabled, strings.TrimSpace(req.Note), time.Now().UTC().Format(time.RFC3339), id,
	); err != nil {
		slog.Warn("Failed to update finding path ignore rule", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "updated"})
}

func (gw *Gateway) handleDeleteFindingPathIgnore(w http.ResponseWriter, r *http.Request) {
	if err := gw.ensureFindingIgnoreSchema(r.Context()); err != nil {
		slog.Warn("Failed ensuring finding path ignore schema", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to prepare finding path ignore schema")
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.db.Exec(r.Context(), `DELETE FROM finding_path_ignore_rules WHERE id = ?`, id); err != nil {
		slog.Warn("Failed to delete finding path ignore rule", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Raw output parsers ---

func (gw *Gateway) loadFindingsFromRawOutputs(ctx context.Context, scanJobID int64) ([]jobUnifiedFinding, error) {
	type rawRow struct {
		ScannerName string `db:"scanner_name"`
		RawOutput   []byte `db:"raw_output"`
	}
	var raws []rawRow
	if err := gw.db.Select(ctx, &raws, `SELECT scanner_name, raw_output FROM scan_job_raw_outputs WHERE scan_job_id = ?`, scanJobID); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var out []jobUnifiedFinding
	for _, rr := range raws {
		parsed := findings.ParseRawScannerOutput(rr.ScannerName, rr.RawOutput)
		for i, f := range parsed {
			out = append(out, jobUnifiedFinding{
				ID:        int64(i + 1),
				ScanJobID: scanJobID,
				Kind:      f.Kind,
				Scanner:   f.Scanner,
				Severity:  f.Severity,
				Title:     f.Title,
				FilePath:  f.FilePath,
				Line:      f.Line,
				Message:   f.Message,
				Package:   f.Package,
				Version:   f.Version,
				Fix:       f.Fix,
				Status:    firstNonEmpty(f.Status, "open"),
				FirstSeen: now,
			})
		}
	}
	return out, nil
}

func parseOpengrepRawFindings(scanJobID int64, data []byte, firstSeen string) []jobUnifiedFinding {
	var payload struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	out := make([]jobUnifiedFinding, 0, len(payload.Results))
	for i, r := range payload.Results {
		out = append(out, jobUnifiedFinding{
			ID:        int64(i + 1),
			ScanJobID: scanJobID,
			Kind:      "sast",
			Scanner:   "opengrep",
			Severity:  strings.ToUpper(strings.TrimSpace(r.Extra.Severity)),
			Title:     r.CheckID,
			FilePath:  normalizeRepoRelativePath(r.Path),
			Line:      r.Start.Line,
			Message:   r.Extra.Message,
			Status:    "open",
			FirstSeen: firstSeen,
		})
	}
	return out
}

func parseGrypeRawFindings(scanJobID int64, data []byte, firstSeen string) []jobUnifiedFinding {
	var payload struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	out := make([]jobUnifiedFinding, 0, len(payload.Matches))
	for i, m := range payload.Matches {
		fix := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fix = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		filePath := ""
		if len(m.Artifact.Locations) > 0 {
			filePath = normalizeRepoRelativePath(m.Artifact.Locations[0].Path)
		}
		if filePath == "" {
			filePath = strings.TrimSuffix(m.Artifact.Name+"@"+m.Artifact.Version, "@")
		}
		out = append(out, jobUnifiedFinding{
			ID:        int64(i + 1),
			ScanJobID: scanJobID,
			Kind:      "sca",
			Scanner:   "grype",
			Severity:  strings.ToUpper(strings.TrimSpace(m.Vulnerability.Severity)),
			Title:     m.Vulnerability.ID,
			FilePath:  filePath,
			Package:   m.Artifact.Name,
			Version:   m.Artifact.Version,
			Fix:       fix,
			Message:   m.Vulnerability.Description,
			Status:    "open",
			FirstSeen: firstSeen,
		})
	}
	return out
}

func parseTrivyRawFindings(scanJobID int64, data []byte, firstSeen string) []jobUnifiedFinding {
	var payload struct {
		Results []struct {
			Target            string `json:"Target"`
			Misconfigurations []struct {
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
				IacMetadata struct {
					StartLine int `json:"StartLine"`
				} `json:"IacMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	var out []jobUnifiedFinding
	n := 1
	for _, r := range payload.Results {
		for _, m := range r.Misconfigurations {
			out = append(out, jobUnifiedFinding{
				ID:        int64(n),
				ScanJobID: scanJobID,
				Kind:      "iac",
				Scanner:   "trivy",
				Severity:  strings.ToUpper(strings.TrimSpace(m.Severity)),
				Title:     firstNonEmpty(m.Title, m.ID),
				FilePath:  normalizeRepoRelativePath(r.Target),
				Line:      m.IacMetadata.StartLine,
				Message:   m.Description,
				Status:    "open",
				FirstSeen: firstSeen,
			})
			n++
		}
	}
	return out
}

func parseTrufflehogRawFindings(scanJobID int64, data []byte, firstSeen string) []jobUnifiedFinding {
	var out []jobUnifiedFinding
	sc := bufio.NewScanner(bytes.NewReader(data))
	i := 1
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			DetectorName   string         `json:"DetectorName"`
			Verified       bool           `json:"Verified"`
			SourceMetadata map[string]any `json:"SourceMetadata"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		file, lineNo := extractTrufflehogPathLine(rec.SourceMetadata)
		file = normalizeRepoRelativePath(file)
		sev := "MEDIUM"
		msg := "Unverified secret candidate"
		if rec.Verified {
			sev = "HIGH"
			msg = "Verified secret detected"
		}
		title := strings.TrimSpace(rec.DetectorName)
		if title == "" {
			title = "Secret"
		}
		out = append(out, jobUnifiedFinding{
			ID:        int64(i),
			ScanJobID: scanJobID,
			Kind:      "secrets",
			Scanner:   "trufflehog",
			Severity:  sev,
			Title:     title,
			FilePath:  file,
			Line:      lineNo,
			Message:   msg,
			Status:    "open",
			FirstSeen: firstSeen,
		})
		i++
	}
	return out
}

func extractTrufflehogPathLine(source map[string]any) (string, int) {
	if len(source) == 0 {
		return "", 0
	}
	var lineNo int
	if data, ok := source["Data"].(map[string]any); ok {
		if p, l := findPathLineInMap(data); p != "" || l != 0 {
			return p, l
		}
	}
	path, l := findPathLineInMap(source)
	if l != 0 {
		lineNo = l
	}
	return path, lineNo
}

func findPathLineInMap(m map[string]any) (string, int) {
	type node struct {
		v any
	}
	q := []node{{v: m}}
	seen := map[uintptr]struct{}{}
	var firstPath string
	var firstLine int

	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		switch x := cur.v.(type) {
		case map[string]any:
			// Prevent pathological cycles (unlikely for JSON, but cheap safeguard).
			ptr := fmt.Sprintf("%p", x)
			_ = ptr
			for k, v := range x {
				kl := strings.ToLower(strings.TrimSpace(k))
				switch kl {
				case "file", "filepath", "path":
					if firstPath == "" {
						if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
							firstPath = s
						}
					}
				case "line", "linenumber", "line_number":
					if firstLine == 0 {
						firstLine = anyToInt(v)
					}
				}
				switch vv := v.(type) {
				case map[string]any:
					q = append(q, node{v: vv})
				case []any:
					for _, item := range vv {
						q = append(q, node{v: item})
					}
				}
			}
		case []any:
			for _, item := range x {
				q = append(q, node{v: item})
			}
		}
		if firstPath != "" && firstLine != 0 {
			break
		}
		_ = seen
	}
	return firstPath, firstLine
}

func anyToInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case float32:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case int32:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}

func normalizeRepoRelativePath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if idx := strings.Index(p, "/ctrlscan-clone-"); idx >= 0 {
		rest := p[idx+1:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return strings.TrimPrefix(rest[slash+1:], "/")
		}
	}
	return p
}
