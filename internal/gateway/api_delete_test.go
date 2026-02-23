package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
)

func TestHandleDeleteJobDeletesRelatedRecords(t *testing.T) {
	gw, db := newTestGatewayForDeleteAPI(t)
	defer db.Close()
	seedScanJobGraph(t, db, 101)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/jobs/101", nil)
	buildHandler(gw).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp deleteJobsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.DeletedCount != 1 || len(resp.DeletedIDs) != 1 || resp.DeletedIDs[0] != 101 {
		t.Fatalf("unexpected response: %+v", resp)
	}

	for _, table := range []string{
		"scan_jobs",
		"scan_job_scanners",
		"scan_job_raw_outputs",
		"sca_vulns",
		"sast_findings",
		"secrets_findings",
		"iac_findings",
		"fix_queue",
		"sboms",
		"sbom_artifacts",
	} {
		if n := countByScanJobID(t, db, table, 101); n != 0 {
			t.Fatalf("expected %s rows for job 101 to be deleted, found %d", table, n)
		}
	}
}

func TestHandleDeleteJobsBulkReportsNotFound(t *testing.T) {
	gw, db := newTestGatewayForDeleteAPI(t)
	defer db.Close()
	seedScanJobGraph(t, db, 201)
	seedScanJobGraph(t, db, 202)

	rr := httptest.NewRecorder()
	body := `{"ids":[201,999,201]}`
	req := httptest.NewRequest(http.MethodDelete, "/api/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	buildHandler(gw).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp deleteJobsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.DeletedCount != 1 {
		t.Fatalf("expected 1 deleted, got %+v", resp)
	}
	if len(resp.DeletedIDs) != 1 || resp.DeletedIDs[0] != 201 {
		t.Fatalf("unexpected deleted ids: %+v", resp.DeletedIDs)
	}
	if len(resp.NotFoundIDs) != 1 || resp.NotFoundIDs[0] != 999 {
		t.Fatalf("unexpected not found ids: %+v", resp.NotFoundIDs)
	}
	if n := countByScanJobID(t, db, "scan_jobs", 201); n != 0 {
		t.Fatalf("job 201 should be deleted")
	}
	if n := countByScanJobID(t, db, "scan_jobs", 202); n != 1 {
		t.Fatalf("job 202 should remain, count=%d", n)
	}
}

func TestHandleDeleteJobsDeleteAllRequiresExplicitFlag(t *testing.T) {
	gw, db := newTestGatewayForDeleteAPI(t)
	defer db.Close()
	seedScanJobGraph(t, db, 301)
	seedScanJobGraph(t, db, 302)

	handler := buildHandler(gw)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/jobs", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for ambiguous delete-all, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/jobs", bytes.NewBufferString(`{"delete_all":true}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for delete_all, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp deleteJobsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.DeleteAll || resp.DeletedCount != 2 {
		t.Fatalf("unexpected delete_all response: %+v", resp)
	}

	for _, table := range []string{
		"scan_jobs",
		"scan_job_scanners",
		"scan_job_raw_outputs",
		"sca_vulns",
		"sast_findings",
		"secrets_findings",
		"iac_findings",
		"fix_queue",
		"sboms",
		"sbom_artifacts",
	} {
		if n := countAllRows(t, db, table); n != 0 {
			t.Fatalf("expected %s to be empty after delete_all, found %d", table, n)
		}
	}
}

func newTestGatewayForDeleteAPI(t *testing.T) (*Gateway, database.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gateway-delete-test.db")
	db, err := database.NewSQLite(config.DatabaseConfig{Path: dbPath})
	if err != nil {
		t.Fatalf("new sqlite db: %v", err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	gw := &Gateway{
		cfg:         &config.Config{},
		db:          db,
		broadcaster: newBroadcaster(),
	}
	return gw, db
}

func seedScanJobGraph(t *testing.T, db database.DB, jobID int64) {
	t.Helper()
	ctx := context.Background()
	ts := time.Now().UTC().Format(time.RFC3339)
	sbomID := jobID + 10000

	mustExec(t, db, ctx, `INSERT INTO scan_jobs (
		id, unique_key, provider, owner, repo, branch, status, started_at
	) VALUES (?, ?, 'github', 'acme', ?, 'main', 'completed', ?)`,
		jobID, "job-"+itoa(jobID), "repo-"+itoa(jobID), ts,
	)
	mustExec(t, db, ctx, `INSERT INTO scan_job_scanners (scan_job_id, scanner_name, scanner_type, status) VALUES (?, 'grype', 'sca', 'completed')`, jobID)
	mustExec(t, db, ctx, `INSERT INTO scan_job_raw_outputs (scan_job_id, scanner_name, content_type, raw_output, created_at) VALUES (?, 'grype', 'application/json', ?, ?)`,
		jobID, []byte(`{"ok":true}`), ts,
	)
	mustExec(t, db, ctx, `INSERT INTO sca_vulns (
		unique_key, scan_job_id, package_name, version_affected, vulnerability_id, severity, last_scanned, first_seen_at
	) VALUES (?, ?, 'openssl', '1.0.0', 'CVE-2026-0001', 'HIGH', ?, ?)`,
		"sca-"+itoa(jobID), jobID, ts, ts,
	)
	mustExec(t, db, ctx, `INSERT INTO sast_findings (
		unique_key, scan_job_id, scanner, check_id, severity, file_path, first_seen_at, last_seen_at
	) VALUES (?, ?, 'opengrep', 'RULE-1', 'MEDIUM', 'main.go', ?, ?)`,
		"sast-"+itoa(jobID), jobID, ts, ts,
	)
	mustExec(t, db, ctx, `INSERT INTO secrets_findings (
		unique_key, scan_job_id, detector_name, credential_hash, location_hash, first_seen_at, last_seen_at
	) VALUES (?, ?, 'AWS', 'cred-hash', 'loc-hash', ?, ?)`,
		"secret-"+itoa(jobID), jobID, ts, ts,
	)
	mustExec(t, db, ctx, `INSERT INTO iac_findings (
		unique_key, scan_job_id, scanner, check_id, severity, first_seen_at, last_seen_at
	) VALUES (?, ?, 'trivy', 'AVD-1', 'LOW', ?, ?)`,
		"iac-"+itoa(jobID), jobID, ts, ts,
	)
	mustExec(t, db, ctx, `INSERT INTO fix_queue (scan_job_id, finding_type, finding_id, generated_at) VALUES (?, 'sca', 1, ?)`, jobID, ts)
	mustExec(t, db, ctx, `INSERT INTO sboms (id, scan_job_id, tool_name) VALUES (?, ?, 'syft')`, sbomID, jobID)
	mustExec(t, db, ctx, `INSERT INTO sbom_artifacts (sbom_id, scan_job_id, name) VALUES (?, ?, 'openssl')`, sbomID, jobID)
}

func mustExec(t *testing.T, db database.DB, ctx context.Context, query string, args ...any) {
	t.Helper()
	if err := db.Exec(ctx, query, args...); err != nil {
		t.Fatalf("exec failed: %v\nquery: %s", err, query)
	}
}

func countByScanJobID(t *testing.T, db database.DB, table string, jobID int64) int {
	t.Helper()
	var row countRow
	query := "SELECT COUNT(*) AS n FROM " + table + " WHERE scan_job_id = ?"
	if table == "scan_jobs" {
		query = "SELECT COUNT(*) AS n FROM scan_jobs WHERE id = ?"
	}
	if err := db.Get(context.Background(), &row, query, jobID); err != nil {
		t.Fatalf("count %s by job id: %v", table, err)
	}
	return row.N
}

func countAllRows(t *testing.T, db database.DB, table string) int {
	t.Helper()
	var row countRow
	if err := db.Get(context.Background(), &row, "SELECT COUNT(*) AS n FROM "+table); err != nil {
		t.Fatalf("count all %s: %v", table, err)
	}
	return row.N
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
