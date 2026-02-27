package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// --- Row types ---

// scanJobRow is used to scan rows from the scan_jobs table into a response payload.
type scanJobRow struct {
	ID               int64   `db:"id"                json:"id"`
	UniqueKey        string  `db:"unique_key"        json:"unique_key"`
	Provider         string  `db:"provider"          json:"provider"`
	Owner            string  `db:"owner"             json:"owner"`
	Repo             string  `db:"repo"              json:"repo"`
	Branch           string  `db:"branch"            json:"branch"`
	Status           string  `db:"status"            json:"status"`
	FindingsCritical int     `db:"findings_critical" json:"findings_critical"`
	FindingsHigh     int     `db:"findings_high"     json:"findings_high"`
	FindingsMedium   int     `db:"findings_medium"   json:"findings_medium"`
	FindingsLow      int     `db:"findings_low"      json:"findings_low"`
	StartedAt        string  `db:"started_at"        json:"started_at"`
	CompletedAt      *string `db:"completed_at"      json:"completed_at,omitempty"`
	ErrorMsg         string  `db:"error_msg"         json:"error_msg,omitempty"`
}

type scanJobDetailRow struct {
	ID               int64   `db:"id"                json:"id"`
	UniqueKey        string  `db:"unique_key"        json:"unique_key"`
	Provider         string  `db:"provider"          json:"provider"`
	Owner            string  `db:"owner"             json:"owner"`
	Repo             string  `db:"repo"              json:"repo"`
	Branch           string  `db:"branch"            json:"branch"`
	CommitSHA        string  `db:"commit_sha"        json:"commit_sha"`
	Status           string  `db:"status"            json:"status"`
	ScanMode         string  `db:"scan_mode"         json:"scan_mode"`
	FindingsCritical int     `db:"findings_critical" json:"findings_critical"`
	FindingsHigh     int     `db:"findings_high"     json:"findings_high"`
	FindingsMedium   int     `db:"findings_medium"   json:"findings_medium"`
	FindingsLow      int     `db:"findings_low"      json:"findings_low"`
	StartedAt        string  `db:"started_at"        json:"started_at"`
	CompletedAt      *string `db:"completed_at"      json:"completed_at,omitempty"`
	ErrorMsg         string  `db:"error_msg"         json:"error_msg,omitempty"`
}

type scanJobLookupHistoryRow struct {
	ID                int64   `db:"id"                json:"id"`
	Branch            string  `db:"branch"            json:"branch"`
	CommitSHA         string  `db:"commit_sha"        json:"commit_sha"`
	Status            string  `db:"status"            json:"status"`
	FindingsCritical  int     `db:"findings_critical" json:"findings_critical"`
	FindingsHigh      int     `db:"findings_high"     json:"findings_high"`
	FindingsMedium    int     `db:"findings_medium"   json:"findings_medium"`
	FindingsLow       int     `db:"findings_low"      json:"findings_low"`
	PresentCount      int     `db:"present_count"     json:"present_count"`
	IntroducedCount   int     `db:"introduced_count"  json:"introduced_count"`
	FixedCount        int     `db:"fixed_count"       json:"fixed_count"`
	ReintroducedCount int     `db:"reintroduced_count" json:"reintroduced_count"`
	StartedAt         string  `db:"started_at"        json:"started_at"`
	CompletedAt       *string `db:"completed_at"      json:"completed_at,omitempty"`
}

type scanJobScannerRow struct {
	ID            int64  `db:"id"             json:"id"`
	ScanJobID     int64  `db:"scan_job_id"    json:"scan_job_id"`
	ScannerName   string `db:"scanner_name"   json:"scanner_name"`
	ScannerType   string `db:"scanner_type"   json:"scanner_type"`
	Status        string `db:"status"         json:"status"`
	FindingsCount int    `db:"findings_count" json:"findings_count"`
	DurationMs    int64  `db:"duration_ms"    json:"duration_ms"`
	ErrorMsg      string `db:"error_msg"      json:"error_msg,omitempty"`
	HasRaw        bool   `db:"has_raw"        json:"has_raw"`
}

type deleteJobsRequest struct {
	IDs       []int64 `json:"ids"`
	DeleteAll bool    `json:"delete_all"`
}

type deleteJobsResponse struct {
	DeletedCount int     `json:"deleted_count"`
	DeletedIDs   []int64 `json:"deleted_ids"`
	NotFoundIDs  []int64 `json:"not_found_ids"`
	DeleteAll    bool    `json:"delete_all,omitempty"`
}

// --- Job list/query handlers ---

func (gw *Gateway) handleListJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	status := q.Get("status")
	repos := q["repo"]
	minHighStr := q.Get("min_high")
	minMediumStr := q.Get("min_medium")
	pg := parsePaginationParams(r, 20, 200)

	var conditions []string
	var args []any

	if status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, status)
	}
	if len(repos) > 0 {
		var repoConds []string
		for _, rv := range repos {
			parts := strings.SplitN(rv, "/", 2)
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				repoConds = append(repoConds, "(owner = ? AND repo = ?)")
				args = append(args, parts[0], parts[1])
			}
		}
		if len(repoConds) > 0 {
			conditions = append(conditions, "("+strings.Join(repoConds, " OR ")+")")
		}
	}
	if minHighStr != "" {
		if n, err := strconv.Atoi(minHighStr); err == nil {
			conditions = append(conditions, "findings_high >= ?")
			args = append(args, n)
		}
	}
	if minMediumStr != "" {
		if n, err := strconv.Atoi(minMediumStr); err == nil {
			conditions = append(conditions, "findings_medium >= ?")
			args = append(args, n)
		}
	}

	baseSelect := `SELECT id, unique_key, provider, owner, repo, branch, status,
	           findings_critical, findings_high, findings_medium, findings_low,
	           started_at, completed_at, error_msg
	          FROM scan_jobs`
	baseCount := `SELECT COUNT(*) AS n FROM scan_jobs`
	if len(conditions) > 0 {
		where := " WHERE " + strings.Join(conditions, " AND ")
		baseSelect += where
		baseCount += where
	}

	type countRow struct {
		N int `db:"n"`
	}
	var count countRow
	if err := gw.db.Get(ctx, &count, baseCount, args...); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	query := baseSelect + " ORDER BY id DESC LIMIT ? OFFSET ?"
	argsWithPaging := append(args, pg.PageSize, pg.Offset)

	var jobs []scanJobRow
	if err := gw.db.Select(ctx, &jobs, query, argsWithPaging...); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if jobs == nil {
		jobs = []scanJobRow{}
	}
	totalPages := 1
	if count.N > 0 {
		totalPages = (count.N + pg.PageSize - 1) / pg.PageSize
	}
	writeJSON(w, http.StatusOK, paginationResult[scanJobRow]{
		Items:      jobs,
		Page:       pg.Page,
		PageSize:   pg.PageSize,
		Total:      count.N,
		TotalPages: totalPages,
	})
}

func (gw *Gateway) handleJobsSummary(w http.ResponseWriter, r *http.Request) {
	type row struct {
		TotalJobs int `db:"total_jobs" json:"total_jobs"`
		Running   int `db:"running" json:"running"`
		Completed int `db:"completed" json:"completed"`
		Partial   int `db:"partial" json:"partial"`
		Failed    int `db:"failed" json:"failed"`
		Stopped   int `db:"stopped" json:"stopped"`
		Critical  int `db:"critical" json:"critical"`
		High      int `db:"high" json:"high"`
		Medium    int `db:"medium" json:"medium"`
		Low       int `db:"low" json:"low"`
	}
	var out row
	if err := gw.db.Get(r.Context(), &out, `
		SELECT
		  COUNT(*) AS total_jobs,
		  COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) AS running,
		  COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) AS completed,
		  COALESCE(SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END), 0) AS partial,
		  COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed,
		  COALESCE(SUM(CASE WHEN status = 'stopped' THEN 1 ELSE 0 END), 0) AS stopped,
		  COALESCE(SUM(findings_critical), 0) AS critical,
		  COALESCE(SUM(findings_high), 0) AS high,
		  COALESCE(SUM(findings_medium), 0) AS medium,
		  COALESCE(SUM(findings_low), 0) AS low
		FROM scan_jobs`); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (gw *Gateway) handleListJobRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	pg := parsePaginationParams(r, 200, 1000)

	type row struct {
		Provider string `db:"provider" json:"provider"`
		Owner    string `db:"owner" json:"owner"`
		Repo     string `db:"repo" json:"repo"`
		LastID   int64  `db:"last_id" json:"last_id"`
	}
	type countRow struct {
		N int `db:"n"`
	}

	var count countRow
	countSQL := `
		SELECT COUNT(*) AS n
		FROM (
		  SELECT provider, owner, repo
		  FROM scan_jobs
	`
	var countArgs []any
	if q != "" {
		countSQL += ` WHERE LOWER(owner || '/' || repo) LIKE ?`
		countArgs = append(countArgs, "%"+q+"%")
	}
	countSQL += ` GROUP BY provider, owner, repo
		) t`
	if err := gw.db.Get(ctx, &count, countSQL, countArgs...); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	sql := `
		SELECT provider, owner, repo, MAX(id) AS last_id
		FROM scan_jobs
	`
	var args []any
	if q != "" {
		sql += ` WHERE LOWER(owner || '/' || repo) LIKE ?`
		args = append(args, "%"+q+"%")
	}
	sql += ` GROUP BY provider, owner, repo
	         ORDER BY last_id DESC
	         LIMIT ? OFFSET ?`
	args = append(args, pg.PageSize, pg.Offset)

	var rows []row
	if err := gw.db.Select(ctx, &rows, sql, args...); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []row{}
	}
	totalPages := 1
	if count.N > 0 {
		totalPages = (count.N + pg.PageSize - 1) / pg.PageSize
	}
	writeJSON(w, http.StatusOK, paginationResult[row]{
		Items:      rows,
		Page:       pg.Page,
		PageSize:   pg.PageSize,
		Total:      count.N,
		TotalPages: totalPages,
	})
}

func normalizeJobLookupSource(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "github", "gh":
		return "github"
	case "gitlab", "gl":
		return "gitlab"
	case "azure", "azuredevops", "ado":
		return "azure"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func parseLookupRepoFullName(v string) (owner, repo string, err error) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(v), "/"), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("repo must be in owner/name format")
	}
	return parts[0], parts[1], nil
}

func (gw *Gateway) handleLookupJob(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := normalizeJobLookupSource(q.Get("source"))
	if source == "" {
		source = normalizeJobLookupSource(q.Get("provider"))
	}
	repoFull := q.Get("repo")
	branch := strings.TrimSpace(q.Get("branch"))
	commit := strings.TrimSpace(q.Get("commit"))
	if commit == "" {
		commit = strings.TrimSpace(q.Get("commit_sha"))
	}
	historyLimit := 20
	if raw := strings.TrimSpace(q.Get("history_limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			if n < 1 {
				historyLimit = 1
			} else if n > 200 {
				historyLimit = 200
			} else {
				historyLimit = n
			}
		}
	}
	if source == "" {
		writeError(w, http.StatusBadRequest, "source (or provider) is required")
		return
	}
	owner, repo, err := parseLookupRepoFullName(repoFull)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	args := []any{source, owner, repo}
	where := []string{"provider = ?", "owner = ?", "repo = ?"}
	if branch != "" {
		where = append(where, "branch = ?")
		args = append(args, branch)
	}
	if commit != "" {
		where = append(where, "commit_sha = ?")
		args = append(args, commit)
	}

	var job scanJobDetailRow
	jobSQL := `SELECT id, unique_key, provider, owner, repo, branch, commit_sha, status, scan_mode,
		findings_critical, findings_high, findings_medium, findings_low, started_at, completed_at, error_msg
		FROM scan_jobs WHERE ` + strings.Join(where, " AND ") + ` ORDER BY id DESC LIMIT 1`
	if err := gw.db.Get(r.Context(), &job, jobSQL, args...); err != nil {
		writeError(w, http.StatusNotFound, "no scan job found for the requested source/repo/branch")
		return
	}

	historyArgs := []any{job.Provider, job.Owner, job.Repo, job.Branch, historyLimit}
	var history []scanJobLookupHistoryRow
	_ = gw.db.Select(r.Context(), &history, `SELECT j.id, j.branch, j.commit_sha, j.status,
		j.findings_critical, j.findings_high, j.findings_medium, j.findings_low,
		COALESCE(s.present_count, 0) AS present_count,
		COALESCE(s.introduced_count, 0) AS introduced_count,
		COALESCE(s.fixed_count, 0) AS fixed_count,
		COALESCE(s.reintroduced_count, 0) AS reintroduced_count,
		j.started_at, j.completed_at
		FROM scan_jobs j
		LEFT JOIN scan_job_finding_summaries s ON s.scan_job_id = j.id
		WHERE j.provider = ? AND j.owner = ? AND j.repo = ? AND j.branch = ?
		ORDER BY j.id DESC
		LIMIT ?`, historyArgs...)
	if history == nil {
		history = []scanJobLookupHistoryRow{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"lookup": map[string]any{
			"source":      source,
			"repo":        owner + "/" + repo,
			"branch":      branch,
			"commit":      commit,
			"history_max": historyLimit,
		},
		"job":     job,
		"history": history,
	})
}

func (gw *Gateway) handleGetJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var job scanJobDetailRow
	if err := gw.db.Get(r.Context(), &job, `SELECT id, unique_key, provider, owner, repo, branch, commit_sha, status, scan_mode,
		findings_critical, findings_high, findings_medium, findings_low, started_at, completed_at, error_msg
		FROM scan_jobs WHERE id = ?`, id); err != nil {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (gw *Gateway) handleGetJobHistory(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var job scanJobDetailRow
	if err := gw.db.Get(r.Context(), &job, `SELECT id, unique_key, provider, owner, repo, branch, commit_sha, status, scan_mode,
		findings_critical, findings_high, findings_medium, findings_low, started_at, completed_at, error_msg
		FROM scan_jobs WHERE id = ?`, id); err != nil {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			if n < 1 {
				limit = 1
			} else if n > 200 {
				limit = 200
			} else {
				limit = n
			}
		}
	}
	var history []scanJobLookupHistoryRow
	_ = gw.db.Select(r.Context(), &history, `SELECT j.id, j.branch, j.commit_sha, j.status,
		j.findings_critical, j.findings_high, j.findings_medium, j.findings_low,
		COALESCE(s.present_count, 0) AS present_count,
		COALESCE(s.introduced_count, 0) AS introduced_count,
		COALESCE(s.fixed_count, 0) AS fixed_count,
		COALESCE(s.reintroduced_count, 0) AS reintroduced_count,
		j.started_at, j.completed_at
		FROM scan_jobs j
		LEFT JOIN scan_job_finding_summaries s ON s.scan_job_id = j.id
		WHERE j.provider = ? AND j.owner = ? AND j.repo = ? AND j.branch = ?
		ORDER BY j.id DESC
		LIMIT ?`, job.Provider, job.Owner, job.Repo, job.Branch, limit)
	if history == nil {
		history = []scanJobLookupHistoryRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job":     job,
		"history": history,
		"lookup": map[string]any{
			"source":      job.Provider,
			"repo":        job.Owner + "/" + job.Repo,
			"branch":      job.Branch,
			"commit":      job.CommitSHA,
			"history_max": limit,
		},
	})
}

func (gw *Gateway) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if id <= 0 {
		writeError(w, http.StatusBadRequest, "id must be positive")
		return
	}

	existing, err := gw.existingScanJobIDs(r.Context(), []int64{id})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if len(existing) == 0 {
		writeError(w, http.StatusNotFound, "scan job not found")
		return
	}
	if err := gw.deleteScanJobsByIDs(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, deleteJobsResponse{
		DeletedCount: 1,
		DeletedIDs:   existing,
		NotFoundIDs:  []int64{},
	})
}

func (gw *Gateway) handleDeleteJobs(w http.ResponseWriter, r *http.Request) {
	var req deleteJobsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DeleteAll {
		ids, err := gw.listAllScanJobIDs(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "query failed")
			return
		}
		if err := gw.deleteAllScanJobs(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "delete failed")
			return
		}
		writeJSON(w, http.StatusOK, deleteJobsResponse{
			DeletedCount: len(ids),
			DeletedIDs:   ids,
			NotFoundIDs:  []int64{},
			DeleteAll:    true,
		})
		return
	}

	ids, err := normalizeDeleteIDs(req.IDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "provide ids or set delete_all=true")
		return
	}

	existing, err := gw.existingScanJobIDs(r.Context(), ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	notFound := diffInt64(ids, existing)
	if len(existing) > 0 {
		if err := gw.deleteScanJobsByIDs(r.Context(), existing); err != nil {
			writeError(w, http.StatusInternalServerError, "delete failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, deleteJobsResponse{
		DeletedCount: len(existing),
		DeletedIDs:   existing,
		NotFoundIDs:  notFound,
	})
}

func (gw *Gateway) handleListJobScanners(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var rows []scanJobScannerRow
	if err := gw.db.Select(r.Context(), &rows, `SELECT s.id, s.scan_job_id, s.scanner_name, s.scanner_type, s.status,
		s.findings_count, s.duration_ms, s.error_msg,
		CASE WHEN r.id IS NULL THEN 0 ELSE 1 END AS has_raw
		FROM scan_job_scanners s
		LEFT JOIN scan_job_raw_outputs r ON r.scan_job_id = s.scan_job_id AND r.scanner_name = s.scanner_name
		WHERE s.scan_job_id = ?
		ORDER BY s.id ASC`, id); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []scanJobScannerRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleListJobFixes(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var rows []fixQueueRow
	if err := gw.db.Select(r.Context(), &rows,
		`SELECT id, scan_job_id, finding_type, finding_id, ai_provider, ai_model, ai_endpoint, apply_hints_json, pr_title, pr_body,
		        status, pr_url, generated_at, approved_at
		   FROM fix_queue
		  WHERE scan_job_id = ?
		  ORDER BY id DESC`, id); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []fixQueueRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleListJobRemediationRuns(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pg := parsePaginationParams(r, 10, 100)
	type row struct {
		TaskID              int64   `db:"task_id" json:"task_id"`
		CampaignID          int64   `db:"campaign_id" json:"campaign_id"`
		CampaignName        string  `db:"campaign_name" json:"campaign_name"`
		CampaignStatus      string  `db:"campaign_status" json:"campaign_status"`
		CampaignMode        string  `db:"campaign_mode" json:"campaign_mode"`
		TaskStatus          string  `db:"task_status" json:"task_status"`
		WorkerName          string  `db:"worker_name" json:"worker_name,omitempty"`
		TaskMessage         string  `db:"task_message" json:"task_message,omitempty"`
		CampaignError       string  `db:"campaign_error" json:"campaign_error,omitempty"`
		CreatedAt           string  `db:"created_at" json:"created_at"`
		StartedAt           *string `db:"started_at" json:"started_at,omitempty"`
		CompletedAt         *string `db:"completed_at" json:"completed_at,omitempty"`
		CampaignStartedAt   *string `db:"campaign_started_at" json:"campaign_started_at,omitempty"`
		CampaignCompletedAt *string `db:"campaign_completed_at" json:"campaign_completed_at,omitempty"`
		AIFindingsLoaded    int     `db:"ai_findings_loaded" json:"ai_findings_loaded"`
		AIFindingsDeduped   int     `db:"ai_findings_deduped" json:"ai_findings_deduped"`
		AITriageStatus      string  `db:"ai_triage_status" json:"ai_triage_status,omitempty"`
		AITriageBatches     int     `db:"ai_triage_batches" json:"ai_triage_batches"`
		AITriageSummary     string  `db:"ai_triage_summary" json:"ai_triage_summary,omitempty"`
		AITriageJSON        string  `db:"ai_triage_json" json:"ai_triage_json,omitempty"`
		AIProvider          string  `db:"ai_provider" json:"ai_provider,omitempty"`
		AIModel             string  `db:"ai_model" json:"ai_model,omitempty"`
		AIEndpoint          string  `db:"ai_endpoint" json:"ai_endpoint,omitempty"`
		AIProgressPhase     string  `db:"ai_progress_phase" json:"ai_progress_phase,omitempty"`
		AIProgressCurrent   int     `db:"ai_progress_current" json:"ai_progress_current"`
		AIProgressTotal     int     `db:"ai_progress_total" json:"ai_progress_total"`
		AIProgressPercent   int     `db:"ai_progress_percent" json:"ai_progress_percent"`
		AIProgressNote      string  `db:"ai_progress_note" json:"ai_progress_note,omitempty"`
		AIProgressUpdatedAt *string `db:"ai_progress_updated_at" json:"ai_progress_updated_at,omitempty"`
		AIFixAttempted      int     `db:"ai_fix_attempted" json:"ai_fix_attempted"`
		AIFixQueued         int     `db:"ai_fix_queued" json:"ai_fix_queued"`
		AIFixSkippedLowConf int     `db:"ai_fix_skipped_low_conf" json:"ai_fix_skipped_low_conf"`
		AIFixFailed         int     `db:"ai_fix_failed" json:"ai_fix_failed"`
		AIUpdatedAt         *string `db:"ai_updated_at" json:"ai_updated_at,omitempty"`
	}
	type countRow struct {
		N int `db:"n"`
	}
	var count countRow
	if err := gw.db.Get(r.Context(), &count, `
		SELECT COUNT(*) AS n
		FROM remediation_tasks t
		INNER JOIN remediation_campaigns c ON c.id = t.campaign_id
		WHERE t.scan_job_id = ?
	`, id); err != nil {
		slog.Warn("Failed to count remediation runs for scan job", "scan_job_id", id, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	var rows []row
	if err := gw.db.Select(r.Context(), &rows, `
		SELECT
		  t.id AS task_id,
		  t.campaign_id AS campaign_id,
		  c.name AS campaign_name,
		  c.status AS campaign_status,
		  c.mode AS campaign_mode,
		  t.status AS task_status,
		  t.worker_name AS worker_name,
		  t.error_msg AS task_message,
		  c.error_msg AS campaign_error,
		  t.created_at AS created_at,
		  t.started_at AS started_at,
		  t.completed_at AS completed_at,
		  c.started_at AS campaign_started_at,
		  c.completed_at AS campaign_completed_at,
		  COALESCE(t.ai_findings_loaded, 0) AS ai_findings_loaded,
		  COALESCE(t.ai_findings_deduped, 0) AS ai_findings_deduped,
		  COALESCE(t.ai_triage_status, '') AS ai_triage_status,
		  COALESCE(t.ai_triage_batches, 0) AS ai_triage_batches,
		  COALESCE(t.ai_triage_summary, '') AS ai_triage_summary,
		  COALESCE(t.ai_triage_json, '') AS ai_triage_json,
		  COALESCE(t.ai_provider, '') AS ai_provider,
		  COALESCE(t.ai_model, '') AS ai_model,
		  COALESCE(t.ai_endpoint, '') AS ai_endpoint,
		  COALESCE(t.ai_progress_phase, '') AS ai_progress_phase,
		  COALESCE(t.ai_progress_current, 0) AS ai_progress_current,
		  COALESCE(t.ai_progress_total, 0) AS ai_progress_total,
		  COALESCE(t.ai_progress_percent, 0) AS ai_progress_percent,
		  COALESCE(t.ai_progress_note, '') AS ai_progress_note,
		  t.ai_progress_updated_at AS ai_progress_updated_at,
		  COALESCE(t.ai_fix_attempted, 0) AS ai_fix_attempted,
		  COALESCE(t.ai_fix_queued, 0) AS ai_fix_queued,
		  COALESCE(t.ai_fix_skipped_low_conf, 0) AS ai_fix_skipped_low_conf,
		  COALESCE(t.ai_fix_failed, 0) AS ai_fix_failed,
		  t.ai_updated_at AS ai_updated_at
		FROM remediation_tasks t
		INNER JOIN remediation_campaigns c ON c.id = t.campaign_id
		WHERE t.scan_job_id = ?
		ORDER BY t.id DESC
		LIMIT ? OFFSET ?
	`, id, pg.PageSize, pg.Offset); err != nil {
		slog.Warn("Failed to list remediation runs for scan job", "scan_job_id", id, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []row{}
	}
	totalPages := 1
	if count.N > 0 {
		totalPages = (count.N + pg.PageSize - 1) / pg.PageSize
	}
	writeJSON(w, http.StatusOK, paginationResult[row]{
		Items:      rows,
		Page:       pg.Page,
		PageSize:   pg.PageSize,
		Total:      count.N,
		TotalPages: totalPages,
	})
}

// --- DB helpers ---

func (gw *Gateway) listAllScanJobIDs(ctx context.Context) ([]int64, error) {
	type row struct {
		ID int64 `db:"id"`
	}
	var rows []row
	if err := gw.db.Select(ctx, &rows, `SELECT id FROM scan_jobs ORDER BY id ASC`); err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out, nil
}

func (gw *Gateway) existingScanJobIDs(ctx context.Context, ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return []int64{}, nil
	}
	type row struct {
		ID int64 `db:"id"`
	}
	query := fmt.Sprintf("SELECT id FROM scan_jobs WHERE id IN (%s)", placeholders(len(ids)))
	var rows []row
	if err := gw.db.Select(ctx, &rows, query, toAnyArgs(ids)...); err != nil {
		return nil, err
	}
	found := make(map[int64]struct{}, len(rows))
	for _, r := range rows {
		found[r.ID] = struct{}{}
	}
	ordered := make([]int64, 0, len(rows))
	for _, id := range ids {
		if _, ok := found[id]; ok {
			ordered = append(ordered, id)
		}
	}
	return ordered, nil
}

func (gw *Gateway) deleteScanJobsByIDs(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := toAnyArgs(ids)
	where := fmt.Sprintf(" WHERE scan_job_id IN (%s)", placeholders(len(ids)))
	if err := gw.db.Exec(ctx, "DELETE FROM sbom_artifacts"+where, args...); err != nil {
		return err
	}
	if err := gw.db.Exec(ctx, "DELETE FROM sboms"+where, args...); err != nil {
		return err
	}
	for _, table := range []string{
		"scan_job_raw_outputs",
		"scan_job_scanners",
		"scan_job_findings",
		"scan_job_finding_summaries",
		"sca_vulns",
		"sast_findings",
		"secrets_findings",
		"iac_findings",
		"fix_queue",
	} {
		if err := gw.db.Exec(ctx, "DELETE FROM "+table+where, args...); err != nil {
			return err
		}
	}
	jobWhere := fmt.Sprintf(" WHERE id IN (%s)", placeholders(len(ids)))
	return gw.db.Exec(ctx, "DELETE FROM scan_jobs"+jobWhere, args...)
}

func (gw *Gateway) deleteAllScanJobs(ctx context.Context) error {
	for _, table := range []string{
		"sbom_artifacts",
		"sboms",
		"scan_job_raw_outputs",
		"scan_job_scanners",
		"scan_job_findings",
		"scan_job_finding_summaries",
		"sca_vulns",
		"sast_findings",
		"secrets_findings",
		"iac_findings",
		"fix_queue",
		"repo_finding_lifecycles",
		"scan_jobs",
	} {
		if err := gw.db.Exec(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	return nil
}

// handleGetJobRawScannerOutput streams raw scanner output for a job.
func (gw *Gateway) handleGetJobRawScannerOutput(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scanner := strings.TrimSpace(r.PathValue("scanner"))
	if scanner == "" {
		writeError(w, http.StatusBadRequest, "missing scanner")
		return
	}
	type rawRow struct {
		ContentType string `db:"content_type"`
		RawOutput   []byte `db:"raw_output"`
	}
	var row rawRow
	if err := gw.db.Get(r.Context(), &row,
		`SELECT content_type, raw_output FROM scan_job_raw_outputs WHERE scan_job_id = ? AND scanner_name = ?`,
		id, scanner,
	); err != nil {
		writeError(w, http.StatusNotFound, "raw output not found")
		return
	}
	filename := fmt.Sprintf("scan-job-%d-%s.raw", id, scanner)
	if strings.Contains(row.ContentType, "json") {
		filename = fmt.Sprintf("scan-job-%d-%s.json", id, scanner)
	}
	w.Header().Set("Content-Type", row.ContentType)
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	}
	w.WriteHeader(http.StatusOK)
	// Raw scanner payload download endpoint intentionally streams bytes with an explicit content type.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(row.RawOutput)
}

