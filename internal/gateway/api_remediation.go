package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
)

// --- Schema helpers ---

func (gw *Gateway) ensureRemediationSchema(ctx context.Context) error {
	// Safe to call repeatedly; migration runner is idempotent.
	return gw.db.Migrate(ctx)
}

func remediationSchemaHint(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no such table") && (strings.Contains(msg, "remediation_campaigns") || strings.Contains(msg, "remediation_tasks")) {
		return "remediation schema is missing; restart the gateway after upgrading so migrations can run"
	}
	return ""
}

// --- Row/request types ---

type remediationCampaignRow struct {
	ID             int64   `db:"id" json:"id"`
	Name           string  `db:"name" json:"name"`
	Status         string  `db:"status" json:"status"`
	Mode           string  `db:"mode" json:"mode"`
	AutoPR         bool    `db:"auto_pr" json:"auto_pr"`
	FiltersJSON    string  `db:"filters_json" json:"filters_json"`
	CreatedAt      string  `db:"created_at" json:"created_at"`
	StartedAt      *string `db:"started_at" json:"started_at,omitempty"`
	CompletedAt    *string `db:"completed_at" json:"completed_at,omitempty"`
	ErrorMsg       string  `db:"error_msg" json:"error_msg,omitempty"`
	TotalTasks     int     `db:"total_tasks" json:"total_tasks"`
	PendingTasks   int     `db:"pending_tasks" json:"pending_tasks"`
	RunningTasks   int     `db:"running_tasks" json:"running_tasks"`
	CompletedTasks int     `db:"completed_tasks" json:"completed_tasks"`
	FailedTasks    int     `db:"failed_tasks" json:"failed_tasks"`
	SkippedTasks   int     `db:"skipped_tasks" json:"skipped_tasks"`
}

type remediationTaskRow struct {
	ID                  int64   `db:"id" json:"id"`
	CampaignID          int64   `db:"campaign_id" json:"campaign_id"`
	ScanJobID           int64   `db:"scan_job_id" json:"scan_job_id"`
	Provider            string  `db:"provider" json:"provider"`
	Owner               string  `db:"owner" json:"owner"`
	Repo                string  `db:"repo" json:"repo"`
	Branch              string  `db:"branch" json:"branch"`
	CloneURL            string  `db:"clone_url" json:"clone_url,omitempty"`
	Status              string  `db:"status" json:"status"`
	WorkerName          string  `db:"worker_name" json:"worker_name,omitempty"`
	ErrorMsg            string  `db:"error_msg" json:"error_msg,omitempty"`
	AIProvider          string  `db:"ai_provider" json:"ai_provider,omitempty"`
	AIModel             string  `db:"ai_model" json:"ai_model,omitempty"`
	AIEndpoint          string  `db:"ai_endpoint" json:"ai_endpoint,omitempty"`
	AIProgressPhase     string  `db:"ai_progress_phase" json:"ai_progress_phase,omitempty"`
	AIProgressCurrent   int     `db:"ai_progress_current" json:"ai_progress_current"`
	AIProgressTotal     int     `db:"ai_progress_total" json:"ai_progress_total"`
	AIProgressPercent   int     `db:"ai_progress_percent" json:"ai_progress_percent"`
	AIProgressNote      string  `db:"ai_progress_note" json:"ai_progress_note,omitempty"`
	AIProgressUpdatedAt *string `db:"ai_progress_updated_at" json:"ai_progress_updated_at,omitempty"`
	CreatedAt           string  `db:"created_at" json:"created_at"`
	StartedAt           *string `db:"started_at" json:"started_at,omitempty"`
	CompletedAt         *string `db:"completed_at" json:"completed_at,omitempty"`
}

type remediationCampaignCreateRequest struct {
	Name       string   `json:"name"`
	Mode       string   `json:"mode"`    // triage|semi|auto
	AutoPR     bool     `json:"auto_pr"` // trigger PR processing for approved fixes
	StartNow   bool     `json:"start_now"`
	Force      bool     `json:"force,omitempty"`
	Repos      []string `json:"repos"` // owner/repo list (optional)
	ScanJobIDs []int64  `json:"scan_job_ids,omitempty"`
	MaxRepos   int      `json:"max_repos"` // optional limit
	LatestOnly bool     `json:"latest_only"`
	Scanners   []string `json:"scanners,omitempty"`
	Kinds      []string `json:"kinds,omitempty"`
	Severities []string `json:"severities,omitempty"`
}

type remediationCampaignScanConflict struct {
	CampaignID     int64  `db:"campaign_id"`
	CampaignStatus string `db:"campaign_status"`
	ScanJobID      int64  `db:"scan_job_id"`
}

// --- Remediation campaign handlers ---

func (gw *Gateway) handleListRemediationCampaigns(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	var rows []remediationCampaignRow
	if err := gw.db.Select(r.Context(), &rows, `SELECT * FROM remediation_campaigns ORDER BY id DESC LIMIT 200`); err != nil {
		slog.Warn("Failed to list remediation campaigns", "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []remediationCampaignRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleGetRemediationCampaign(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var row remediationCampaignRow
	if err := gw.db.Get(r.Context(), &row, `SELECT * FROM remediation_campaigns WHERE id = ?`, id); err != nil {
		slog.Warn("Failed to get remediation campaign", "id", id, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusNotFound, "campaign not found")
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (gw *Gateway) handleListRemediationCampaignTasks(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var rows []remediationTaskRow
	if err := gw.db.Select(r.Context(), &rows, `
		SELECT id, campaign_id, scan_job_id, provider, owner, repo, branch, clone_url,
		       status, worker_name, error_msg, ai_provider, ai_model, ai_endpoint,
		       ai_progress_phase, ai_progress_current, ai_progress_total, ai_progress_percent, ai_progress_note, ai_progress_updated_at,
		       created_at, started_at, completed_at
		FROM remediation_tasks
		WHERE campaign_id = ?
		ORDER BY id ASC`, id); err != nil {
		slog.Warn("Failed to list remediation campaign tasks", "campaign_id", id, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []remediationTaskRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleCreateRemediationCampaign(w http.ResponseWriter, r *http.Request) {
	if err := gw.ensureRemediationSchema(r.Context()); err != nil {
		slog.Warn("Failed ensuring remediation schema", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to prepare remediation schema")
		return
	}
	var req remediationCampaignCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "Offline Remediation Campaign"
	}
	if req.Mode == "" {
		req.Mode = "triage"
	}
	if req.Mode != "triage" && req.Mode != "semi" && req.Mode != "auto" {
		writeError(w, http.StatusBadRequest, "mode must be triage, semi, or auto")
		return
	}
	if req.MaxRepos < 0 {
		req.MaxRepos = 0
	}
	if ids, err := normalizeDeleteIDs(req.ScanJobIDs); err != nil {
		writeError(w, http.StatusBadRequest, "scan_job_ids must contain positive integers")
		return
	} else {
		req.ScanJobIDs = ids
	}
	if !req.LatestOnly {
		req.LatestOnly = true
	}
	if !req.Force && len(req.ScanJobIDs) > 0 {
		conflicts, err := gw.findActiveRemediationCampaignConflicts(r.Context(), req.ScanJobIDs)
		if err != nil {
			slog.Warn("Failed checking remediation campaign conflicts", "scan_job_ids", req.ScanJobIDs, "error", err)
			writeError(w, http.StatusInternalServerError, "failed to check existing remediation campaigns")
			return
		}
		if len(conflicts) > 0 {
			parts := make([]string, 0, len(conflicts))
			for _, c := range conflicts {
				parts = append(parts, fmt.Sprintf("scan #%d in campaign #%d (%s)", c.ScanJobID, c.CampaignID, c.CampaignStatus))
			}
			writeError(w, http.StatusConflict, "an active remediation campaign already exists for this scan ("+strings.Join(parts, "; ")+"); stop it first or retry with force=true")
			return
		}
	}
	filtersJSON, _ := json.Marshal(map[string]any{
		"repos": req.Repos, "max_repos": req.MaxRepos, "latest_only": req.LatestOnly,
		"scan_job_ids": req.ScanJobIDs,
		"scanners":     req.Scanners, "kinds": req.Kinds, "severities": req.Severities,
	})
	now := time.Now().UTC().Format(time.RFC3339)
	status := "draft"
	startedAt := ""
	if req.StartNow {
		status = "running"
		startedAt = now
	}
	cRow := struct {
		Name        string `db:"name"`
		Status      string `db:"status"`
		Mode        string `db:"mode"`
		AutoPR      bool   `db:"auto_pr"`
		FiltersJSON string `db:"filters_json"`
		CreatedAt   string `db:"created_at"`
		StartedAt   string `db:"started_at"`
	}{
		Name: req.Name, Status: status, Mode: req.Mode, AutoPR: req.AutoPR, FiltersJSON: string(filtersJSON), CreatedAt: now, StartedAt: startedAt,
	}
	id, err := gw.db.Insert(r.Context(), "remediation_campaigns", cRow)
	if err != nil {
		slog.Warn("Failed to create remediation campaign", "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "create failed")
		return
	}
	if err := gw.materializeRemediationCampaignTasks(r.Context(), id, req); err != nil {
		_ = gw.db.Exec(r.Context(), `UPDATE remediation_campaigns SET status = 'failed', error_msg = ? WHERE id = ?`, err.Error(), id)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("task materialization failed: %v", err))
		return
	}
	if req.StartNow {
		gw.broadcaster.send(SSEEvent{Type: "campaign.started", Payload: map[string]any{"campaign_id": id}})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": status})
}

func (gw *Gateway) findActiveRemediationCampaignConflicts(ctx context.Context, scanJobIDs []int64) ([]remediationCampaignScanConflict, error) {
	if len(scanJobIDs) == 0 {
		return nil, nil
	}
	query := fmt.Sprintf(`
SELECT DISTINCT t.campaign_id AS campaign_id, c.status AS campaign_status, t.scan_job_id AS scan_job_id
FROM remediation_tasks t
JOIN remediation_campaigns c ON c.id = t.campaign_id
WHERE t.scan_job_id IN (%s)
  AND c.status IN ('draft','running')
ORDER BY t.campaign_id DESC, t.scan_job_id ASC
LIMIT 20
`, placeholders(len(scanJobIDs)))
	var rows []remediationCampaignScanConflict
	if err := gw.db.Select(ctx, &rows, query, toAnyArgs(scanJobIDs)...); err != nil {
		if hint := remediationSchemaHint(err); hint != "" {
			return nil, fmt.Errorf("%s", hint)
		}
		return nil, err
	}
	return rows, nil
}

func (gw *Gateway) handleStartRemediationCampaign(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := gw.db.Exec(r.Context(), `UPDATE remediation_campaigns SET status = 'running', started_at = COALESCE(NULLIF(started_at,''), ?), completed_at = NULL WHERE id = ?`, now, id); err != nil {
		slog.Warn("Failed to start remediation campaign", "id", id, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "campaign.started", Payload: map[string]any{"campaign_id": id}})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "running", "id": id})
}

func (gw *Gateway) handleStopRemediationCampaign(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := gw.db.Exec(r.Context(), `UPDATE remediation_campaigns SET status = 'stopped', completed_at = ?, error_msg = CASE WHEN error_msg = '' THEN 'stopped by user' ELSE error_msg END WHERE id = ?`, now, id); err != nil {
		slog.Warn("Failed to stop remediation campaign", "id", id, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	_ = gw.db.Exec(r.Context(), `UPDATE remediation_tasks SET status = 'stopped', completed_at = ? WHERE campaign_id = ? AND status IN ('pending','running')`, now, id)
	if gw.orch != nil {
		_ = gw.orch.CancelActiveRemediationForCampaign(id)
	}
	gw.broadcaster.send(SSEEvent{Type: "campaign.stopped", Payload: map[string]any{"campaign_id": id}})
	writeJSON(w, http.StatusOK, map[string]any{"status": "stopped", "id": id})
}

func (gw *Gateway) handleStopJobRemediation(w http.ResponseWriter, r *http.Request) {
	_ = gw.ensureRemediationSchema(r.Context())
	scanJobID, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	type row struct {
		ID int64 `db:"id"`
	}
	var rows []row
	if err := gw.db.Select(ctx, &rows, `
		SELECT DISTINCT c.id
		FROM remediation_campaigns c
		INNER JOIN remediation_tasks t ON t.campaign_id = c.id
		WHERE t.scan_job_id = ?
		  AND c.status IN ('running','draft')
		ORDER BY c.id ASC
	`, scanJobID); err != nil {
		slog.Warn("Failed to locate remediation campaigns for scan job", "scan_job_id", scanJobID, "error", err)
		if hint := remediationSchemaHint(err); hint != "" {
			writeError(w, http.StatusInternalServerError, hint)
			return
		}
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if len(rows) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "idle",
			"scan_job_id":       scanJobID,
			"stopped_count":     0,
			"stopped_campaigns": []int64{},
		})
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	ph := placeholders(len(ids))
	args := append([]any{now}, toAnyArgs(ids)...)
	if err := gw.db.Exec(ctx,
		fmt.Sprintf(`UPDATE remediation_campaigns
			SET status = 'stopped',
			    completed_at = ?,
			    error_msg = CASE WHEN error_msg = '' THEN 'stopped by user (scan detail)' ELSE error_msg END
		  WHERE id IN (%s)`, ph),
		args...,
	); err != nil {
		slog.Warn("Failed to stop remediation campaigns for scan job", "scan_job_id", scanJobID, "error", err)
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	taskArgs := append([]any{now, scanJobID}, toAnyArgs(ids)...)
	_ = gw.db.Exec(ctx,
		fmt.Sprintf(`UPDATE remediation_tasks
			SET status = 'stopped', completed_at = ?
		  WHERE scan_job_id = ?
		    AND campaign_id IN (%s)
		    AND status IN ('pending','running')`, ph),
		taskArgs...,
	)
	if gw.orch != nil {
		_ = gw.orch.CancelActiveRemediationForScanJob(scanJobID)
	}
	for _, id := range ids {
		_ = gw.db.Exec(ctx, `UPDATE remediation_campaigns SET
			total_tasks = (SELECT COUNT(*) FROM remediation_tasks WHERE campaign_id = ?),
			pending_tasks = COALESCE((SELECT COUNT(*) FROM remediation_tasks WHERE campaign_id = ? AND status='pending'),0),
			running_tasks = COALESCE((SELECT COUNT(*) FROM remediation_tasks WHERE campaign_id = ? AND status='running'),0),
			completed_tasks = COALESCE((SELECT COUNT(*) FROM remediation_tasks WHERE campaign_id = ? AND status='completed'),0),
			failed_tasks = COALESCE((SELECT COUNT(*) FROM remediation_tasks WHERE campaign_id = ? AND status='failed'),0),
			skipped_tasks = COALESCE((SELECT COUNT(*) FROM remediation_tasks WHERE campaign_id = ? AND status='skipped'),0)
		  WHERE id = ?`, id, id, id, id, id, id, id)
		gw.broadcaster.send(SSEEvent{Type: "campaign.stopped", Payload: map[string]any{"campaign_id": id, "scan_job_id": scanJobID}})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "stopped",
		"scan_job_id":       scanJobID,
		"stopped_count":     len(ids),
		"stopped_campaigns": ids,
	})
}

func (gw *Gateway) materializeRemediationCampaignTasks(ctx context.Context, campaignID int64, req remediationCampaignCreateRequest) error {
	type scanJobLite struct {
		ID       int64  `db:"id"`
		Provider string `db:"provider"`
		Owner    string `db:"owner"`
		Repo     string `db:"repo"`
		Branch   string `db:"branch"`
	}
	var rows []scanJobLite
	if len(req.ScanJobIDs) > 0 {
		query := fmt.Sprintf("SELECT id, provider, owner, repo, branch FROM scan_jobs WHERE id IN (%s)", placeholders(len(req.ScanJobIDs)))
		if err := gw.db.Select(ctx, &rows, query, toAnyArgs(req.ScanJobIDs)...); err != nil {
			return err
		}
		// Keep caller-specified order.
		byID := make(map[int64]scanJobLite, len(rows))
		for _, row := range rows {
			byID[row.ID] = row
		}
		ordered := make([]scanJobLite, 0, len(rows))
		for _, id := range req.ScanJobIDs {
			if row, ok := byID[id]; ok {
				ordered = append(ordered, row)
			}
		}
		rows = ordered
	} else {
		if err := gw.db.Select(ctx, &rows, `SELECT id, provider, owner, repo, branch FROM scan_jobs ORDER BY id DESC LIMIT 2000`); err != nil {
			return err
		}
	}
	repoFilter := map[string]struct{}{}
	for _, r := range req.Repos {
		r = strings.TrimSpace(strings.ToLower(r))
		if r == "" {
			continue
		}
		repoFilter[r] = struct{}{}
	}
	seenRepo := map[string]struct{}{}
	providers := gw.orch.RepoProvidersForPreview()
	now := time.Now().UTC().Format(time.RFC3339)
	count := 0
	for _, row := range rows {
		key := strings.ToLower(row.Owner + "/" + row.Repo)
		if len(repoFilter) > 0 {
			if _, ok := repoFilter[key]; !ok {
				continue
			}
		}
		if req.LatestOnly {
			if _, ok := seenRepo[key]; ok {
				continue
			}
			seenRepo[key] = struct{}{}
		}
		cloneURL := ""
		if p := pickRepoProviderByName(providers, row.Provider); p != nil {
			if repo, err := p.GetRepo(ctx, row.Owner, row.Repo); err == nil {
				cloneURL = repo.CloneURL
				if row.Branch == "" {
					row.Branch = repo.DefaultBranch
				}
			}
		}
		if cloneURL == "" {
			cloneURL = fallbackCloneURL(row.Provider, row.Owner, row.Repo)
		}
		task := struct {
			CampaignID int64  `db:"campaign_id"`
			ScanJobID  int64  `db:"scan_job_id"`
			Provider   string `db:"provider"`
			Owner      string `db:"owner"`
			Repo       string `db:"repo"`
			Branch     string `db:"branch"`
			CloneURL   string `db:"clone_url"`
			Status     string `db:"status"`
			CreatedAt  string `db:"created_at"`
		}{
			CampaignID: campaignID, ScanJobID: row.ID, Provider: row.Provider, Owner: row.Owner, Repo: row.Repo,
			Branch: firstNonEmpty(row.Branch, "main"), CloneURL: cloneURL, Status: "pending", CreatedAt: now,
		}
		if _, err := gw.db.Insert(ctx, "remediation_tasks", task); err != nil {
			continue
		}
		count++
		if req.MaxRepos > 0 && count >= req.MaxRepos {
			break
		}
	}
	return gw.db.Exec(ctx, `UPDATE remediation_campaigns SET total_tasks=?, pending_tasks=? WHERE id = ?`, count, count, campaignID)
}

func pickRepoProviderByName(providers []repository.RepoProvider, name string) repository.RepoProvider {
	for _, p := range providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func fallbackCloneURL(provider, owner, repo string) string {
	switch provider {
	case "github":
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	case "gitlab":
		return fmt.Sprintf("https://gitlab.com/%s/%s.git", owner, repo)
	default:
		return ""
	}
}
