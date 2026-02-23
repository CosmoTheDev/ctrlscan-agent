package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
	cfgpkg "github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
)

// buildHandler wires all REST and SSE routes onto a new ServeMux.
// Uses Go 1.22+ method-prefixed patterns ("GET /path", "POST /path").
func buildHandler(gw *Gateway) http.Handler {
	mux := http.NewServeMux()

	// Root/help
	mux.HandleFunc("GET /", gw.handleRoot)
	mux.HandleFunc("GET /ui", gw.handleUIIndex)
	mux.HandleFunc("GET /ui/", gw.handleUIIndex)
	mux.HandleFunc("GET /ui/app.css", gw.handleUIAsset)
	mux.HandleFunc("GET /ui/app.js", gw.handleUIAsset)
	mux.HandleFunc("GET /ui/js/", gw.handleUIAsset)

	// Health / status
	mux.HandleFunc("GET /health", gw.handleHealth)
	mux.HandleFunc("GET /api/status", gw.handleStatus)

	// Scan jobs
	mux.HandleFunc("GET /api/jobs", gw.handleListJobs)
	mux.HandleFunc("GET /api/jobs/repos", gw.handleListJobRepos)
	mux.HandleFunc("DELETE /api/jobs", gw.handleDeleteJobs)
	mux.HandleFunc("GET /api/jobs/summary", gw.handleJobsSummary)
	mux.HandleFunc("GET /api/jobs/{id}", gw.handleGetJob)
	mux.HandleFunc("DELETE /api/jobs/{id}", gw.handleDeleteJob)
	mux.HandleFunc("GET /api/jobs/{id}/scanners", gw.handleListJobScanners)
	mux.HandleFunc("GET /api/jobs/{id}/findings", gw.handleListJobFindings)
	mux.HandleFunc("GET /api/jobs/{id}/fixes", gw.handleListJobFixes)
	mux.HandleFunc("GET /api/jobs/{id}/remediation", gw.handleListJobRemediationRuns)
	mux.HandleFunc("GET /api/jobs/{id}/raw/{scanner}", gw.handleGetJobRawScannerOutput)
	mux.HandleFunc("POST /api/jobs/{id}/remediation/stop", gw.handleStopJobRemediation)
	mux.HandleFunc("POST /api/scan", gw.handleTriggerScan)

	// Agent runtime controls
	mux.HandleFunc("GET /api/agent", gw.handleAgentStatus)
	mux.HandleFunc("POST /api/agent/preview", gw.handleAgentPreview)
	mux.HandleFunc("POST /api/agent/trigger", gw.handleAgentTrigger)
	mux.HandleFunc("POST /api/agent/stop", gw.handleAgentStop)
	mux.HandleFunc("POST /api/agent/pause", gw.handleAgentPause)
	mux.HandleFunc("POST /api/agent/resume", gw.handleAgentResume)
	mux.HandleFunc("PUT /api/agent/workers", gw.handleAgentWorkers)
	mux.HandleFunc("GET /api/agent/workers", gw.handleAgentWorkersList)

	// Findings (read-only aggregated view)
	mux.HandleFunc("GET /api/findings", gw.handleListFindings)
	mux.HandleFunc("GET /api/findings/path-ignores", gw.handleListFindingPathIgnores)
	mux.HandleFunc("POST /api/findings/path-ignores", gw.handleCreateFindingPathIgnore)
	mux.HandleFunc("PUT /api/findings/path-ignores/{id}", gw.handleUpdateFindingPathIgnore)
	mux.HandleFunc("DELETE /api/findings/path-ignores/{id}", gw.handleDeleteFindingPathIgnore)
	mux.HandleFunc("GET /api/logs", gw.handleLogs)

	// Fix queue + approval
	mux.HandleFunc("GET /api/fix-queue", gw.handleListFixQueue)
	mux.HandleFunc("POST /api/fix-queue/{id}/approve", gw.handleFixApprove)
	mux.HandleFunc("POST /api/fix-queue/{id}/approve-and-run", gw.handleFixApproveAndRun)
	mux.HandleFunc("POST /api/fix-queue/{id}/reject", gw.handleFixReject)

	// Schedule management
	mux.HandleFunc("GET /api/schedules", gw.handleListSchedules)
	mux.HandleFunc("POST /api/schedules", gw.handleCreateSchedule)
	mux.HandleFunc("DELETE /api/schedules/{id}", gw.handleDeleteSchedule)
	mux.HandleFunc("POST /api/schedules/{id}/trigger", gw.handleTriggerSchedule)

	// Remediation campaigns (offline AI fix/PR workflow on existing findings)
	mux.HandleFunc("GET /api/remediation/campaigns", gw.handleListRemediationCampaigns)
	mux.HandleFunc("POST /api/remediation/campaigns", gw.handleCreateRemediationCampaign)
	mux.HandleFunc("GET /api/remediation/campaigns/{id}", gw.handleGetRemediationCampaign)
	mux.HandleFunc("GET /api/remediation/campaigns/{id}/tasks", gw.handleListRemediationCampaignTasks)
	mux.HandleFunc("POST /api/remediation/campaigns/{id}/start", gw.handleStartRemediationCampaign)
	mux.HandleFunc("POST /api/remediation/campaigns/{id}/stop", gw.handleStopRemediationCampaign)

	// Server-Sent Events stream
	mux.HandleFunc("GET /events", gw.handleEvents)

	// Config management
	mux.HandleFunc("GET /api/config", gw.handleGetConfig)
	mux.HandleFunc("PUT /api/config", gw.handlePutConfig)

	return mux
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

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

func pathID(r *http.Request, name string) (int64, error) {
	raw := r.PathValue(name)
	if raw == "" {
		return 0, fmt.Errorf("missing path parameter %q", name)
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid id %q", raw)
	}
	return id, nil
}

// --- handlers ---

func (gw *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (gw *Gateway) handleRoot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "ctrlscan gateway",
		"status":  "running",
		"message": "Gateway is up. REST/SSE API available here; browser dashboard is at /ui.",
		"endpoints": []string{
			"GET /health",
			"GET /api/status",
			"GET /api/jobs",
			"DELETE /api/jobs/{id}",
			"DELETE /api/jobs",
			"POST /api/scan",
			"GET /api/findings",
			"GET /api/fix-queue",
			"GET /api/schedules",
			"POST /api/schedules",
			"GET /api/remediation/campaigns",
			"POST /api/remediation/campaigns",
			"GET /events",
			"GET /ui",
		},
	})
}

func (gw *Gateway) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, gw.currentStatus())
}

func (gw *Gateway) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	aiEnabled := strings.TrimSpace(gw.cfg.AI.Provider) != "" &&
		gw.cfg.AI.Provider != "none" &&
		((gw.cfg.AI.Provider == "openai" && gw.cfg.AI.OpenAIKey != "") || gw.cfg.AI.Provider != "openai")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            gw.currentStatus(),
		"mode":              gw.cfg.Agent.Mode,
		"targets":           gw.cfg.Agent.ScanTargets,
		"supported_targets": []string{"own_repos", "watchlist", "cve_search", "all_accessible"},
		"ai_enabled":        aiEnabled,
		"ai_provider":       gw.cfg.AI.Provider,
	})
}

type agentTriggerRequest struct {
	ScanTargets   []string             `json:"scan_targets"`
	Workers       int                  `json:"workers"`
	SelectedRepos []agent.SelectedRepo `json:"selected_repos"`
}

type agentPreviewRequest struct {
	ScanTargets []string `json:"scan_targets"`
	Limit       int      `json:"limit"`
}

func (gw *Gateway) handleAgentTrigger(w http.ResponseWriter, r *http.Request) {
	if gw.isPaused() {
		writeError(w, http.StatusConflict, "agent is paused")
		return
	}
	var req agentTriggerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateScanTargets(req.ScanTargets); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSelectedRepos(req.SelectedRepos); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Workers < 0 || req.Workers > 64 {
		writeError(w, http.StatusBadRequest, "workers must be between 1 and 64")
		return
	}
	gw.triggerWithOptions(req.ScanTargets, req.Workers, req.SelectedRepos)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":         "triggered",
		"scan_targets":   req.ScanTargets,
		"workers":        req.Workers,
		"selected_repos": len(req.SelectedRepos),
	})
}

func (gw *Gateway) handleAgentPreview(w http.ResponseWriter, r *http.Request) {
	var req agentPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.ScanTargets) == 0 {
		req.ScanTargets = append([]string(nil), gw.cfg.Agent.ScanTargets...)
		if len(req.ScanTargets) == 0 {
			req.ScanTargets = []string{"own_repos"}
		}
	}
	if err := validateScanTargets(req.ScanTargets); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Limit <= 0 {
		req.Limit = 12
	}
	if req.Limit > 50 {
		req.Limit = 50
	}

	providers := gw.orch.RepoProvidersForPreview()
	type repoPreview struct {
		Provider string `json:"provider"`
		Host     string `json:"host"`
		Owner    string `json:"owner"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
		Language string `json:"language"`
		Stars    int    `json:"stars"`
		URL      string `json:"url"`
	}
	type targetPreview struct {
		Target    string        `json:"target"`
		RepoCount int           `json:"repo_count"`
		Samples   []repoPreview `json:"samples"`
		Errors    []string      `json:"errors,omitempty"`
	}

	resp := struct {
		RequestedTargets []string        `json:"requested_targets"`
		Limit            int             `json:"limit"`
		Targets          []targetPreview `json:"targets"`
	}{RequestedTargets: req.ScanTargets, Limit: req.Limit}

	for _, target := range req.ScanTargets {
		tp := targetPreview{Target: target, Samples: []repoPreview{}}
		seen := map[string]struct{}{}
		appendRepo := func(providerName string, host string, owner string, name string, fullName string, private bool, language string, stars int, url string) {
			key := providerName + "|" + host + "|" + owner + "|" + name
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			tp.RepoCount++
			if len(tp.Samples) >= req.Limit {
				return
			}
			tp.Samples = append(tp.Samples, repoPreview{
				Provider: providerName, Host: host, Owner: owner, Name: name, FullName: fullName, Private: private, Language: language, Stars: stars, URL: url,
			})
		}

		switch target {
		case "own_repos":
			for _, p := range providers {
				repos, err := p.ListRepos(r.Context(), repository.ListReposOptions{PerPage: 100, Visibility: "all"})
				if err != nil {
					tp.Errors = append(tp.Errors, err.Error())
					continue
				}
				for _, repo := range repos {
					appendRepo(repo.Provider, repo.Host, repo.Owner, repo.Name, repo.FullName, repo.Private, repo.Language, repo.Stars, repo.HTMLURL)
				}
			}
		case "all_accessible":
			for _, p := range providers {
				repos, err := p.ListRepos(r.Context(), repository.ListReposOptions{
					PerPage: 100, Page: 1, Visibility: "all", Affiliation: "owner,collaborator,organization_member",
				})
				if err != nil {
					tp.Errors = append(tp.Errors, err.Error())
					continue
				}
				for _, repo := range repos {
					appendRepo(repo.Provider, repo.Host, repo.Owner, repo.Name, repo.FullName, repo.Private, repo.Language, repo.Stars, repo.HTMLURL)
				}
			}
		case "watchlist":
			for _, entry := range gw.cfg.Agent.Watchlist {
				for _, p := range providers {
					repos, err := p.SearchRepos(r.Context(), entry)
					if err != nil {
						tp.Errors = append(tp.Errors, fmt.Sprintf("%s: %v", entry, err))
						continue
					}
					for _, repo := range repos {
						appendRepo(repo.Provider, repo.Host, repo.Owner, repo.Name, repo.FullName, repo.Private, repo.Language, repo.Stars, repo.HTMLURL)
					}
				}
			}
		case "cve_search":
			queries := []string{
				"topic:security language:Go",
				"topic:security language:JavaScript stars:>100",
				"topic:security language:Python stars:>100",
			}
			for _, q := range queries {
				for _, p := range providers {
					repos, err := p.SearchRepos(r.Context(), q)
					if err != nil {
						tp.Errors = append(tp.Errors, fmt.Sprintf("%s: %v", q, err))
						continue
					}
					for _, repo := range repos {
						appendRepo(repo.Provider, repo.Host, repo.Owner, repo.Name, repo.FullName, repo.Private, repo.Language, repo.Stars, repo.HTMLURL)
					}
				}
			}
		}
		resp.Targets = append(resp.Targets, tp)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (gw *Gateway) handleAgentStop(w http.ResponseWriter, r *http.Request) {
	if gw.orch.StopCurrentSweep() {
		now := time.Now().UTC().Format(time.RFC3339)
		_ = gw.db.Exec(r.Context(),
			`UPDATE scan_jobs
			 SET status = 'stopped',
			     completed_at = COALESCE(completed_at, ?),
			     error_msg = CASE WHEN error_msg = '' THEN 'stopped by user' ELSE error_msg END
			 WHERE status = 'running'`, now)
		gw.broadcaster.send(SSEEvent{Type: "agent.stop_requested"})
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "stopping"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "idle"})
}

func (gw *Gateway) handleAgentPause(w http.ResponseWriter, r *http.Request) {
	gw.setPaused(true)
	gw.broadcaster.send(SSEEvent{Type: "agent.paused"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (gw *Gateway) handleAgentResume(w http.ResponseWriter, r *http.Request) {
	gw.setPaused(false)
	gw.broadcaster.send(SSEEvent{Type: "agent.resumed"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "running"})
}

type agentWorkersRequest struct {
	Workers int `json:"workers"`
}

func (gw *Gateway) handleAgentWorkers(w http.ResponseWriter, r *http.Request) {
	var req agentWorkersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Workers < 1 || req.Workers > 64 {
		writeError(w, http.StatusBadRequest, "workers must be between 1 and 64")
		return
	}
	gw.mu.Lock()
	gw.cfg.Agent.Workers = req.Workers
	cfgPath := gw.configPath
	cfgCopy := *gw.cfg
	gw.mu.Unlock()
	if err := cfgpkg.Save(&cfgCopy, cfgPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving config: %v", err))
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "agent.workers.updated", Payload: map[string]any{"workers": req.Workers}})
	writeJSON(w, http.StatusOK, map[string]any{"workers": req.Workers})
}

func (gw *Gateway) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	gw.mu.RLock()
	cfgCopy := *gw.cfg
	cfgCopy.AI.OpenAIKey = redactSecret(cfgCopy.AI.OpenAIKey)
	cfgCopy.Git.GitHub = cloneGitHubConfigRedacted(cfgCopy.Git.GitHub)
	cfgCopy.Git.GitLab = cloneGitLabConfigRedacted(cfgCopy.Git.GitLab)
	cfgCopy.Git.Azure = cloneAzureConfigRedacted(cfgCopy.Git.Azure)
	cfgPath := gw.configPath
	gw.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"path":   cfgPath,
		"config": cfgCopy,
	})
}

type logFileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

type logsResponse struct {
	LogDir       string         `json:"log_dir"`
	SelectedFile string         `json:"selected_file,omitempty"`
	Tail         int            `json:"tail"`
	Files        []logFileEntry `json:"files"`
	Lines        []string       `json:"lines"`
}

func (gw *Gateway) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fileName := strings.TrimSpace(q.Get("file"))
	tail := 200
	if raw := strings.TrimSpace(q.Get("tail")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "tail must be a positive integer")
			return
		}
		if n > 5000 {
			n = 5000
		}
		tail = n
	}

	gw.mu.RLock()
	logDir := gw.logDir
	gw.mu.RUnlock()
	if logDir == "" {
		logDir = "logs"
	}

	files, err := listLogFiles(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, logsResponse{
				LogDir: logDir, Tail: tail, Files: []logFileEntry{}, Lines: []string{},
			})
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("listing logs: %v", err))
		return
	}

	if fileName == "" {
		for _, f := range files {
			if f.Name == "gateway.log" {
				fileName = f.Name
				break
			}
		}
		if fileName == "" && len(files) > 0 {
			fileName = files[0].Name
		}
	}

	if fileName != "" {
		clean := filepath.Base(fileName)
		if clean != fileName || strings.Contains(fileName, "..") {
			writeError(w, http.StatusBadRequest, "invalid file name")
			return
		}
		fileName = clean
	}

	var lines []string
	if fileName != "" {
		lines, err = tailFileLines(filepath.Join(logDir, fileName), tail)
		if err != nil {
			if os.IsNotExist(err) {
				writeError(w, http.StatusNotFound, "log file not found")
				return
			}
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("reading log file: %v", err))
			return
		}
	}

	writeJSON(w, http.StatusOK, logsResponse{
		LogDir:       logDir,
		SelectedFile: fileName,
		Tail:         tail,
		Files:        files,
		Lines:        lines,
	})
}

func listLogFiles(dir string) ([]logFileEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type row struct {
		logFileEntry
		mod time.Time
	}
	rows := make([]row, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rows = append(rows, row{
			logFileEntry: logFileEntry{
				Name:    name,
				Size:    info.Size(),
				ModTime: info.ModTime().UTC().Format(time.RFC3339),
			},
			mod: info.ModTime(),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name == "gateway.log" {
			return true
		}
		if rows[j].Name == "gateway.log" {
			return false
		}
		return rows[i].mod.After(rows[j].mod)
	})
	out := make([]logFileEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.logFileEntry)
	}
	return out, nil
}

func tailFileLines(path string, tail int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if tail <= 0 || len(lines) <= tail {
		if lines == nil {
			return []string{}, nil
		}
		return lines, nil
	}
	return lines[len(lines)-tail:], nil
}

func (gw *Gateway) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var req cfgpkg.Config
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Agent.Workers <= 0 {
		req.Agent.Workers = 3
	}
	if req.Agent.Mode == "" {
		req.Agent.Mode = "triage"
	}
	switch req.Agent.Mode {
	case "triage", "semi", "auto":
	default:
		writeError(w, http.StatusBadRequest, "invalid agent.mode")
		return
	}
	if req.Gateway.Port == 0 {
		req.Gateway.Port = gw.cfg.Gateway.Port
	}
	mergeMaskedSecrets(&req, gw.cfg)

	gw.mu.Lock()
	*gw.cfg = req
	cfgPath := gw.configPath
	gw.mu.Unlock()
	if err := cfgpkg.Save(&req, cfgPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving config: %v", err))
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "config.updated"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func mergeMaskedSecrets(dst *cfgpkg.Config, current *cfgpkg.Config) {
	if dst == nil || current == nil {
		return
	}
	if strings.Contains(dst.AI.OpenAIKey, "*") {
		dst.AI.OpenAIKey = current.AI.OpenAIKey
	}

	for i := range dst.Git.GitHub {
		if i < len(current.Git.GitHub) && strings.Contains(dst.Git.GitHub[i].Token, "*") {
			dst.Git.GitHub[i].Token = current.Git.GitHub[i].Token
		}
	}
	for i := range dst.Git.GitLab {
		if i < len(current.Git.GitLab) && strings.Contains(dst.Git.GitLab[i].Token, "*") {
			dst.Git.GitLab[i].Token = current.Git.GitLab[i].Token
		}
	}
	for i := range dst.Git.Azure {
		if i < len(current.Git.Azure) && strings.Contains(dst.Git.Azure[i].Token, "*") {
			dst.Git.Azure[i].Token = current.Git.Azure[i].Token
		}
	}
}

func redactSecret(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 8 {
		return "********"
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}

func cloneGitHubConfigRedacted(in []cfgpkg.GitHubConfig) []cfgpkg.GitHubConfig {
	out := make([]cfgpkg.GitHubConfig, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Token = redactSecret(v.Token)
	}
	return out
}

func cloneGitLabConfigRedacted(in []cfgpkg.GitLabConfig) []cfgpkg.GitLabConfig {
	out := make([]cfgpkg.GitLabConfig, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Token = redactSecret(v.Token)
	}
	return out
}

func cloneAzureConfigRedacted(in []cfgpkg.AzureConfig) []cfgpkg.AzureConfig {
	out := make([]cfgpkg.AzureConfig, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Token = redactSecret(v.Token)
	}
	return out
}

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

type paginationResult[T any] struct {
	Items      []T `json:"items"`
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

type paginationParams struct {
	Page     int
	PageSize int
	Offset   int
}

func parsePaginationParams(r *http.Request, defaultPageSize, maxPageSize int) paginationParams {
	q := r.URL.Query()
	page := 1
	pageSize := defaultPageSize

	if v := strings.TrimSpace(q.Get("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := strings.TrimSpace(q.Get("page_size")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	} else if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if maxPageSize > 0 && pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return paginationParams{
				Page:     (n / pageSize) + 1,
				PageSize: pageSize,
				Offset:   n,
			}
		}
	}

	return paginationParams{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

func (gw *Gateway) handleListJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	status := q.Get("status")
	pg := parsePaginationParams(r, 20, 200)

	baseSelect := `SELECT id, unique_key, provider, owner, repo, branch, status,
	           findings_critical, findings_high, findings_medium, findings_low,
	           started_at, completed_at, error_msg
	          FROM scan_jobs`
	baseCount := `SELECT COUNT(*) AS n FROM scan_jobs`
	var args []any
	if status != "" {
		baseSelect += " WHERE status = ?"
		baseCount += " WHERE status = ?"
		args = append(args, status)
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
	args = append(args, pg.PageSize, pg.Offset)

	var jobs []scanJobRow
	if err := gw.db.Select(ctx, &jobs, query, args...); err != nil {
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

type jobUnifiedFinding struct {
	ID        int64  `json:"id"`
	ScanJobID int64  `json:"scan_job_id"`
	Kind      string `json:"kind"`
	Scanner   string `json:"scanner,omitempty"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	FilePath  string `json:"file_path"`
	Line      int    `json:"line,omitempty"`
	Message   string `json:"message,omitempty"`
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	Fix       string `json:"fix,omitempty"`
	Status    string `json:"status"`
	FirstSeen string `json:"first_seen"`
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

func normalizeDeleteIDs(ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, fmt.Errorf("ids must contain positive integers")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func diffInt64(requested, existing []int64) []int64 {
	if len(requested) == 0 {
		return []int64{}
	}
	have := make(map[int64]struct{}, len(existing))
	for _, id := range existing {
		have[id] = struct{}{}
	}
	out := make([]int64, 0)
	for _, id := range requested {
		if _, ok := have[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func toAnyArgs(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}

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
		"sca_vulns",
		"sast_findings",
		"secrets_findings",
		"iac_findings",
		"fix_queue",
		"scan_jobs",
	} {
		if err := gw.db.Exec(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	return nil
}

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

	if kind == "" || kind == "sca" {
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
	if kind == "" || kind == "sast" {
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
	if kind == "" || kind == "secrets" {
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
	if kind == "" || kind == "iac" {
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
	if scanner != "" {
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

func (gw *Gateway) handleListJobFixes(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var rows []fixQueueRow
	if err := gw.db.Select(r.Context(), &rows,
		`SELECT id, scan_job_id, finding_type, finding_id, pr_title, pr_body,
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
		switch rr.ScannerName {
		case "opengrep":
			out = append(out, parseOpengrepRawFindings(scanJobID, rr.RawOutput, now)...)
		case "grype":
			out = append(out, parseGrypeRawFindings(scanJobID, rr.RawOutput, now)...)
		case "trivy":
			out = append(out, parseTrivyRawFindings(scanJobID, rr.RawOutput, now)...)
		case "trufflehog":
			out = append(out, parseTrufflehogRawFindings(scanJobID, rr.RawOutput, now)...)
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
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

// scanTriggerRequest is the body for POST /api/scan.
type scanTriggerRequest struct {
	// RepoURL is optional: if provided, that specific repo is added to the
	// queue. If empty, the orchestrator runs a full discovery sweep.
	RepoURL string `json:"repo_url"`
}

func (gw *Gateway) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	var req scanTriggerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RepoURL != "" {
		// Best-effort: add the repo directly to repo_queue so the next sweep
		// picks it up, even if it bypasses normal discovery.
		if err := gw.enqueueRepoURL(r.Context(), req.RepoURL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	gw.trigger()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "triggered"})
}

func validateScanTargets(targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	allowed := map[string]struct{}{
		"own_repos":      {},
		"watchlist":      {},
		"cve_search":     {},
		"all_accessible": {},
	}
	seen := map[string]struct{}{}
	for _, t := range targets {
		if _, ok := allowed[t]; !ok {
			return fmt.Errorf("invalid scan target %q", t)
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("duplicate scan target %q", t)
		}
		seen[t] = struct{}{}
	}
	return nil
}

func validateSelectedRepos(repos []agent.SelectedRepo) error {
	if len(repos) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for i, r := range repos {
		r.Provider = strings.TrimSpace(r.Provider)
		r.Host = strings.TrimSpace(r.Host)
		r.Owner = strings.TrimSpace(r.Owner)
		r.Name = strings.TrimSpace(r.Name)
		if r.Provider == "" || r.Owner == "" || r.Name == "" {
			return fmt.Errorf("selected_repos[%d] must include provider, owner, and name", i)
		}
		key := strings.ToLower(r.Provider + "|" + r.Host + "|" + r.Owner + "|" + r.Name)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate selected repo %q", r.Owner+"/"+r.Name)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// enqueueRepoURL parses a GitHub/GitLab/Azure HTTPS URL and inserts a
// pending row into repo_queue.
func (gw *Gateway) enqueueRepoURL(ctx context.Context, rawURL string) error {
	// Minimal URL parse: https://github.com/owner/name
	raw := strings.TrimSuffix(rawURL, ".git")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	parts := strings.SplitN(raw, "/", 3)
	if len(parts) != 3 {
		return fmt.Errorf("repo_url must be https://host/owner/name")
	}
	host, owner, name := parts[0], parts[1], parts[2]

	provider := "github"
	switch {
	case strings.Contains(host, "gitlab"):
		provider = "gitlab"
	case strings.Contains(host, "azure") || strings.Contains(host, "visualstudio"):
		provider = "azure"
	}

	type queueRow struct {
		Provider      string `db:"provider"`
		Host          string `db:"host"`
		Owner         string `db:"owner"`
		Name          string `db:"name"`
		FullName      string `db:"full_name"`
		CloneURL      string `db:"clone_url"`
		DefaultBranch string `db:"default_branch"`
		Status        string `db:"status"`
		Priority      int    `db:"priority"`
		DiscoveredAt  string `db:"discovered_at"`
	}

	row := queueRow{
		Provider:      provider,
		Host:          host,
		Owner:         owner,
		Name:          name,
		FullName:      owner + "/" + name,
		CloneURL:      "https://" + host + "/" + owner + "/" + name + ".git",
		DefaultBranch: "main",
		Status:        "pending",
		Priority:      10, // elevated — user-requested
		DiscoveredAt:  time.Now().UTC().Format(time.RFC3339),
	}

	return gw.db.Exec(ctx,
		`INSERT INTO repo_queue (provider, host, owner, name, full_name, clone_url, default_branch, status, priority, discovered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(provider, host, owner, name) DO UPDATE SET status = 'pending', priority = 10`,
		row.Provider, row.Host, row.Owner, row.Name, row.FullName,
		row.CloneURL, row.DefaultBranch, row.Status, row.Priority, row.DiscoveredAt,
	)
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

// fixQueueRow maps a row from the fix_queue table.
type fixQueueRow struct {
	ID          int64   `db:"id"           json:"id"`
	ScanJobID   int64   `db:"scan_job_id"  json:"scan_job_id"`
	FindingType string  `db:"finding_type" json:"finding_type"`
	FindingID   int64   `db:"finding_id"   json:"finding_id"`
	PRTitle     string  `db:"pr_title"     json:"pr_title"`
	PRBody      string  `db:"pr_body"      json:"pr_body"`
	Status      string  `db:"status"       json:"status"`
	PRURL       string  `db:"pr_url"       json:"pr_url,omitempty"`
	GeneratedAt string  `db:"generated_at" json:"generated_at"`
	ApprovedAt  *string `db:"approved_at"  json:"approved_at,omitempty"`
}

func (gw *Gateway) handleListFixQueue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}

	var rows []fixQueueRow
	if err := gw.db.Select(ctx, &rows,
		`SELECT id, scan_job_id, finding_type, finding_id, pr_title, pr_body,
		        status, pr_url, generated_at, approved_at
		 FROM fix_queue WHERE status = ? ORDER BY id DESC LIMIT 100`,
		status,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []fixQueueRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleFixApprove(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := gw.db.Exec(r.Context(),
		"UPDATE fix_queue SET status = 'approved', approved_at = ? WHERE id = ?", now, id,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{
		Type:    "fix.approved",
		Payload: map[string]any{"id": id},
	})
	gw.trigger() // wake orchestrator so PRAgent can pick this up
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (gw *Gateway) handleFixApproveAndRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := gw.db.Exec(r.Context(),
		"UPDATE fix_queue SET status = 'approved', approved_at = ? WHERE id = ?", now, id,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "fix.approved", Payload: map[string]any{"id": id}})
	gw.triggerPRProcessing()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "approved_and_pr_processing"})
}

func (gw *Gateway) handleFixReject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.db.Exec(r.Context(),
		"UPDATE fix_queue SET status = 'rejected' WHERE id = ?", id,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{
		Type:    "fix.rejected",
		Payload: map[string]any{"id": id},
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

// scheduleRequest is the body for POST /api/schedules.
type scheduleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Expr        string `json:"expr"`
	Targets     string `json:"targets"`
	Mode        string `json:"mode"`
	Enabled     bool   `json:"enabled"`
}

func (gw *Gateway) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	schedules, err := gw.scheduler.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if schedules == nil {
		schedules = []Schedule{}
	}
	writeJSON(w, http.StatusOK, schedules)
}

func (gw *Gateway) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Expr == "" {
		writeError(w, http.StatusBadRequest, "name and expr are required")
		return
	}
	if req.Targets == "" {
		req.Targets = "[]"
	}

	sched := Schedule{
		Name:        req.Name,
		Description: req.Description,
		Expr:        req.Expr,
		Targets:     req.Targets,
		Mode:        req.Mode,
		Enabled:     req.Enabled,
	}
	id, err := gw.scheduler.Add(r.Context(), sched)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sched.ID = id
	gw.broadcaster.send(SSEEvent{Type: "schedule.created", Payload: map[string]any{"id": id}})
	writeJSON(w, http.StatusCreated, sched)
}

func (gw *Gateway) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.scheduler.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "schedule.deleted", Payload: map[string]any{"id": id}})
	w.WriteHeader(http.StatusNoContent)
}

func (gw *Gateway) handleTriggerSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.scheduler.TriggerNow(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "triggered"})
}

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
	ID          int64   `db:"id" json:"id"`
	CampaignID  int64   `db:"campaign_id" json:"campaign_id"`
	ScanJobID   int64   `db:"scan_job_id" json:"scan_job_id"`
	Provider    string  `db:"provider" json:"provider"`
	Owner       string  `db:"owner" json:"owner"`
	Repo        string  `db:"repo" json:"repo"`
	Branch      string  `db:"branch" json:"branch"`
	CloneURL    string  `db:"clone_url" json:"clone_url,omitempty"`
	Status      string  `db:"status" json:"status"`
	WorkerName  string  `db:"worker_name" json:"worker_name,omitempty"`
	ErrorMsg    string  `db:"error_msg" json:"error_msg,omitempty"`
	CreatedAt   string  `db:"created_at" json:"created_at"`
	StartedAt   *string `db:"started_at" json:"started_at,omitempty"`
	CompletedAt *string `db:"completed_at" json:"completed_at,omitempty"`
}

type remediationCampaignCreateRequest struct {
	Name       string   `json:"name"`
	Mode       string   `json:"mode"`    // triage|semi|auto
	AutoPR     bool     `json:"auto_pr"` // trigger PR processing for approved fixes
	StartNow   bool     `json:"start_now"`
	Repos      []string `json:"repos"` // owner/repo list (optional)
	ScanJobIDs []int64  `json:"scan_job_ids,omitempty"`
	MaxRepos   int      `json:"max_repos"` // optional limit
	LatestOnly bool     `json:"latest_only"`
	Scanners   []string `json:"scanners,omitempty"`
	Kinds      []string `json:"kinds,omitempty"`
	Severities []string `json:"severities,omitempty"`
}

func (gw *Gateway) handleAgentWorkersList(w http.ResponseWriter, r *http.Request) {
	rows := gw.workerStatuses()
	if rows == nil {
		rows = []agent.WorkerStatus{}
	}
	writeJSON(w, http.StatusOK, rows)
}

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
	if err := gw.db.Select(r.Context(), &rows, `SELECT * FROM remediation_tasks WHERE campaign_id = ? ORDER BY id ASC`, id); err != nil {
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
	gw.broadcaster.send(SSEEvent{Type: "campaign.stopped", Payload: map[string]any{"campaign_id": id}})
	writeJSON(w, http.StatusOK, map[string]any{"status": "stopped", "id": id})
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

// handleEvents streams SSE to the client. Each line is a JSON SSEEvent.
// Clients receive a "connected" event immediately, then live updates.
func (gw *Gateway) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if behind a proxy

	ch := gw.broadcaster.subscribe()
	defer gw.broadcaster.unsubscribe(ch)

	// Send initial connected event with current status.
	status := gw.currentStatus()
	connected, _ := json.Marshal(SSEEvent{Type: "connected", Payload: status})
	// SSE endpoint writes JSON event frames, not HTML; HTML escaping is not applicable here.
	// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
	fmt.Fprintf(w, "data: %s\n\n", connected)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case frame, ok := <-ch:
			if !ok {
				return
			}
			// SSE endpoint streams prebuilt frames (event-stream), not HTML template output.
			// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
			w.Write(frame)
			flusher.Flush()
		}
	}
}
