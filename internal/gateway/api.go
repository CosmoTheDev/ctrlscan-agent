package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	// Health / status
	mux.HandleFunc("GET /health", gw.handleHealth)
	mux.HandleFunc("GET /api/status", gw.handleStatus)

	// Scan jobs
	mux.HandleFunc("GET /api/jobs", gw.handleListJobs)
	mux.HandleFunc("DELETE /api/jobs", gw.handleDeleteJobs)
	mux.HandleFunc("GET /api/jobs/summary", gw.handleJobsSummary)
	mux.HandleFunc("GET /api/jobs/{id}", gw.handleGetJob)
	mux.HandleFunc("DELETE /api/jobs/{id}", gw.handleDeleteJob)
	mux.HandleFunc("GET /api/jobs/{id}/scanners", gw.handleListJobScanners)
	mux.HandleFunc("GET /api/jobs/{id}/findings", gw.handleListJobFindings)
	mux.HandleFunc("GET /api/jobs/{id}/fixes", gw.handleListJobFixes)
	mux.HandleFunc("GET /api/jobs/{id}/raw/{scanner}", gw.handleGetJobRawScannerOutput)
	mux.HandleFunc("POST /api/scan", gw.handleTriggerScan)

	// Agent runtime controls
	mux.HandleFunc("GET /api/agent", gw.handleAgentStatus)
	mux.HandleFunc("POST /api/agent/preview", gw.handleAgentPreview)
	mux.HandleFunc("POST /api/agent/trigger", gw.handleAgentTrigger)
	mux.HandleFunc("POST /api/agent/stop", gw.handleAgentStop)
	mux.HandleFunc("POST /api/agent/pause", gw.handleAgentPause)
	mux.HandleFunc("POST /api/agent/resume", gw.handleAgentResume)
	mux.HandleFunc("PUT /api/agent/workers", gw.handleAgentWorkers)

	// Findings (read-only aggregated view)
	mux.HandleFunc("GET /api/findings", gw.handleListFindings)
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

func (gw *Gateway) handleListJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	status := q.Get("status")
	limit := 50

	query := `SELECT id, unique_key, provider, owner, repo, branch, status,
	           findings_critical, findings_high, findings_medium, findings_low,
	           started_at, completed_at, error_msg
	          FROM scan_jobs`
	var args []any
	if status != "" {
		query += " WHERE status = ?"
		args = append(args, status)
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	var jobs []scanJobRow
	if err := gw.db.Select(ctx, &jobs, query, args...); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if jobs == nil {
		jobs = []scanJobRow{}
	}
	writeJSON(w, http.StatusOK, jobs)
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
	severity := strings.TrimSpace(q.Get("severity"))
	status := strings.TrimSpace(q.Get("status"))
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
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, vulnerability_id, package_name, status, first_seen_at FROM sca_vulns")+" ORDER BY id DESC LIMIT 500")
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
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, check_id, file_path, status, first_seen_at FROM sast_findings")+" ORDER BY id DESC LIMIT 500")
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
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, detector_name, file_path, status, first_seen_at FROM secrets_findings")+" ORDER BY id DESC LIMIT 500")
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
		_ = gw.db.Select(ctx, &rows, addFilter("SELECT id, scan_job_id, severity, title, file_path, status, first_seen_at FROM iac_findings")+" ORDER BY id DESC LIMIT 500")
		for _, row := range rows {
			results = append(results, jobUnifiedFinding{ID: row.ID, ScanJobID: row.ScanJobID, Kind: "iac", Scanner: "trivy", Severity: row.Severity, Title: row.Title, FilePath: row.FilePath, Status: row.Status, FirstSeen: row.FirstSeen})
		}
	}
	if len(results) == 0 {
		if parsed, err := gw.loadFindingsFromRawOutputs(ctx, id); err == nil && len(parsed) > 0 {
			results = parsed
		}
	}
	if results == nil {
		results = []jobUnifiedFinding{}
	}
	writeJSON(w, http.StatusOK, results)
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
