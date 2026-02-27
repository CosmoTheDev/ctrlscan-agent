package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
	cfgpkg "github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
)

// --- Request types ---

type agentTriggerRequest struct {
	ScanTargets   []string             `json:"scan_targets"`
	Workers       int                  `json:"workers"`
	SelectedRepos []agent.SelectedRepo `json:"selected_repos"`
	ForceScan     bool                 `json:"force_scan"`
	Profile       string               `json:"profile"`
}

type agentPreviewRequest struct {
	ScanTargets []string `json:"scan_targets"`
	Limit       int      `json:"limit"`
}

type agentWorkersRequest struct {
	Workers int `json:"workers"`
}

// scanTriggerRequest is the body for POST /api/scan.
type scanTriggerRequest struct {
	// RepoURL is optional: if provided, that specific repo is added to the
	// queue. If empty, the orchestrator runs a full discovery sweep.
	RepoURL string `json:"repo_url"`
}

// --- Handlers ---

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
			"PUT /api/schedules/{id}",
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

func (gw *Gateway) handleAgentHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, gw.heartbeat.computeStatus())
}

func (gw *Gateway) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	aiEnabled := strings.TrimSpace(gw.cfg.AI.Provider) != "" &&
		gw.cfg.AI.Provider != "none" &&
		((gw.cfg.AI.Provider == "openai" && gw.cfg.AI.OpenAIKey != "") || gw.cfg.AI.Provider != "openai")

	status := gw.currentStatus()
	aiProvider, aiFallbackMode := "", false
	if gw.orch != nil {
		aiProvider, aiFallbackMode = gw.orch.AIProviderStatus()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":            status,
		"mode":              gw.cfg.Agent.Mode,
		"targets":           gw.cfg.Agent.ScanTargets,
		"supported_targets": []string{"own_repos", "watchlist", "cve_search", "all_accessible"},
		"ai_enabled":        aiEnabled,
		"ai_provider":       aiProvider,
		"ai_fallback_mode":  aiFallbackMode,
	})
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
	gw.triggerWithOptions(req.ScanTargets, req.Workers, req.SelectedRepos, req.ForceScan, "", req.Profile)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":         "triggered",
		"scan_targets":   req.ScanTargets,
		"workers":        req.Workers,
		"selected_repos": len(req.SelectedRepos),
		"force_scan":     req.ForceScan,
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

func (gw *Gateway) handleAgentWorkersList(w http.ResponseWriter, r *http.Request) {
	rows := gw.workerStatuses()
	if rows == nil {
		rows = []agent.WorkerStatus{}
	}
	writeJSON(w, http.StatusOK, rows)
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

// --- Validation helpers ---

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

func isValidAgentMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "", "triage", "semi", "auto":
		return true
	default:
		return false
	}
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
