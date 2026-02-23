package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/scanner"
)

// Orchestrator coordinates the discovery → scan → fix → PR pipeline.
type Orchestrator struct {
	cfg       *config.Config
	db        database.DB
	triggerCh chan struct{}
	opts      OrchestratorOptions

	mu                sync.Mutex
	activeSweepCancel context.CancelFunc
	pendingTrigger    *TriggerRequest
	prTriggerCh       chan struct{}
	workerStates      map[string]WorkerStatus
}

// OrchestratorOptions controls loop behavior for different runtimes (CLI agent vs gateway).
type OrchestratorOptions struct {
	RunInitialSweep    bool
	EnablePolling      bool
	OnSweepStarted     func(payload map[string]any)
	OnSweepCompleted   func(payload map[string]any)
	OnRepoSkipped      func(payload map[string]any)
	OnWorkerStatus     func(payload map[string]any)
	OnRemediationEvent func(eventType string, payload map[string]any)
}

// WorkerStatus reports what a background worker is doing right now.
type WorkerStatus struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Status          string `json:"status"`
	Action          string `json:"action"`
	Repo            string `json:"repo,omitempty"`
	ScanJobID       int64  `json:"scan_job_id,omitempty"`
	CampaignID      int64  `json:"campaign_id,omitempty"`
	TaskID          int64  `json:"task_id,omitempty"`
	Message         string `json:"message,omitempty"`
	ProgressPhase   string `json:"progress_phase,omitempty"`
	ProgressCurrent int    `json:"progress_current,omitempty"`
	ProgressTotal   int    `json:"progress_total,omitempty"`
	ProgressPercent int    `json:"progress_percent,omitempty"`
	ProgressNote    string `json:"progress_note,omitempty"`
	UpdatedAt       string `json:"updated_at"`
}

// TriggerRequest optionally overrides scan settings for the next sweep only.
type TriggerRequest struct {
	ScanTargets   []string
	Workers       int
	SelectedRepos []SelectedRepo
	ForceScan     bool
	Mode          string
}

// SelectedRepo identifies a repo chosen from gateway preview for a one-shot sweep.
type SelectedRepo struct {
	Provider string
	Host     string
	Owner    string
	Name     string
}

// NewOrchestrator creates an Orchestrator.
func NewOrchestrator(cfg *config.Config, db database.DB) *Orchestrator {
	return NewOrchestratorWithOptions(cfg, db, OrchestratorOptions{
		RunInitialSweep: true,
		EnablePolling:   true,
	})
}

// NewOrchestratorWithOptions creates an Orchestrator with explicit loop behavior.
func NewOrchestratorWithOptions(cfg *config.Config, db database.DB, opts OrchestratorOptions) *Orchestrator {
	return &Orchestrator{
		cfg:          cfg,
		db:           db,
		triggerCh:    make(chan struct{}, 1),
		prTriggerCh:  make(chan struct{}, 1),
		workerStates: make(map[string]WorkerStatus),
		opts:         opts,
	}
}

// Trigger requests an immediate discovery sweep, interrupting the current poll
// interval. If a sweep is already in progress the signal is queued (at most one
// pending trigger is kept).
func (o *Orchestrator) Trigger() {
	o.TriggerWithRequest(nil)
}

// TriggerWithRequest requests an immediate sweep and optionally applies one-shot
// overrides (targets/workers) to that next sweep.
func (o *Orchestrator) TriggerWithRequest(req *TriggerRequest) {
	if req != nil {
		o.mu.Lock()
		cp := *req
		if req.ScanTargets != nil {
			cp.ScanTargets = append([]string(nil), req.ScanTargets...)
		}
		if req.SelectedRepos != nil {
			cp.SelectedRepos = append([]SelectedRepo(nil), req.SelectedRepos...)
		}
		cp.ForceScan = req.ForceScan
		cp.Mode = req.Mode
		o.pendingTrigger = &cp
		o.mu.Unlock()
	}
	select {
	case o.triggerCh <- struct{}{}:
	default:
		// Already has a pending trigger — don't block.
	}
}

// StopCurrentSweep cancels the currently running sweep, if any. The orchestrator
// keeps running and remains available for future triggers.
func (o *Orchestrator) StopCurrentSweep() bool {
	o.mu.Lock()
	cancel := o.activeSweepCancel
	o.mu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

// TriggerPRProcessing asks the PR worker to process approved fixes immediately.
func (o *Orchestrator) TriggerPRProcessing() {
	select {
	case o.prTriggerCh <- struct{}{}:
	default:
	}
}

// Run starts the agent loop. It runs an initial sweep then waits for either a
// Trigger() call or the poll interval before running the next sweep. Blocks
// until ctx is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	slog.Info("Orchestrator starting",
		"mode", o.cfg.Agent.Mode,
		"workers", o.cfg.Agent.Workers,
	)

	// Initialise AI provider.
	aiProvider, err := ai.New(o.cfg.AI)
	if err != nil {
		return fmt.Errorf("initialising AI provider: %w", err)
	}
	if !aiProvider.IsAvailable(ctx) {
		if o.cfg.AI.Provider != "" && o.cfg.AI.Provider != "none" {
			slog.Warn("AI provider is not reachable — running in scan-only mode",
				"provider", o.cfg.AI.Provider)
		} else {
			slog.Info("No AI provider configured — running in scan-only mode")
		}
		if o.cfg.Agent.Mode == "semi" || o.cfg.Agent.Mode == "auto" {
			slog.Warn("Agent mode requires AI to generate fixes and PRs",
				"mode", o.cfg.Agent.Mode)
		}
	}

	// Build repository providers.
	repoProviders := o.buildRepoProviders()
	if len(repoProviders) == 0 {
		return fmt.Errorf("no git providers configured; run 'ctrlscan onboard'")
	}

	scannerWorkers := scanner.BuildScanners(o.cfg.Agent.Scanners, o.cfg.Tools.BinDir, o.cfg.Tools.PreferDocker)
	aiProv := aiProvider

	// PR worker runs independently of sweeps so UI approvals can create PRs
	// without waiting for the next sweep trigger.
	go o.runPRLoop(ctx, aiProv)
	go o.runRemediationLoop(ctx, aiProv, repoProviders)

	// Run sweeps: initial + on trigger or poll interval (depending on options).
	firstLoop := true
	for {
		req := o.consumePendingTrigger()
		if !firstLoop || o.opts.RunInitialSweep {
			if err := o.runSweep(ctx, repoProviders, scannerWorkers, aiProv, req); err != nil && ctx.Err() == nil {
				slog.Error("Sweep error", "error", err)
			}
		} else {
			slog.Info("Orchestrator idle on startup; waiting for trigger or schedule")
		}
		firstLoop = false

		if !o.opts.EnablePolling {
			select {
			case <-ctx.Done():
				slog.Info("Orchestrator received shutdown signal")
				return nil
			case <-o.triggerCh:
				slog.Info("Orchestrator: triggered, starting next sweep immediately")
			}
			continue
		}

		select {
		case <-ctx.Done():
			slog.Info("Orchestrator received shutdown signal")
			return nil
		case <-o.triggerCh:
			slog.Info("Orchestrator: triggered, starting next sweep immediately")
		case <-time.After(pollInterval):
			slog.Info("Orchestrator: poll interval elapsed, starting sweep")
		}
	}
}

func (o *Orchestrator) runPRLoop(ctx context.Context, aiProv ai.AIProvider) {
	prAgent := NewPRAgent(o.cfg, o.db, aiProv)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	o.setWorkerStatus(WorkerStatus{
		Name: "pr-0", Kind: "pr", Status: "waiting", Action: "waiting for approved fixes",
	})
	for {
		select {
		case <-ctx.Done():
			o.setWorkerStatus(WorkerStatus{Name: "pr-0", Kind: "pr", Status: "stopped", Action: "shutdown"})
			return
		case <-ticker.C:
			o.setWorkerStatus(WorkerStatus{Name: "pr-0", Kind: "pr", Status: "running", Action: "draining approved fixes"})
			prAgent.drainApprovedFixes(ctx)
			o.setWorkerStatus(WorkerStatus{Name: "pr-0", Kind: "pr", Status: "waiting", Action: "waiting for approved fixes"})
		case <-o.prTriggerCh:
			o.setWorkerStatus(WorkerStatus{Name: "pr-0", Kind: "pr", Status: "running", Action: "processing triggered PR queue"})
			prAgent.drainApprovedFixes(ctx)
			o.setWorkerStatus(WorkerStatus{Name: "pr-0", Kind: "pr", Status: "waiting", Action: "waiting for approved fixes"})
		}
	}
}

func (o *Orchestrator) runRemediationLoop(ctx context.Context, aiProv ai.AIProvider, repoProviders []repository.RepoProvider) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	workerName := "remediation-0"
	// Recover tasks that were mid-flight when the gateway exited. They keep
	// their persisted AI progress pointer and will be re-processed safely.
	_ = o.db.Exec(ctx, `UPDATE remediation_tasks
		SET status = 'pending',
		    worker_name = '',
		    error_msg = CASE
		        WHEN status = 'running' AND error_msg = '' THEN 'requeued after restart'
		        ELSE error_msg
		    END
		WHERE status = 'running'`)
	o.setWorkerStatus(WorkerStatus{Name: workerName, Kind: "remediation", Status: "waiting", Action: "waiting for campaigns"})
	for {
		select {
		case <-ctx.Done():
			o.setWorkerStatus(WorkerStatus{Name: workerName, Kind: "remediation", Status: "stopped", Action: "shutdown"})
			return
		case <-ticker.C:
			o.processOneRemediationTask(ctx, aiProv, repoProviders, workerName)
		}
	}
}

// runSweep executes one complete discovery → scan → fix cycle and returns when
// all work from this sweep is done. Each sweep creates fresh in-memory queues
// so sweeps are fully isolated.
func (o *Orchestrator) runSweep(
	ctx context.Context,
	repoProviders []repository.RepoProvider,
	scannerList []scanner.Scanner,
	aiProvider ai.AIProvider,
	req *TriggerRequest,
) error {
	sweepCtx, sweepCancel := context.WithCancel(ctx)
	o.mu.Lock()
	o.activeSweepCancel = sweepCancel
	o.mu.Unlock()
	defer func() {
		sweepCancel()
		o.mu.Lock()
		o.activeSweepCancel = nil
		o.mu.Unlock()
	}()

	effectiveCfg := o.cfg
	sweepStartedAt := time.Now().UTC()
	skippedByReason := map[string]int{}
	var skippedTotal int
	var skipMu sync.Mutex
	if req != nil && (req.Workers > 0 || len(req.ScanTargets) > 0 || strings.TrimSpace(req.Mode) != "") {
		cfgCopy := *o.cfg
		if req.Workers > 0 {
			cfgCopy.Agent.Workers = req.Workers
		}
		if len(req.ScanTargets) > 0 {
			cfgCopy.Agent.ScanTargets = append([]string(nil), req.ScanTargets...)
		}
		if strings.TrimSpace(req.Mode) != "" {
			cfgCopy.Agent.Mode = strings.TrimSpace(req.Mode)
		}
		effectiveCfg = &cfgCopy
		slog.Info("Orchestrator applying one-shot trigger overrides",
			"workers", effectiveCfg.Agent.Workers,
			"targets", effectiveCfg.Agent.ScanTargets,
			"mode", effectiveCfg.Agent.Mode,
		)
	}

	repoQueue := make(chan repoJob, 256)
	fixQueue := make(chan fixJob, 512)

	workers := effectiveCfg.Agent.Workers
	if workers <= 0 {
		workers = 3
	}
	if o.opts.OnSweepStarted != nil {
		payload := map[string]any{
			"workers":    workers,
			"started_at": sweepStartedAt.Format(time.RFC3339),
		}
		if req != nil {
			if len(req.ScanTargets) > 0 {
				payload["scan_targets"] = append([]string(nil), req.ScanTargets...)
			}
			if len(req.SelectedRepos) > 0 {
				payload["selected_repos"] = len(req.SelectedRepos)
			}
			if req.ForceScan {
				payload["force_scan"] = true
			}
			if strings.TrimSpace(req.Mode) != "" {
				payload["mode"] = strings.TrimSpace(req.Mode)
			}
		}
		o.opts.OnSweepStarted(payload)
	}

	var wg sync.WaitGroup

	// Discovery — runs one full sweep then returns, closing repoQueue.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if req != nil && len(req.SelectedRepos) > 0 {
			o.enqueueSelectedRepos(sweepCtx, repoProviders, req.SelectedRepos, repoQueue)
		} else {
			discovery := NewDiscoveryAgent(effectiveCfg, o.db, repoProviders)
			discovery.RunOnce(sweepCtx, repoQueue)
		}
		close(repoQueue)
	}()

	// Scanner workers — drain repoQueue and write to fixQueue.
	// fixQueue is closed once all scanner workers exit.
	var scanWg sync.WaitGroup
	for i := 0; i < workers; i++ {
		scanWg.Add(1)
		go func(workerID int) {
			defer scanWg.Done()
			forceScan := req != nil && req.ForceScan
			sa := NewScannerAgent(workerID, effectiveCfg, o.db, scannerList, forceScan, func(payload map[string]any) {
				reason := ""
				if v, ok := payload["reason"].(string); ok {
					reason = v
				}
				skipMu.Lock()
				skippedTotal++
				skippedByReason[reason]++
				skipMu.Unlock()
				if o.opts.OnRepoSkipped != nil {
					o.opts.OnRepoSkipped(payload)
				}
			}, func(ws WorkerStatus) {
				o.setWorkerStatus(ws)
			})
			sa.Run(sweepCtx, repoQueue, fixQueue)
		}(i)
	}
	go func() {
		scanWg.Wait()
		close(fixQueue) // signals the fixer that no more jobs are coming
	}()

	// Fixer — drains fixQueue and exits when it is closed.
	wg.Add(1)
	go func() {
		defer wg.Done()
		fixer := NewFixerAgent(effectiveCfg, o.db, aiProvider)
		fixer.Run(sweepCtx, fixQueue)
	}()

	// Wait for discovery + fixer to complete.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		o.emitSweepCompleted(sweepStartedAt, "shutdown", skippedTotal, skippedByReason)
		return nil
	case <-sweepCtx.Done():
		slog.Info("Orchestrator: sweep cancelled")
		o.emitSweepCompleted(sweepStartedAt, "cancelled", skippedTotal, skippedByReason)
		return nil
	case <-done:
		slog.Info("Orchestrator: sweep complete")
		o.emitSweepCompleted(sweepStartedAt, "completed", skippedTotal, skippedByReason)
		return nil
	}
}

func (o *Orchestrator) emitSweepCompleted(start time.Time, status string, skippedTotal int, skippedByReason map[string]int) {
	if o.opts.OnSweepCompleted == nil {
		return
	}
	reasons := map[string]int{}
	for k, v := range skippedByReason {
		if k == "" || v == 0 {
			continue
		}
		reasons[k] = v
	}
	o.opts.OnSweepCompleted(map[string]any{
		"status":            status,
		"started_at":        start.Format(time.RFC3339),
		"completed_at":      time.Now().UTC().Format(time.RFC3339),
		"duration_seconds":  time.Since(start).Seconds(),
		"skipped_repos":     skippedTotal,
		"skipped_by_reason": reasons,
	})
}

func (o *Orchestrator) enqueueSelectedRepos(ctx context.Context, providers []repository.RepoProvider, selected []SelectedRepo, out chan<- repoJob) {
	slog.Info("Discovery bypassed; scanning selected repos only", "count", len(selected))
	for _, sel := range selected {
		if ctx.Err() != nil {
			return
		}
		p := pickProviderForSelectedRepo(providers, sel)
		if p == nil {
			slog.Warn("Selected repo skipped: provider not configured",
				"provider", sel.Provider, "host", sel.Host, "repo", sel.Owner+"/"+sel.Name)
			continue
		}
		repo, err := p.GetRepo(ctx, sel.Owner, sel.Name)
		if err != nil {
			slog.Warn("Selected repo lookup failed",
				"provider", sel.Provider, "repo", sel.Owner+"/"+sel.Name, "error", err)
			continue
		}
		select {
		case out <- repoJob{
			Provider: p,
			Owner:    repo.Owner,
			Name:     repo.Name,
			CloneURL: repo.CloneURL,
			Branch:   repo.DefaultBranch,
		}:
		case <-ctx.Done():
			return
		}
	}
}

func pickProviderForSelectedRepo(providers []repository.RepoProvider, sel SelectedRepo) repository.RepoProvider {
	for _, p := range providers {
		if p.Name() == sel.Provider {
			return p
		}
	}
	return nil
}

func (o *Orchestrator) consumePendingTrigger() *TriggerRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	req := o.pendingTrigger
	o.pendingTrigger = nil
	return req
}

// buildRepoProviders constructs a RepoProvider for each configured git platform.
func (o *Orchestrator) buildRepoProviders() []repository.RepoProvider {
	var providers []repository.RepoProvider

	for _, gh := range o.cfg.Git.GitHub {
		if gh.Token == "" {
			continue
		}
		p, err := repository.NewGitHub(gh)
		if err != nil {
			slog.Warn("Failed to create GitHub provider", "host", gh.Host, "error", err)
			continue
		}
		providers = append(providers, p)
		slog.Info("Registered git provider", "provider", "github", "host", gh.Host)
	}

	for _, gl := range o.cfg.Git.GitLab {
		if gl.Token == "" {
			continue
		}
		p, err := repository.NewGitLab(gl)
		if err != nil {
			slog.Warn("Failed to create GitLab provider", "host", gl.Host, "error", err)
			continue
		}
		providers = append(providers, p)
		slog.Info("Registered git provider", "provider", "gitlab", "host", gl.Host)
	}

	for _, az := range o.cfg.Git.Azure {
		if az.Token == "" {
			continue
		}
		p, err := repository.NewAzureDevOps(az)
		if err != nil {
			slog.Warn("Failed to create Azure DevOps provider", "org", az.Org, "error", err)
			continue
		}
		providers = append(providers, p)
		slog.Info("Registered git provider", "provider", "azure", "org", az.Org)
	}

	return providers
}

// RepoProvidersForPreview builds providers using the current config. Intended
// for gateway preview APIs (does not start a sweep).
func (o *Orchestrator) RepoProvidersForPreview() []repository.RepoProvider {
	return o.buildRepoProviders()
}

// WorkerStatuses returns a snapshot of orchestrator background worker activity.
func (o *Orchestrator) WorkerStatuses() []WorkerStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]WorkerStatus, 0, len(o.workerStates))
	for _, ws := range o.workerStates {
		out = append(out, ws)
	}
	return out
}

func (o *Orchestrator) setWorkerStatus(ws WorkerStatus) {
	o.mu.Lock()
	defer o.mu.Unlock()
	ws.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	o.workerStates[ws.Name] = ws
	if o.opts.OnWorkerStatus != nil {
		payload := map[string]any{
			"name":             ws.Name,
			"kind":             ws.Kind,
			"status":           ws.Status,
			"action":           ws.Action,
			"repo":             ws.Repo,
			"scan_job_id":      ws.ScanJobID,
			"campaign_id":      ws.CampaignID,
			"task_id":          ws.TaskID,
			"message":          ws.Message,
			"progress_phase":   ws.ProgressPhase,
			"progress_current": ws.ProgressCurrent,
			"progress_total":   ws.ProgressTotal,
			"progress_percent": ws.ProgressPercent,
			"progress_note":    ws.ProgressNote,
			"updated_at":       ws.UpdatedAt,
		}
		o.opts.OnWorkerStatus(payload)
	}
}

func (o *Orchestrator) emitRemediationEvent(eventType string, payload map[string]any) {
	if o.opts.OnRemediationEvent != nil {
		o.opts.OnRemediationEvent(eventType, payload)
	}
}

func (o *Orchestrator) processOneRemediationTask(ctx context.Context, aiProv ai.AIProvider, repoProviders []repository.RepoProvider, workerName string) {
	type taskRow struct {
		ID         int64  `db:"id"`
		CampaignID int64  `db:"campaign_id"`
		ScanJobID  int64  `db:"scan_job_id"`
		Provider   string `db:"provider"`
		Owner      string `db:"owner"`
		Repo       string `db:"repo"`
		Branch     string `db:"branch"`
		CloneURL   string `db:"clone_url"`
		Status     string `db:"status"`
	}
	var task taskRow
	err := o.db.Get(ctx, &task, `
		SELECT t.id, t.campaign_id, t.scan_job_id, t.provider, t.owner, t.repo, t.branch, t.clone_url, t.status
		FROM remediation_tasks t
		INNER JOIN remediation_campaigns c ON c.id = t.campaign_id
		WHERE c.status = 'running' AND t.status = 'pending'
		ORDER BY t.id ASC
		LIMIT 1`)
	if err != nil {
		o.setWorkerStatus(WorkerStatus{Name: workerName, Kind: "remediation", Status: "waiting", Action: "waiting for campaigns"})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_ = o.db.Exec(ctx,
		`UPDATE remediation_tasks SET status = 'running', worker_name = ?, started_at = ?, error_msg = '' WHERE id = ?`,
		workerName, now, task.ID)
	_ = o.refreshRemediationCampaignStats(ctx, task.CampaignID)

	repoFull := fmt.Sprintf("%s/%s", task.Owner, task.Repo)
	o.setWorkerStatus(WorkerStatus{
		Name: workerName, Kind: "remediation", Status: "running", Action: "generating fixes",
		Repo: repoFull, ScanJobID: task.ScanJobID, CampaignID: task.CampaignID, TaskID: task.ID,
	})
	o.emitRemediationEvent("campaign.task.started", map[string]any{
		"campaign_id": task.CampaignID, "task_id": task.ID, "scan_job_id": task.ScanJobID, "repo": repoFull,
	})

	cfgCopy := *o.cfg
	var campaignMode string
	var autoPR int
	type campaignCfgRow struct {
		Mode   string `db:"mode"`
		AutoPR int    `db:"auto_pr"`
	}
	var cRow campaignCfgRow
	if err := o.db.Get(ctx, &cRow, `SELECT mode, auto_pr FROM remediation_campaigns WHERE id = ?`, task.CampaignID); err == nil {
		campaignMode = cRow.Mode
		autoPR = cRow.AutoPR
	}
	if strings.TrimSpace(campaignMode) != "" {
		cfgCopy.Agent.Mode = campaignMode
	}

	p := pickProviderForSelectedRepo(repoProviders, SelectedRepo{Provider: task.Provider})
	cloneURL := task.CloneURL
	if cloneURL == "" && p != nil {
		if repo, err := p.GetRepo(ctx, task.Owner, task.Repo); err == nil {
			cloneURL = repo.CloneURL
		}
	}
	if cloneURL == "" {
		cloneURL = defaultCloneURL(task.Provider, task.Owner, task.Repo)
	}
	if cloneURL == "" || p == nil {
		msg := "provider/clone URL unavailable for remediation task"
		_ = o.db.Exec(ctx, `UPDATE remediation_tasks SET status = 'failed', error_msg = ?, completed_at = ? WHERE id = ?`, msg, time.Now().UTC().Format(time.RFC3339), task.ID)
		_ = o.refreshRemediationCampaignStats(ctx, task.CampaignID)
		o.setWorkerStatus(WorkerStatus{Name: workerName, Kind: "remediation", Status: "failed", Action: "task failed", Repo: repoFull, CampaignID: task.CampaignID, TaskID: task.ID, Message: msg})
		o.emitRemediationEvent("campaign.task.failed", map[string]any{"campaign_id": task.CampaignID, "task_id": task.ID, "repo": repoFull, "error": msg})
		return
	}

	cm := repository.NewCloneManager(cfgCopy.Tools.BinDir)
	cloneResult, err := cm.Clone(ctx, cloneURL, p.AuthToken(), task.Branch)
	if err != nil {
		msg := fmt.Sprintf("cloning %s: %v", repoFull, err)
		_ = o.db.Exec(ctx, `UPDATE remediation_tasks SET status = 'failed', error_msg = ?, completed_at = ? WHERE id = ?`, msg, time.Now().UTC().Format(time.RFC3339), task.ID)
		_ = o.refreshRemediationCampaignStats(ctx, task.CampaignID)
		o.emitRemediationEvent("campaign.task.failed", map[string]any{"campaign_id": task.CampaignID, "task_id": task.ID, "repo": repoFull, "error": msg})
		return
	}
	defer cm.Cleanup(cloneResult)

	fixer := NewFixerAgent(&cfgCopy, o.db, aiProv)
	fixer.progressNotify = func(ev remediationProgressEvent) {
		action := "generating fixes"
		if ev.PhaseLabel != "" {
			action = ev.PhaseLabel
		}
		if ev.Total > 0 {
			action = fmt.Sprintf("%s (%d/%d, %d%%)", action, ev.Current, ev.Total, ev.Percent)
		} else if ev.Percent > 0 {
			action = fmt.Sprintf("%s (%d%%)", action, ev.Percent)
		}
		o.setWorkerStatus(WorkerStatus{
			Name:            workerName,
			Kind:            "remediation",
			Status:          "running",
			Action:          action,
			Repo:            repoFull,
			ScanJobID:       task.ScanJobID,
			CampaignID:      task.CampaignID,
			TaskID:          task.ID,
			ProgressPhase:   ev.Phase,
			ProgressCurrent: ev.Current,
			ProgressTotal:   ev.Total,
			ProgressPercent: ev.Percent,
			ProgressNote:    ev.Note,
		})
		o.emitRemediationEvent("campaign.task.progress", map[string]any{
			"campaign_id": task.CampaignID,
			"task_id":     task.ID,
			"scan_job_id": task.ScanJobID,
			"repo":        repoFull,
			"phase":       ev.Phase,
			"phase_label": ev.PhaseLabel,
			"current":     ev.Current,
			"total":       ev.Total,
			"percent":     ev.Percent,
			"note":        ev.Note,
			"finding_id":  ev.FindingID,
		})
	}
	before := countFixQueueForScanJob(ctx, o.db, task.ScanJobID)
	if err := fixer.processFixJob(ctx, fixJob{
		ScanJobID:         task.ScanJobID,
		RemediationTaskID: task.ID,
		WorkerName:        workerName,
		Provider:          task.Provider,
		Owner:             task.Owner,
		Repo:              task.Repo,
		Branch:            cloneResult.Branch,
		Commit:            cloneResult.Commit,
		RepoPath:          cloneResult.LocalPath,
	}); err != nil {
		msg := fmt.Sprintf("processing remediation task: %v", err)
		_ = o.db.Exec(ctx, `UPDATE remediation_tasks SET status = 'failed', error_msg = ?, completed_at = ? WHERE id = ?`,
			msg, time.Now().UTC().Format(time.RFC3339), task.ID)
		_ = o.refreshRemediationCampaignStats(ctx, task.CampaignID)
		o.setWorkerStatus(WorkerStatus{
			Name: workerName, Kind: "remediation", Status: "waiting", Action: "waiting for campaigns",
		})
		o.emitRemediationEvent("campaign.task.failed", map[string]any{
			"campaign_id": task.CampaignID, "task_id": task.ID, "repo": repoFull, "error": msg,
		})
		return
	}
	after := countFixQueueForScanJob(ctx, o.db, task.ScanJobID)
	if autoPR == 1 {
		o.TriggerPRProcessing()
	}

	_ = o.db.Exec(ctx, `UPDATE remediation_tasks SET status = 'completed', completed_at = ?, error_msg = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), fmt.Sprintf("fix_queue_delta=%d", after-before), task.ID)
	_ = o.refreshRemediationCampaignStats(ctx, task.CampaignID)
	o.setWorkerStatus(WorkerStatus{
		Name: workerName, Kind: "remediation", Status: "waiting", Action: "waiting for campaigns",
	})
	o.emitRemediationEvent("campaign.task.completed", map[string]any{
		"campaign_id": task.CampaignID, "task_id": task.ID, "repo": repoFull, "fix_queue_delta": after - before,
	})
}

func (o *Orchestrator) refreshRemediationCampaignStats(ctx context.Context, campaignID int64) error {
	type counts struct {
		Total     int `db:"total"`
		Pending   int `db:"pending"`
		Running   int `db:"running"`
		Completed int `db:"completed"`
		Failed    int `db:"failed"`
		Skipped   int `db:"skipped"`
	}
	var c counts
	if err := o.db.Get(ctx, &c, `
		SELECT
		  COUNT(*) AS total,
		  COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END),0) AS pending,
		  COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),0) AS running,
		  COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END),0) AS completed,
		  COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END),0) AS failed,
		  COALESCE(SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END),0) AS skipped
		FROM remediation_tasks WHERE campaign_id = ?`, campaignID); err != nil {
		return err
	}
	status := ""
	completedAt := ""
	if c.Total > 0 && c.Pending == 0 && c.Running == 0 {
		status = "completed"
		completedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if status == "" {
		return o.db.Exec(ctx, `UPDATE remediation_campaigns SET total_tasks=?, pending_tasks=?, running_tasks=?, completed_tasks=?, failed_tasks=?, skipped_tasks=? WHERE id = ?`,
			c.Total, c.Pending, c.Running, c.Completed, c.Failed, c.Skipped, campaignID)
	}
	if err := o.db.Exec(ctx, `UPDATE remediation_campaigns SET status=?, completed_at=?, total_tasks=?, pending_tasks=?, running_tasks=?, completed_tasks=?, failed_tasks=?, skipped_tasks=? WHERE id = ?`,
		status, completedAt, c.Total, c.Pending, c.Running, c.Completed, c.Failed, c.Skipped, campaignID); err != nil {
		return err
	}
	o.emitRemediationEvent("campaign.completed", map[string]any{
		"campaign_id": campaignID,
		"total_tasks": c.Total, "completed_tasks": c.Completed, "failed_tasks": c.Failed, "skipped_tasks": c.Skipped,
	})
	return nil
}

func countFixQueueForScanJob(ctx context.Context, db database.DB, scanJobID int64) int {
	type row struct {
		N int `db:"n"`
	}
	var r row
	_ = db.Get(ctx, &r, `SELECT COUNT(*) AS n FROM fix_queue WHERE scan_job_id = ?`, scanJobID)
	return r.N
}

func defaultCloneURL(provider, owner, repo string) string {
	switch provider {
	case "github":
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	case "gitlab":
		return fmt.Sprintf("https://gitlab.com/%s/%s.git", owner, repo)
	default:
		return ""
	}
}

// repoJob carries a discovered repository to the scanner workers.
type repoJob struct {
	Provider repository.RepoProvider
	Owner    string
	Name     string
	CloneURL string
	Branch   string
}

// fixJob carries scan findings to the fixer agent.
type fixJob struct {
	ScanJobID         int64
	RemediationTaskID int64
	WorkerName        string
	Provider          string
	Owner             string
	Repo              string
	Branch            string
	Commit            string
	RepoPath          string // still-live clone for context reading
	CleanupFn         func() // call when done with repoPath
}

// pollInterval controls how long the orchestrator waits between automatic sweeps.
var pollInterval = 30 * time.Minute
