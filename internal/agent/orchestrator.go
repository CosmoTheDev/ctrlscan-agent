package agent

import (
	"context"
	"fmt"
	"log/slog"
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
}

// OrchestratorOptions controls loop behavior for different runtimes (CLI agent vs gateway).
type OrchestratorOptions struct {
	RunInitialSweep bool
	EnablePolling   bool
}

// TriggerRequest optionally overrides scan settings for the next sweep only.
type TriggerRequest struct {
	ScanTargets   []string
	Workers       int
	SelectedRepos []SelectedRepo
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
		cfg:         cfg,
		db:          db,
		triggerCh:   make(chan struct{}, 1),
		prTriggerCh: make(chan struct{}, 1),
		opts:        opts,
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prAgent.drainApprovedFixes(ctx)
		case <-o.prTriggerCh:
			prAgent.drainApprovedFixes(ctx)
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
	if req != nil && (req.Workers > 0 || len(req.ScanTargets) > 0) {
		cfgCopy := *o.cfg
		if req.Workers > 0 {
			cfgCopy.Agent.Workers = req.Workers
		}
		if len(req.ScanTargets) > 0 {
			cfgCopy.Agent.ScanTargets = append([]string(nil), req.ScanTargets...)
		}
		effectiveCfg = &cfgCopy
		slog.Info("Orchestrator applying one-shot trigger overrides",
			"workers", effectiveCfg.Agent.Workers,
			"targets", effectiveCfg.Agent.ScanTargets,
		)
	}

	repoQueue := make(chan repoJob, 256)
	fixQueue := make(chan fixJob, 512)

	workers := effectiveCfg.Agent.Workers
	if workers <= 0 {
		workers = 3
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
			sa := NewScannerAgent(workerID, effectiveCfg, o.db, scannerList)
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
		return nil
	case <-sweepCtx.Done():
		slog.Info("Orchestrator: sweep cancelled")
		return nil
	case <-done:
		slog.Info("Orchestrator: sweep complete")
		return nil
	}
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
	ScanJobID int64
	Provider  string
	Owner     string
	Repo      string
	Branch    string
	RepoPath  string // still-live clone for context reading
	CleanupFn func() // call when done with repoPath
}

// pollInterval controls how long the orchestrator waits between automatic sweeps.
var pollInterval = 30 * time.Minute
