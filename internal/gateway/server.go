package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
)

// Gateway is the long-running daemon that combines:
//   - the agent Orchestrator (running sweeps continuously)
//   - a cron Scheduler (triggering sweeps on schedule)
//   - a REST + SSE HTTP server (control plane for users)
type Gateway struct {
	cfg         *config.Config
	configPath  string
	logDir      string
	db          database.DB
	orch        *agent.Orchestrator
	scheduler   *Scheduler
	broadcaster *Broadcaster

	mu            sync.RWMutex
	status        AgentStatus
	lastTriggerAt string
	startedAt     time.Time
	paused        bool
}

// New creates a Gateway. Call Start() to begin serving.
func New(cfg *config.Config, db database.DB) *Gateway {
	b := newBroadcaster()
	orch := agent.NewOrchestratorWithOptions(cfg, db, agent.OrchestratorOptions{
		RunInitialSweep: false,
		EnablePolling:   false, // gateway scans are driven by API triggers and cron schedules
		OnSweepStarted: func(payload map[string]any) {
			b.send(SSEEvent{Type: "sweep.started", Payload: payload})
		},
		OnSweepCompleted: func(payload map[string]any) {
			b.send(SSEEvent{Type: "sweep.completed", Payload: payload})
		},
		OnRepoSkipped: func(payload map[string]any) {
			b.send(SSEEvent{Type: "repo.skipped", Payload: payload})
		},
		OnWorkerStatus: func(payload map[string]any) {
			b.send(SSEEvent{Type: "worker.status", Payload: payload})
		},
		OnRemediationEvent: func(eventType string, payload map[string]any) {
			b.send(SSEEvent{Type: eventType, Payload: payload})
		},
	})

	gw := &Gateway{
		cfg:         cfg,
		db:          db,
		logDir:      "logs",
		orch:        orch,
		broadcaster: b,
		startedAt:   time.Now(),
	}
	gw.scheduler = newScheduler(db, gw.triggerSchedule, b.send)
	return gw
}

func (gw *Gateway) workerStatuses() []agent.WorkerStatus {
	if gw.orch == nil {
		return nil
	}
	return gw.orch.WorkerStatuses()
}

// SetConfigPath stores the CLI-resolved config path so config API writes back to the same file.
func (gw *Gateway) SetConfigPath(path string) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.configPath = path
}

// SetLogDir stores the CLI-resolved log directory so log APIs read the same files being written.
func (gw *Gateway) SetLogDir(path string) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if path == "" {
		path = "logs"
	}
	gw.logDir = path
}

// trigger wakes the orchestrator and broadcasts an agent.triggered event.
func (gw *Gateway) trigger() {
	gw.triggerWithOptions(nil, 0, nil, false, "")
}

func (gw *Gateway) triggerSchedule(sched Schedule) {
	scope, err := parseScheduleScope(sched)
	if err != nil {
		slog.Warn("gateway: ignoring schedule trigger due to invalid scope",
			"id", sched.ID, "name", sched.Name, "error", err)
		return
	}
	selectedRepos, err := gw.resolveScheduleSelectedRepos(context.Background(), scope)
	if err != nil {
		slog.Warn("gateway: ignoring schedule trigger due to unresolved scope selectors",
			"id", sched.ID, "name", sched.Name, "error", err)
		return
	}
	mode := strings.TrimSpace(scope.Mode)
	if !isValidAgentMode(mode) {
		slog.Warn("gateway: ignoring schedule trigger due to invalid mode",
			"id", sched.ID, "name", sched.Name, "mode", mode)
		return
	}
	gw.triggerWithOptions(scope.Targets, 0, selectedRepos, false, mode)
}

func (gw *Gateway) triggerWithOptions(scanTargets []string, workers int, selectedRepos []agent.SelectedRepo, forceScan bool, mode string) {
	gw.mu.RLock()
	paused := gw.paused
	gw.mu.RUnlock()
	if paused {
		slog.Info("gateway: trigger ignored while agent is paused")
		gw.broadcaster.send(SSEEvent{Type: "agent.trigger_ignored", Payload: map[string]any{"reason": "paused"}})
		return
	}
	var req *agent.TriggerRequest
	if len(scanTargets) > 0 || workers > 0 || len(selectedRepos) > 0 || forceScan || strings.TrimSpace(mode) != "" {
		req = &agent.TriggerRequest{
			ScanTargets:   append([]string(nil), scanTargets...),
			Workers:       workers,
			SelectedRepos: append([]agent.SelectedRepo(nil), selectedRepos...),
			ForceScan:     forceScan,
			Mode:          strings.TrimSpace(mode),
		}
	}
	if req != nil {
		gw.orch.TriggerWithRequest(req)
	} else {
		gw.orch.Trigger()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	gw.mu.Lock()
	gw.lastTriggerAt = now
	gw.mu.Unlock()
	payload := map[string]any{"at": now}
	if len(scanTargets) > 0 {
		payload["scan_targets"] = scanTargets
	}
	if workers > 0 {
		payload["workers"] = workers
	}
	if len(selectedRepos) > 0 {
		payload["selected_repos"] = len(selectedRepos)
	}
	if forceScan {
		payload["force_scan"] = true
	}
	if strings.TrimSpace(mode) != "" {
		payload["mode"] = strings.TrimSpace(mode)
	}
	gw.broadcaster.send(SSEEvent{Type: "agent.triggered", Payload: payload})
}

// Start runs the gateway until ctx is cancelled. It:
//  1. Loads and starts the cron scheduler
//  2. Starts the orchestrator in a background goroutine
//  3. Starts a stats ticker that refreshes AgentStatus every 5s via SSE
//  4. Binds the HTTP server (blocks until shutdown)
func (gw *Gateway) Start(ctx context.Context) error {
	port := gw.cfg.Gateway.Port
	if port == 0 {
		port = 6080
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// 1. Start scheduler.
	if err := gw.scheduler.Start(ctx); err != nil {
		return fmt.Errorf("starting scheduler: %w", err)
	}

	// 2. Run orchestrator in background.
	go func() {
		gw.mu.Lock()
		gw.status.Running = true
		gw.mu.Unlock()

		if err := gw.orch.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("gateway: orchestrator error", "error", err)
		}

		gw.mu.Lock()
		gw.status.Running = false
		gw.mu.Unlock()
		gw.broadcaster.send(SSEEvent{Type: "agent.stopped"})
	}()

	// 3. Stats ticker.
	go gw.runStatsTicker(ctx)

	// 4. HTTP server.
	srv := &http.Server{
		Addr:    addr,
		Handler: buildHandler(gw),
	}

	// Shut down HTTP server when ctx is cancelled.
	go func() {
		<-ctx.Done()
		gw.scheduler.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("gateway: listening", "addr", "http://"+addr)
	gw.broadcaster.send(SSEEvent{
		Type:    "gateway.started",
		Payload: map[string]string{"addr": "http://" + addr},
	})

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

// runStatsTicker refreshes AgentStatus from the DB every 5 seconds and
// broadcasts a "status.update" SSE event to all connected clients.
func (gw *Gateway) runStatsTicker(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			gw.refreshStatus(ctx)
		}
	}
}

func (gw *Gateway) refreshStatus(ctx context.Context) {
	var queued, active, pending countRow
	_ = gw.db.Get(ctx, &queued, "SELECT COUNT(*) AS n FROM repo_queue WHERE status = 'pending'")
	_ = gw.db.Get(ctx, &active, "SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'running'")
	_ = gw.db.Get(ctx, &pending, "SELECT COUNT(*) AS n FROM fix_queue WHERE status = 'pending'")

	gw.mu.Lock()
	gw.status.QueuedRepos = queued.N
	gw.status.ActiveJobs = active.N
	gw.status.PendingFixes = pending.N
	gw.status.Paused = gw.paused
	gw.status.Workers = gw.cfg.Agent.Workers
	gw.status.UptimeSeconds = int64(time.Since(gw.startedAt).Seconds())
	gw.status.LastTriggerAt = gw.lastTriggerAt
	snap := gw.status
	gw.mu.Unlock()

	gw.broadcaster.send(SSEEvent{Type: "status.update", Payload: snap})
}

func (gw *Gateway) currentStatus() AgentStatus {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	s := gw.status
	s.Paused = gw.paused
	s.Workers = gw.cfg.Agent.Workers
	s.UptimeSeconds = int64(time.Since(gw.startedAt).Seconds())
	s.LastTriggerAt = gw.lastTriggerAt
	return s
}

func (gw *Gateway) setPaused(paused bool) {
	gw.mu.Lock()
	gw.paused = paused
	gw.status.Paused = paused
	gw.mu.Unlock()
}

func (gw *Gateway) isPaused() bool {
	gw.mu.RLock()
	defer gw.mu.RUnlock()
	return gw.paused
}

func (gw *Gateway) triggerPRProcessing() {
	gw.orch.TriggerPRProcessing()
	gw.broadcaster.send(SSEEvent{Type: "pr.processing.triggered"})
}
