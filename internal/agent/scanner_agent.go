package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/scanner"
)

// ScannerAgent clones repositories and runs scanners against them.
// It reads from the repo queue and writes to the fix queue.
type ScannerAgent struct {
	id            int
	cfg           *config.Config
	db            database.DB
	scanners      []scanner.Scanner
	onRepoSkipped func(payload map[string]any)
	onWorkerState func(WorkerStatus)
}

// NewScannerAgent creates a ScannerAgent worker.
func NewScannerAgent(id int, cfg *config.Config, db database.DB, scanners []scanner.Scanner, onRepoSkipped func(payload map[string]any), onWorkerState func(WorkerStatus)) *ScannerAgent {
	return &ScannerAgent{id: id, cfg: cfg, db: db, scanners: scanners, onRepoSkipped: onRepoSkipped, onWorkerState: onWorkerState}
}

// Run processes repo jobs from in and emits fix jobs to out.
func (s *ScannerAgent) Run(ctx context.Context, in <-chan repoJob, out chan<- fixJob) {
	slog.Debug("Scanner worker started", "worker_id", s.id)
	s.emitWorkerState("waiting", "waiting for repos", "", 0, "")
	cm := repository.NewCloneManager(s.cfg.Tools.BinDir)

	for {
		select {
		case job, ok := <-in:
			if !ok {
				slog.Debug("Scanner worker shutting down", "worker_id", s.id)
				s.emitWorkerState("stopped", "shutdown", "", 0, "")
				return
			}
			if err := s.processRepo(ctx, cm, job, out); err != nil {
				if ctx.Err() != nil {
					slog.Info("Scanner worker stopping due to cancellation",
						"worker", s.id,
						"repo", fmt.Sprintf("%s/%s", job.Owner, job.Name),
					)
					s.emitWorkerState("stopped", "cancelled", fmt.Sprintf("%s/%s", job.Owner, job.Name), 0, "")
					return
				}
				s.emitWorkerState("failed", "repo failed", fmt.Sprintf("%s/%s", job.Owner, job.Name), 0, err.Error())
				slog.Error("Failed to process repo",
					"worker", s.id,
					"repo", fmt.Sprintf("%s/%s", job.Owner, job.Name),
					"error", err,
				)
			}
		case <-ctx.Done():
			s.emitWorkerState("stopped", "shutdown", "", 0, "")
			return
		}
	}
}

func (s *ScannerAgent) processRepo(ctx context.Context, cm *repository.CloneManager, job repoJob, out chan<- fixJob) error {
	repoFull := fmt.Sprintf("%s/%s", job.Owner, job.Name)
	s.emitWorkerState("running", "checking skip rules", repoFull, 0, "")
	slog.Info("Scanner worker processing repo", "worker", s.id, "repo", repoFull)

	if skip, reason := s.shouldSkipRepo(ctx, job); skip {
		s.emitWorkerState("waiting", "skipped repo", repoFull, 0, reason)
		slog.Info("Skipping repo scan", "worker", s.id, "repo", repoFull, "reason", reason)
		if s.onRepoSkipped != nil {
			s.onRepoSkipped(map[string]any{
				"worker":   s.id,
				"provider": job.Provider.Name(),
				"repo":     repoFull,
				"reason":   reason,
			})
		}
		return nil
	}

	token := job.Provider.AuthToken()

	// Clone.
	s.emitWorkerState("running", "cloning repo", repoFull, 0, "")
	cloneResult, err := cm.Clone(ctx, job.CloneURL, token, job.Branch)
	if err != nil {
		return fmt.Errorf("cloning %s: %w", repoFull, err)
	}

	// scan_jobs.unique_key must be unique across repeated runs of the same repo/branch.
	// Include commit (for traceability) plus a run timestamp (for uniqueness on rescans).
	jobKey := fmt.Sprintf("%s:%s:%s:%s:%s:%d",
		job.Provider.Name(), job.Owner, job.Name, cloneResult.Branch, cloneResult.Commit, time.Now().UTC().UnixNano())

	// Run scanners.
	s.emitWorkerState("running", "running scanners", repoFull, 0, fmt.Sprintf("branch=%s commit=%s", cloneResult.Branch, cloneResult.Commit))
	runner := scanner.NewRunner(s.scanners, s.db)
	results, err := runner.Run(ctx, &scanner.RunOptions{
		RepoPath: cloneResult.LocalPath,
		JobKey:   jobKey,
		Provider: job.Provider.Name(),
		Owner:    job.Owner,
		Repo:     job.Name,
		Branch:   cloneResult.Branch,
		Commit:   cloneResult.Commit,
		Parallel: true,
	})
	if err != nil {
		cm.Cleanup(cloneResult)
		return fmt.Errorf("scanning %s: %w", repoFull, err)
	}

	slog.Info("Scan complete",
		"repo", repoFull,
		"branch", cloneResult.Branch,
		"commit", cloneResult.Commit,
		"status", results.Status,
		"job_id", results.JobID,
	)
	s.emitWorkerState("running", "scan complete", repoFull, results.JobID, results.Status)

	if results.JobID <= 0 {
		slog.Warn("Scan completed without a persisted scan_job row; skipping fixer queue enqueue",
			"repo", repoFull)
		s.emitWorkerState("waiting", "waiting for repos", "", 0, "")
		cm.Cleanup(cloneResult)
		return nil
	}

	// Emit to fix queue (keep clone alive until fixer is done).
	select {
	case out <- fixJob{
		ScanJobID: results.JobID,
		Provider:  job.Provider.Name(),
		Owner:     job.Owner,
		Repo:      job.Name,
		Branch:    cloneResult.Branch,
		RepoPath:  cloneResult.LocalPath,
		CleanupFn: func() { cm.Cleanup(cloneResult) },
	}:
		s.emitWorkerState("waiting", "queued findings for fixer", repoFull, results.JobID, "")
	case <-ctx.Done():
		cm.Cleanup(cloneResult)
	}

	return nil
}

func (s *ScannerAgent) emitWorkerState(status, action, repo string, scanJobID int64, message string) {
	if s.onWorkerState == nil {
		return
	}
	s.onWorkerState(WorkerStatus{
		Name:      fmt.Sprintf("scan-%d", s.id),
		Kind:      "scan",
		Status:    status,
		Action:    action,
		Repo:      repo,
		ScanJobID: scanJobID,
		Message:   message,
	})
}

func (s *ScannerAgent) shouldSkipRepo(ctx context.Context, job repoJob) (bool, string) {
	type row struct {
		Status      string  `db:"status"`
		StartedAt   string  `db:"started_at"`
		CompletedAt *string `db:"completed_at"`
	}
	var latest row
	err := s.db.Get(ctx, &latest, `
		SELECT status, started_at, completed_at
		FROM scan_jobs
		WHERE provider = ? AND owner = ? AND repo = ? AND branch = ?
		ORDER BY id DESC
		LIMIT 1`,
		job.Provider.Name(), job.Owner, job.Name, job.Branch,
	)
	if err != nil {
		return false, ""
	}
	now := time.Now().UTC()
	const freshness = 24 * time.Hour

	if latest.Status == "completed" || latest.Status == "partial" {
		if latest.CompletedAt != nil {
			if t, err := time.Parse(time.RFC3339, *latest.CompletedAt); err == nil && now.Sub(t) < freshness {
				return true, "recently scanned within 24h"
			}
		}
	}

	if latest.Status == "running" {
		if t, err := time.Parse(time.RFC3339, latest.StartedAt); err == nil && now.Sub(t) > freshness {
			// Stale running row; avoid duplicating work forever and mark it stopped.
			_ = s.db.Exec(ctx, `UPDATE scan_jobs SET status = 'stopped', completed_at = ?, error_msg = 'stale running job skipped' WHERE status = 'running' AND provider = ? AND owner = ? AND repo = ? AND branch = ?`,
				now.Format(time.RFC3339), job.Provider.Name(), job.Owner, job.Name, job.Branch)
			return true, "stale running job older than 24h"
		}
	}

	return false, ""
}
