package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// Runner orchestrates parallel execution of multiple scanners.
type Runner struct {
	scanners []Scanner
	db       database.DB
}

// NewRunner creates a Runner with the provided scanner implementations.
func NewRunner(scanners []Scanner, db database.DB) *Runner {
	return &Runner{scanners: scanners, db: db}
}

// Run executes all registered scanners against opts.RepoPath.
// When opts.Parallel is true, scanners run concurrently.
// Partial results are returned even if some scanners fail.
func (r *Runner) Run(ctx context.Context, opts *RunOptions) (*RunResults, error) {
	if len(r.scanners) == 0 {
		return nil, fmt.Errorf("no scanners configured; run 'ctrlscan onboard'")
	}

	// Create a scan job record in the database.
	jobID, err := r.createScanJob(ctx, opts)
	if err != nil {
		slog.Warn("Failed to create scan job record", "error", err)
	}

	scanOpts := ScanOptions{
		RepoPath: opts.RepoPath,
		BinDir:   "",
		JobID:    jobID,
		Provider: opts.Provider,
		Owner:    opts.Owner,
		Repo:     opts.Repo,
		Branch:   opts.Branch,
		Commit:   opts.Commit,
	}

	results := &RunResults{
		ScannerResults: make(map[string]*ScanResult, len(r.scanners)),
		JobID:          jobID,
	}

	if opts.Parallel {
		results.ScannerResults = r.runParallel(ctx, scanOpts)
	} else {
		results.ScannerResults = r.runSequential(ctx, scanOpts)
	}

	// Determine overall status.
	allOK := true
	anyOK := false
	for _, res := range results.ScannerResults {
		if res.Status == "completed" {
			anyOK = true
		} else {
			allOK = false
		}
	}
	switch {
	case allOK:
		results.Status = "completed"
	case anyOK:
		results.Status = "partial"
	default:
		results.Status = "failed"
	}

	// Update scan job status.
	if jobID > 0 {
		r.persistScannerResults(ctx, jobID, results)
		r.finaliseScanJob(ctx, jobID, results)
	}

	return results, nil
}

func (r *Runner) persistScannerResults(ctx context.Context, jobID int64, results *RunResults) {
	if r.db == nil || jobID <= 0 || results == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	writeCtx := dbWriteCtx(ctx)

	for name, res := range results.ScannerResults {
		if res == nil {
			continue
		}

		row := models.ScanJobScanner{
			ScanJobID:     jobID,
			ScannerName:   name,
			ScannerType:   string(res.Type),
			Status:        res.Status,
			FindingsCount: res.FindingsCount,
			DurationMs:    int64(res.DurationSec * 1000),
			ErrorMsg:      res.Error,
		}
		if _, err := r.db.Insert(writeCtx, "scan_job_scanners", row); err != nil {
			if isContextCanceledErr(err) {
				slog.Info("Skipped scanner row persistence due to cancellation",
					"job_id", jobID, "scanner", name)
				continue
			}
			slog.Warn("Failed to persist scan_job_scanners row",
				"job_id", jobID, "scanner", name, "error", err)
		}

		if len(res.Raw) == 0 {
			continue
		}

		contentType := "application/json"
		if name == "trufflehog" {
			contentType = "application/x-ndjson"
		}

		if err := r.db.Exec(writeCtx,
			`INSERT INTO scan_job_raw_outputs (scan_job_id, scanner_name, content_type, raw_output, created_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(scan_job_id, scanner_name) DO UPDATE
			 SET content_type = excluded.content_type,
			     raw_output = excluded.raw_output,
			     created_at = excluded.created_at`,
			jobID, name, contentType, res.Raw, now,
		); err != nil {
			if isContextCanceledErr(err) {
				slog.Info("Skipped raw scanner output persistence due to cancellation",
					"job_id", jobID, "scanner", name)
				continue
			}
			slog.Warn("Failed to persist raw scanner output",
				"job_id", jobID, "scanner", name, "error", err)
		}
	}
}

type scannerResult struct {
	name   string
	result *ScanResult
}

func (r *Runner) runParallel(ctx context.Context, opts ScanOptions) map[string]*ScanResult {
	resultCh := make(chan scannerResult, len(r.scanners))
	var wg sync.WaitGroup

	for _, s := range r.scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()
			res := r.runOne(ctx, s, opts)
			select {
			case resultCh <- scannerResult{name: s.Name(), result: res}:
			case <-ctx.Done():
				slog.Warn("Result dropped due to context cancellation", "scanner", s.Name())
			}
		}(s)
	}

	// Close channel after all goroutines complete.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	out := make(map[string]*ScanResult)
	for res := range resultCh {
		out[res.name] = res.result
	}
	return out
}

func (r *Runner) runSequential(ctx context.Context, opts ScanOptions) map[string]*ScanResult {
	out := make(map[string]*ScanResult)
	for _, s := range r.scanners {
		if ctx.Err() != nil {
			break
		}
		out[s.Name()] = r.runOne(ctx, s, opts)
	}
	return out
}

func (r *Runner) runOne(ctx context.Context, s Scanner, opts ScanOptions) *ScanResult {
	repoFull := strings.Trim(strings.TrimSpace(opts.Owner)+"/"+strings.TrimSpace(opts.Repo), "/")
	slog.Info("Running scanner",
		"scanner", s.Name(),
		"scanner_type", s.ScannerType(),
		"job_id", opts.JobID,
		"repo", repoFull,
		"branch", opts.Branch,
		"commit", opts.Commit,
	)
	start := time.Now()

	// Check availability: prefer local → fall back to docker.
	if !opts.UseDocker {
		if !s.IsAvailableLocal(ctx) {
			if s.IsAvailableDocker(ctx) {
				slog.Info("Using Docker fallback", "scanner", s.Name(), "image", s.DockerImage())
				opts.UseDocker = true
			} else {
				slog.Warn("Scanner not available (local or docker)", "scanner", s.Name())
				return &ScanResult{
					Scanner:     s.Name(),
					Type:        s.ScannerType(),
					Status:      "skipped",
					DurationSec: time.Since(start).Seconds(),
					Error:       fmt.Sprintf("%s binary not found; install with: ctrlscan doctor --install-tools", s.Name()),
				}
			}
		}
	}

	result, err := s.Scan(ctx, opts)
	if err != nil {
		slog.Error("Scanner failed",
			"scanner", s.Name(),
			"scanner_type", s.ScannerType(),
			"job_id", opts.JobID,
			"repo", repoFull,
			"branch", opts.Branch,
			"commit", opts.Commit,
			"error", err,
		)
		return &ScanResult{
			Scanner:     s.Name(),
			Type:        s.ScannerType(),
			Status:      "failed",
			DurationSec: time.Since(start).Seconds(),
			Error:       err.Error(),
		}
	}

	result.DurationSec = time.Since(start).Seconds()
	slog.Info("Scanner completed",
		"scanner", s.Name(),
		"scanner_type", s.ScannerType(),
		"job_id", opts.JobID,
		"repo", repoFull,
		"branch", opts.Branch,
		"commit", opts.Commit,
		"findings", result.FindingsCount,
		"duration", fmt.Sprintf("%.1fs", result.DurationSec),
	)
	return result
}

// BuildScanners constructs Scanner instances for the given names.
// binDir is where local scanner binaries are expected.
// preferDocker forces docker execution.
func BuildScanners(names []string, binDir string, preferDocker bool) []Scanner {
	scanners := make([]Scanner, 0, len(names))
	for _, name := range names {
		var s Scanner
		switch name {
		case "grype":
			s = NewGrypeScanner(binDir)
		case "opengrep":
			s = NewOpengrepScanner(binDir)
		case "trufflehog":
			s = NewTrufflehogScanner(binDir)
		case "trivy":
			s = NewTrivyScanner(binDir)
		default:
			slog.Warn("Unknown scanner", "name", name)
			continue
		}
		scanners = append(scanners, s)
	}
	return scanners
}

// createScanJob inserts a new scan job into the database.
func (r *Runner) createScanJob(ctx context.Context, opts *RunOptions) (int64, error) {
	if r.db == nil {
		return 0, nil
	}
	job := &models.ScanJob{
		UniqueKey: opts.JobKey,
		Provider:  opts.Provider,
		Owner:     opts.Owner,
		Repo:      opts.Repo,
		Branch:    opts.Branch,
		Commit:    opts.Commit,
		Status:    "running",
		ScanMode:  "local",
		StartedAt: time.Now().UTC(),
	}
	return r.db.Insert(ctx, "scan_jobs", job)
}

// finaliseScanJob updates the scan job status after all scanners complete.
func (r *Runner) finaliseScanJob(ctx context.Context, jobID int64, results *RunResults) {
	if r.db == nil {
		return
	}

	writeCtx := dbWriteCtx(ctx)
	now := time.Now().UTC()
	critical, high, medium, low := 0, 0, 0, 0
	for _, res := range results.ScannerResults {
		critical += res.Critical
		high += res.High
		medium += res.Medium
		low += res.Low
	}

	query := `UPDATE scan_jobs SET status = ?, completed_at = ?,
	           findings_critical = ?, findings_high = ?, findings_medium = ?, findings_low = ?
	           WHERE id = ?`
	if err := r.db.Exec(writeCtx, query,
		results.Status, now.Format(time.RFC3339),
		critical, high, medium, low, jobID,
	); err != nil {
		if isContextCanceledErr(err) {
			slog.Info("Skipped final scan job status update due to cancellation", "job_id", jobID)
			return
		}
		slog.Warn("Failed to update scan job", "job_id", jobID, "error", err)
	}
}

func dbWriteCtx(ctx context.Context) context.Context {
	if ctx != nil && ctx.Err() == nil {
		return ctx
	}
	return context.Background()
}

func isContextCanceledErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(strings.ToLower(err.Error()), "context canceled")
}
