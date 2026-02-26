package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	aiPkg "github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// FixerAgent reads open findings from the database, calls the AI provider
// to generate patches, and enqueues approved fixes for PR creation.
type FixerAgent struct {
	cfg            *config.Config
	db             database.DB
	ai             aiPkg.AIProvider
	progressNotify func(remediationProgressEvent)
	// onFixQueued is called after a fix is successfully inserted into fix_queue.
	// repoKey is "owner/repo", findingID is the finding ref string, severity is the lowercased severity.
	onFixQueued func(repoKey, findingID, severity string)
}

type aiRemediationOutcome struct {
	FindingsLoaded          int
	FindingsDeduped         int
	TriageStatus            string
	TriageBatches           int
	TriageSummary           string
	TriagePrioritisedJSON   string
	AIProvider              string
	AIModel                 string
	AIEndpoint              string
	FixAttempted            int
	FixQueued               int
	FixSkippedLowConfidence int
	FixFailed               int
}

type remediationProgressEvent struct {
	Phase      string
	PhaseLabel string
	Current    int
	Total      int
	Percent    int
	Note       string
	FindingID  string
}

type remediationTaskResumeState struct {
	FindingsLoaded          int    `db:"ai_findings_loaded"`
	FindingsDeduped         int    `db:"ai_findings_deduped"`
	TriageStatus            string `db:"ai_triage_status"`
	TriageBatches           int    `db:"ai_triage_batches"`
	TriageSummary           string `db:"ai_triage_summary"`
	TriagePrioritisedJSON   string `db:"ai_triage_json"`
	ProgressPhase           string `db:"ai_progress_phase"`
	ProgressCurrent         int    `db:"ai_progress_current"`
	ProgressTotal           int    `db:"ai_progress_total"`
	ProgressPercent         int    `db:"ai_progress_percent"`
	ProgressNote            string `db:"ai_progress_note"`
	FixAttempted            int    `db:"ai_fix_attempted"`
	FixQueued               int    `db:"ai_fix_queued"`
	FixSkippedLowConfidence int    `db:"ai_fix_skipped_low_conf"`
	FixFailed               int    `db:"ai_fix_failed"`
}

type fixAttemptOutcome string

const (
	fixAttemptQueued  fixAttemptOutcome = "queued"
	fixAttemptLowConf fixAttemptOutcome = "low_conf"
	fixAttemptFailed  fixAttemptOutcome = "failed"
)

const (
	maxFixAttemptsPerTaskDefault = 20
)

// NewFixerAgent creates a FixerAgent.
func NewFixerAgent(cfg *config.Config, db database.DB, ai aiPkg.AIProvider) *FixerAgent {
	return &FixerAgent{cfg: cfg, db: db, ai: ai}
}

// Run processes fix jobs from in until ctx is cancelled.
func (f *FixerAgent) Run(ctx context.Context, in <-chan fixJob) {
	slog.Info("Fixer agent started")
	for {
		select {
		case job, ok := <-in:
			if !ok {
				slog.Info("Fixer agent shutting down")
				return
			}
			if err := f.processFixJob(ctx, job); err != nil {
				args := append(remediationJobLogFields(job), "error", err)
				slog.Error("Fixer job failed", args...)
			}
			// Always clean up the clone.
			if job.CleanupFn != nil {
				job.CleanupFn()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (f *FixerAgent) processFixJob(ctx context.Context, job fixJob) error {
	slog.Info("Fixer processing scan job", remediationJobLogFields(job)...)
	outcome := aiRemediationOutcome{}
	outcome.AIProvider, outcome.AIModel, outcome.AIEndpoint = f.aiLineage()
	defer func() { f.persistRemediationTaskOutcome(ctx, job.RemediationTaskID, outcome) }()
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "starting", PhaseLabel: "starting", Percent: 0, Note: "initializing remediation task",
	})

	// If no AI is configured, scan results are already stored — nothing more to do.
	if !f.ai.IsAvailable(ctx) {
		slog.Info("Scan-only mode: findings stored, skipping AI triage and fix generation",
			"scan_job_id", job.ScanJobID)
		outcome.TriageStatus = "ai_unavailable"
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100, Note: "AI provider unavailable",
		})
		return nil
	}

	resumeState, hasResumeState := f.loadRemediationTaskResumeState(ctx, job.RemediationTaskID)
	if hasResumeState {
		resume := resumeState
		// Hydrate prior counters so resumed tasks preserve total counts/history.
		outcome.FindingsLoaded = resume.FindingsLoaded
		outcome.FindingsDeduped = resume.FindingsDeduped
		outcome.TriageStatus = resume.TriageStatus
		outcome.TriageBatches = resume.TriageBatches
		outcome.TriageSummary = resume.TriageSummary
		outcome.TriagePrioritisedJSON = resume.TriagePrioritisedJSON
		outcome.FixAttempted = resume.FixAttempted
		outcome.FixQueued = resume.FixQueued
		outcome.FixSkippedLowConfidence = resume.FixSkippedLowConfidence
		outcome.FixFailed = resume.FixFailed

		if f.canResumeFromSavedTriage(resume) {
			args := append(remediationJobLogFields(job),
				"phase", resume.ProgressPhase,
				"current", resume.ProgressCurrent,
				"total", resume.ProgressTotal,
			)
			slog.Info("Resuming remediation task from persisted triage/fix pointer", args...)
			if resumed, err := f.resumeFixesFromSavedTriage(ctx, job, &outcome, resume); err == nil && resumed {
				return nil
			} else if err != nil {
				slog.Warn("Failed resuming from persisted triage; falling back to fresh triage",
					"scan_job_id", job.ScanJobID, "task_id", job.RemediationTaskID, "error", err)
			}
		}
	}

	// Load open findings for this scan job.
	findings := f.loadFindings(ctx, job.ScanJobID)
	outcome.FindingsLoaded = len(findings)
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "loading_findings", PhaseLabel: "loading findings", Current: len(findings), Total: len(findings),
		Percent: progressPercent(len(findings), len(findings)), Note: fmt.Sprintf("loaded %d open findings", len(findings)),
	})
	if len(findings) == 0 {
		slog.Info("No open findings for scan job", "scan_job_id", job.ScanJobID)
		outcome.TriageStatus = "no_findings"
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100, Note: "no open findings",
		})
		return nil
	}
	findings, droppedPrefilter := filterFindingsForAIFix(findings)
	if droppedPrefilter > 0 {
		slog.Info("Filtered non-actionable findings before AI triage",
			"scan_job_id", job.ScanJobID,
			"remaining", len(findings),
			"dropped", droppedPrefilter,
		)
	}
	outcome.FindingsLoaded = len(findings)
	if len(findings) == 0 {
		outcome.TriageStatus = "no_actionable_findings"
		outcome.TriageSummary = "No actionable findings remained after default AI fix prefilters (e.g. vendored/generated/test fixture paths)."
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100, Note: "no actionable findings after prefilters",
		})
		return nil
	}
	if !forceRetryGeneratedFixes() {
		findings, skippedExisting := f.filterAlreadyGeneratedFixes(ctx, job.ScanJobID, findings)
		if skippedExisting > 0 {
			slog.Info("Skipped findings with existing generated fixes",
				"scan_job_id", job.ScanJobID,
				"skipped_existing", skippedExisting,
				"remaining", len(findings),
			)
		}
		outcome.FindingsLoaded = len(findings)
		if len(findings) == 0 {
			outcome.TriageStatus = "all_findings_already_processed"
			outcome.TriageSummary = "All actionable findings for this scan job already have generated fix records. Set CTRLSCAN_AI_FORCE_RETRY_FIXES=1 to force reprocessing."
			f.reportRemediationProgress(ctx, job, remediationProgressEvent{
				Phase: "done", PhaseLabel: "complete", Percent: 100, Note: "all actionable findings already processed",
			})
			return nil
		}
	}

	args := append(remediationJobLogFields(job), "count", len(findings))
	slog.Info("Loaded findings for triage", args...)
	deduped, dedupeStats := dedupeFindingsForTriage(findings)
	outcome.FindingsDeduped = len(deduped)
	if dedupeStats.duplicateCount > 0 {
		slog.Info("Deduped findings for triage",
			"scan_job_id", job.ScanJobID,
			"input_count", len(findings),
			"deduped_count", len(deduped),
			"duplicates_removed", dedupeStats.duplicateCount,
		)
	}
	if f.shouldStreamFixesDuringTriage() {
		if err := f.triageAndGenerateFixesStreaming(ctx, job, deduped, resumeState, &outcome); err != nil {
			return err
		}
		return nil
	}

	// Triage with AI (chunked for large scans).
	triage, triageBatches, err := f.triageFindingsChunked(ctx, job, deduped, resumeState)
	outcome.TriageBatches = triageBatches
	if err != nil {
		outcome.TriageStatus = "failed_fallback"
		outcome.TriageSummary = fmt.Sprintf("AI triage failed; processed fallback subset. Error: %v", err)
		fallback := deduped
		if len(fallback) > 40 {
			fallback = selectFallbackFixCandidates(deduped, 40)
		}
		planned := plannedFixAttempts(len(fallback))
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "fixing", PhaseLabel: "generating fixes (fallback)", Current: 0, Total: planned,
			Percent: 0, Note: fmt.Sprintf("triage failed; processing fallback subset (%d candidates)", len(fallback)),
		})
		slog.Warn("AI triage failed; processing fallback subset",
			"error", err,
			"scan_job_id", job.ScanJobID,
			"total_findings", len(findings),
			"fallback_candidates", len(fallback),
		)
		// Fall back: process a capped, severity-sorted subset to avoid
		// burning provider TPM on very large scans when triage fails.
		for i := range fallback {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if outcome.FixAttempted >= maxFixAttemptsPerTaskDefault {
				slog.Info("Stopping fallback fix generation at cap",
					"scan_job_id", job.ScanJobID,
					"attempt_cap", maxFixAttemptsPerTaskDefault)
				break
			}
			res := f.generateAndQueueFix(ctx, fallback[i], job)
			switch res {
			case fixAttemptQueued:
				outcome.FixAttempted++
				outcome.FixQueued++
			case fixAttemptLowConf:
				outcome.FixAttempted++
				outcome.FixSkippedLowConfidence++
			default:
				outcome.FixAttempted++
				outcome.FixFailed++
			}
			f.reportRemediationProgress(ctx, job, remediationProgressEvent{
				Phase:      "fixing",
				PhaseLabel: "generating fixes (fallback)",
				Current:    outcome.FixAttempted,
				Total:      planned,
				Percent:    progressPercent(outcome.FixAttempted, planned),
				Note:       fmt.Sprintf("%s %s", fixAttemptLabel(res), strings.TrimSpace(fallback[i].ID)),
				FindingID:  strings.TrimSpace(fallback[i].ID),
			})
		}
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100,
			Note: fmt.Sprintf("fallback complete; queued %d/%d fixes", outcome.FixQueued, outcome.FixAttempted),
		})
		return nil
	}
	outcome.TriageStatus = "completed"
	outcome.TriageSummary = triage.Summary
	if b, err := json.Marshal(triage.Prioritised); err == nil {
		outcome.TriagePrioritisedJSON = string(b)
	}

	args = append(remediationJobLogFields(job),
		"triage_batches", triageBatches,
		"prioritised", len(triage.Prioritised),
		"summary", triage.Summary,
	)
	slog.Info("Triage complete", args...)
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "triage", PhaseLabel: "AI triage", Current: triageBatches, Total: max(1, triageBatches),
		Percent: 100, Note: "triage complete",
	})

	// Generate fixes in priority order.
	planned := plannedFixAttempts(len(triage.Prioritised))
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "fixing", PhaseLabel: "generating fixes", Current: 0, Total: planned,
		Percent: 0, Note: fmt.Sprintf("processing %d prioritized findings", len(triage.Prioritised)),
	})
	for _, tf := range triage.Prioritised {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if outcome.FixAttempted >= maxFixAttemptsPerTaskDefault {
			slog.Info("Reached fix attempt cap for remediation task",
				"scan_job_id", job.ScanJobID,
				"attempt_cap", maxFixAttemptsPerTaskDefault)
			break
		}
		res := f.generateAndQueueFix(ctx, tf.Finding, job)
		switch res {
		case fixAttemptQueued:
			outcome.FixAttempted++
			outcome.FixQueued++
		case fixAttemptLowConf:
			outcome.FixAttempted++
			outcome.FixSkippedLowConfidence++
		default:
			outcome.FixAttempted++
			outcome.FixFailed++
		}
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase:      "fixing",
			PhaseLabel: "generating fixes",
			Current:    outcome.FixAttempted,
			Total:      planned,
			Percent:    progressPercent(outcome.FixAttempted, planned),
			Note:       fmt.Sprintf("%s %s", fixAttemptLabel(res), strings.TrimSpace(tf.Finding.ID)),
			FindingID:  strings.TrimSpace(tf.Finding.ID),
		})
	}
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "done", PhaseLabel: "complete", Percent: 100,
		Note: fmt.Sprintf("queued %d/%d fixes", outcome.FixQueued, outcome.FixAttempted),
	})

	return nil
}

func (f *FixerAgent) shouldStreamFixesDuringTriage() bool {
	if v := strings.TrimSpace(strings.ToLower(os.Getenv("CTRLSCAN_AI_STREAM_TRIAGE_FIXES"))); v != "" {
		return v == "1" || v == "true" || v == "yes" || v == "on"
	}
	return f.resolveTriageChunkSize() == 1
}

func (f *FixerAgent) triageAndGenerateFixesStreaming(ctx context.Context, job fixJob, findings []models.FindingSummary, resume remediationTaskResumeState, outcome *aiRemediationOutcome) error {
	chunkSize := f.resolveTriageChunkSize()
	if chunkSize <= 0 {
		chunkSize = 1
	}
	chunks := chunkFindings(findings, chunkSize)
	if len(chunks) == 0 {
		outcome.TriageStatus = "no_findings"
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100, Note: "no findings to triage",
		})
		return nil
	}

	merged := &aiPkg.TriageResult{
		Summary:     fmt.Sprintf("Streaming triage over %d findings across %d batches.", len(findings), len(chunks)),
		Prioritised: make([]aiPkg.TriagedFinding, 0, len(findings)),
	}
	nextPriority := 1
	startBatch := 0
	if canResumeChunkedTriage(resume, len(chunks)) {
		if parsed, err := parseSavedTriagedFindings(resume.TriagePrioritisedJSON); err == nil {
			merged.Prioritised = parsed
			if strings.TrimSpace(resume.TriageSummary) != "" {
				merged.Summary = resume.TriageSummary
			}
			startBatch = resume.ProgressCurrent
			if startBatch > len(chunks) {
				startBatch = len(chunks)
			}
			nextPriority = len(merged.Prioritised) + 1
			args := append(remediationJobLogFields(job),
				"resume_batch", startBatch+1,
				"total_batches", len(chunks),
				"mode", "streaming",
			)
			slog.Info("Resuming streaming AI triage/fix from checkpoint", args...)
		}
	}

	outcome.TriageBatches = len(chunks)
	planned := plannedFixAttempts(len(findings))
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "triage", PhaseLabel: "AI triage + fix streaming", Current: startBatch, Total: len(chunks),
		Percent: progressPercent(startBatch, len(chunks)),
		Note:    fmt.Sprintf("streaming triage/fix across %d findings", len(findings)),
	})

	for idx, chunk := range chunks {
		if idx < startBatch {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "triage", PhaseLabel: "AI triage + fix streaming", Current: idx, Total: len(chunks),
			Percent: progressPercent(idx, len(chunks)),
			Note:    fmt.Sprintf("running triage batch %d/%d (%d findings)", idx+1, len(chunks), len(chunk)),
		})
		args := append(remediationJobLogFields(job),
			"batch", idx+1,
			"batches", len(chunks),
			"chunk_size", len(chunk),
			"streaming", true,
		)
		slog.Info("Running chunked AI triage batch", args...)

		res, err := f.ai.TriageFindings(ctx, chunk)
		if err != nil {
			// In streaming mode, local fallback ordering keeps the pipeline moving.
			wargs := append(remediationJobLogFields(job), "batch", idx+1, "error", err, "streaming", true)
			slog.Warn("AI triage batch failed in streaming mode; using local fallback ordering", wargs...)
			res = &aiPkg.TriageResult{}
		}

		newItems := make([]aiPkg.TriagedFinding, 0, max(1, len(chunk)))
		if strings.TrimSpace(res.Summary) != "" {
			merged.Summary += fmt.Sprintf("\n[Batch %d/%d] %s", idx+1, len(chunks), strings.TrimSpace(res.Summary))
		}
		if len(res.Prioritised) == 0 {
			for _, fd := range chunk {
				tf := aiPkg.TriagedFinding{
					FindingID:    fd.ID,
					Priority:     nextPriority,
					Rationale:    "Added from chunk fallback ordering.",
					SuggestedFix: "",
					Finding:      fd,
				}
				merged.Prioritised = append(merged.Prioritised, tf)
				newItems = append(newItems, tf)
				nextPriority++
			}
		} else {
			for _, tf := range res.Prioritised {
				tf.Priority = nextPriority
				if tf.Finding.ID == "" {
					for _, fd := range chunk {
						if fd.ID == tf.FindingID {
							tf.Finding = fd
							break
						}
					}
				}
				merged.Prioritised = append(merged.Prioritised, tf)
				newItems = append(newItems, tf)
				nextPriority++
			}
		}
		f.persistTriageCheckpoint(ctx, job.RemediationTaskID, merged, idx+1, len(chunks))
		outcome.TriagePrioritisedJSON = mustJSONTriagedFindings(merged.Prioritised, outcome.TriagePrioritisedJSON)
		outcome.TriageSummary = merged.Summary
		outcome.TriageStatus = "running"

		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "triage", PhaseLabel: "AI triage + fix streaming", Current: idx + 1, Total: len(chunks),
			Percent: progressPercent(idx+1, len(chunks)),
			Note:    fmt.Sprintf("completed triage batch %d/%d", idx+1, len(chunks)),
		})

		for _, tf := range newItems {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if outcome.FixAttempted >= maxFixAttemptsPerTaskDefault {
				iargs := append(remediationJobLogFields(job), "attempt_cap", maxFixAttemptsPerTaskDefault)
				slog.Info("Reached fix attempt cap for remediation task", iargs...)
				break
			}
			res := f.generateAndQueueFix(ctx, tf.Finding, job)
			outcome.FixAttempted++
			switch res {
			case fixAttemptQueued:
				outcome.FixQueued++
			case fixAttemptLowConf:
				outcome.FixSkippedLowConfidence++
			default:
				outcome.FixFailed++
			}
			f.reportRemediationProgress(ctx, job, remediationProgressEvent{
				Phase:      "fixing",
				PhaseLabel: "generating fixes (streaming)",
				Current:    outcome.FixAttempted,
				Total:      planned,
				Percent:    progressPercent(outcome.FixAttempted, planned),
				Note:       fmt.Sprintf("%s %s", fixAttemptLabel(res), strings.TrimSpace(tf.Finding.ID)),
				FindingID:  strings.TrimSpace(tf.Finding.ID),
			})
		}
	}

	outcome.TriageStatus = "completed"
	outcome.TriageBatches = len(chunks)
	outcome.TriageSummary = merged.Summary
	outcome.TriagePrioritisedJSON = mustJSONTriagedFindings(merged.Prioritised, outcome.TriagePrioritisedJSON)
	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "done", PhaseLabel: "complete", Percent: 100,
		Note: fmt.Sprintf("streaming complete; queued %d/%d fixes", outcome.FixQueued, outcome.FixAttempted),
	})
	args := append(remediationJobLogFields(job),
		"triage_batches", len(chunks),
		"prioritised", len(merged.Prioritised),
		"queued", outcome.FixQueued,
		"attempted", outcome.FixAttempted,
		"streaming", true,
	)
	slog.Info("Triage + fix streaming complete", args...)
	return nil
}

func mustJSONTriagedFindings(rows []aiPkg.TriagedFinding, fallback string) string {
	b, err := json.Marshal(rows)
	if err != nil {
		return fallback
	}
	return string(b)
}

func filterFindingsForAIFix(findings []models.FindingSummary) ([]models.FindingSummary, int) {
	if len(findings) == 0 {
		return nil, 0
	}
	out := make([]models.FindingSummary, 0, len(findings))
	dropped := 0
	for _, f := range findings {
		if !isLikelyPatchableFinding(f) {
			dropped++
			continue
		}
		if isDefaultAIIgnoredPath(f) {
			dropped++
			continue
		}
		out = append(out, f)
	}
	return out, dropped
}

func isLikelyPatchableFinding(f models.FindingSummary) bool {
	kind := strings.ToLower(strings.TrimSpace(f.Type))
	path := strings.TrimSpace(strings.ReplaceAll(f.FilePath, "\\", "/"))
	switch kind {
	case "sast", "iac":
		return path != ""
	case "secrets":
		return path != ""
	case "sca":
		// SCA fixes without a manifest lockfile path are often not patchable by diff generation.
		return path != "" || (strings.TrimSpace(f.Package) != "" && strings.TrimSpace(f.FixVersion) != "")
	default:
		return path != ""
	}
}

func isDefaultAIIgnoredPath(f models.FindingSummary) bool {
	p := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(f.FilePath, "\\", "/")))
	if p == "" {
		return false
	}
	common := []string{
		"/node_modules/", "node_modules/",
		"/vendor/", "vendor/",
		"/.git/", ".git/",
		"/dist/", "/build/", "/coverage/",
	}
	for _, sub := range common {
		if strings.Contains(p, sub) {
			return true
		}
	}
	// Default skip secret findings in test fixtures/docs/examples; users can still
	// inspect them in the UI and override via future policy controls.
	if strings.EqualFold(strings.TrimSpace(f.Type), "secrets") {
		secretNoisy := []string{"/test/", "/tests/", "/testdata/", "/fixtures/", "/fixture/", "/examples/", "readme", "_test."}
		for _, sub := range secretNoisy {
			if strings.Contains(p, strings.ToLower(sub)) {
				return true
			}
		}
	}
	return false
}

func (f *FixerAgent) triageFindingsChunked(ctx context.Context, job fixJob, findings []models.FindingSummary, resume remediationTaskResumeState) (*aiPkg.TriageResult, int, error) {
	if len(findings) == 0 {
		return &aiPkg.TriageResult{Summary: "No findings to triage."}, 0, nil
	}
	// Keep prompts under TPM ceilings for large scans. We use a chunk size small
	// enough to survive verbose finding descriptions but large enough to preserve
	// some local ranking context.
	chunkSize := f.resolveTriageChunkSize()
	if len(findings) <= chunkSize {
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "triage", PhaseLabel: "AI triage", Current: 0, Total: 1, Percent: 0,
			Note: fmt.Sprintf("triaging %d findings", len(findings)),
		})
		res, err := f.ai.TriageFindings(ctx, findings)
		if err == nil {
			f.reportRemediationProgress(ctx, job, remediationProgressEvent{
				Phase: "triage", PhaseLabel: "AI triage", Current: 1, Total: 1, Percent: 100,
				Note: "triage batch 1/1 complete",
			})
		}
		return res, 1, err
	}

	chunks := chunkFindings(findings, chunkSize)
	merged := &aiPkg.TriageResult{
		Summary:     fmt.Sprintf("Chunked triage over %d findings across %d batches.", len(findings), len(chunks)),
		Prioritised: make([]aiPkg.TriagedFinding, 0, len(findings)),
	}
	nextPriority := 1
	startBatch := 0
	if canResumeChunkedTriage(resume, len(chunks)) {
		if parsed, err := parseSavedTriagedFindings(resume.TriagePrioritisedJSON); err == nil {
			merged.Prioritised = parsed
			if strings.TrimSpace(resume.TriageSummary) != "" {
				merged.Summary = resume.TriageSummary
			}
			startBatch = resume.ProgressCurrent
			if startBatch > len(chunks) {
				startBatch = len(chunks)
			}
			nextPriority = len(merged.Prioritised) + 1
			f.reportRemediationProgress(ctx, job, remediationProgressEvent{
				Phase:      "triage",
				PhaseLabel: "AI triage",
				Current:    startBatch,
				Total:      len(chunks),
				Percent:    progressPercent(startBatch, len(chunks)),
				Note:       fmt.Sprintf("resuming triage at batch %d/%d", startBatch+1, len(chunks)),
			})
			args := append(remediationJobLogFields(job),
				"resume_batch", startBatch+1,
				"total_batches", len(chunks),
				"prioritised_so_far", len(merged.Prioritised),
			)
			slog.Info("Resuming chunked AI triage from checkpoint", args...)
		} else {
			args := append(remediationJobLogFields(job), "error", err)
			slog.Warn("Failed to parse triage checkpoint; restarting triage from batch 1", args...)
		}
	}

	for idx, chunk := range chunks {
		if idx < startBatch {
			continue
		}
		if ctx.Err() != nil {
			return nil, len(chunks), ctx.Err()
		}
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "triage", PhaseLabel: "AI triage", Current: idx, Total: len(chunks),
			Percent: progressPercent(idx, len(chunks)),
			Note:    fmt.Sprintf("running triage batch %d/%d (%d findings)", idx+1, len(chunks), len(chunk)),
		})
		args := append(remediationJobLogFields(job),
			"batch", idx+1,
			"batches", len(chunks),
			"chunk_size", len(chunk),
		)
		slog.Info("Running chunked AI triage batch", args...)
		res, err := f.ai.TriageFindings(ctx, chunk)
		if err != nil {
			return nil, len(chunks), err
		}
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "triage", PhaseLabel: "AI triage", Current: idx + 1, Total: len(chunks),
			Percent: progressPercent(idx+1, len(chunks)),
			Note:    fmt.Sprintf("completed triage batch %d/%d", idx+1, len(chunks)),
		})
		if strings.TrimSpace(res.Summary) != "" {
			if merged.Summary == "" {
				merged.Summary = ""
			}
			merged.Summary += fmt.Sprintf("\n[Batch %d/%d] %s", idx+1, len(chunks), strings.TrimSpace(res.Summary))
		}
		if len(res.Prioritised) == 0 {
			// Fall back to local ordering for this chunk if model returned only summary.
			for _, fd := range chunk {
				merged.Prioritised = append(merged.Prioritised, aiPkg.TriagedFinding{
					FindingID:    fd.ID,
					Priority:     nextPriority,
					Rationale:    "Added from chunk fallback ordering.",
					SuggestedFix: "",
					Finding:      fd,
				})
				nextPriority++
			}
			// Persist checkpoint even when the model returns only a summary (or
			// malformed JSON parsed as summary). This is common with local models
			// and should still be resumable after restart.
			f.persistTriageCheckpoint(ctx, job.RemediationTaskID, merged, idx+1, len(chunks))
			continue
		}
		// Re-number priorities globally while preserving model order within each chunk.
		for _, tf := range res.Prioritised {
			tf.Priority = nextPriority
			if tf.Finding.ID == "" {
				for _, fd := range chunk {
					if fd.ID == tf.FindingID {
						tf.Finding = fd
						break
					}
				}
			}
			merged.Prioritised = append(merged.Prioritised, tf)
			nextPriority++
		}
		f.persistTriageCheckpoint(ctx, job.RemediationTaskID, merged, idx+1, len(chunks))
	}
	return merged, len(chunks), nil
}

func (f *FixerAgent) resolveTriageChunkSize() int {
	if raw := strings.TrimSpace(os.Getenv("CTRLSCAN_AI_TRIAGE_CHUNK_SIZE")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	if f.cfg != nil && f.cfg.AI.OptimizeForLocal {
		return 1
	}
	// Local Ollama models are often context-constrained; process one finding at a
	// time by default for stability and predictable remediation PR generation.
	if strings.EqualFold(strings.TrimSpace(f.ai.Name()), "ollama") {
		return 1
	}
	return 40
}

func (f *FixerAgent) resolveFixCodeContextLines() int {
	if raw := strings.TrimSpace(os.Getenv("CTRLSCAN_AI_FIX_CONTEXT_LINES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return n
		}
	}
	if f.cfg != nil && f.cfg.AI.OptimizeForLocal {
		// Local models get a moderate window — wide enough to produce correct
		// patch offsets but compact enough for smaller context windows.
		return 30
	}
	return 10
}

func (f *FixerAgent) resolveMinFixConfidence() float64 {
	if raw := strings.TrimSpace(os.Getenv("CTRLSCAN_AI_MIN_FIX_CONFIDENCE")); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			if v < 0 {
				return 0
			}
			if v > 1 {
				return 1
			}
			return v
		}
	}
	if f.cfg == nil {
		return 0
	}
	v := f.cfg.AI.MinFixConfidence
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func (f *FixerAgent) resolveSeverityConfidenceThreshold(severity string) float64 {
	raw := strings.TrimSpace(os.Getenv("CTRLSCAN_AI_MIN_FIX_CONFIDENCE_BY_SEVERITY"))
	if raw != "" {
		thresholds := make(map[string]float64)
		pairs := strings.Split(raw, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				k := strings.TrimSpace(strings.ToLower(kv[0]))
				v, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
				if err == nil && v >= 0 && v <= 1 {
					thresholds[k] = v
				}
			}
		}
		if t, ok := thresholds[severity]; ok {
			return t
		}
	}

	defaultThresholds := map[string]float64{
		"critical": 0.6,
		"high":     0.4,
		"medium":   0.2,
		"low":      0.1,
		"unknown":  0.2,
	}
	if t, ok := defaultThresholds[severity]; ok {
		return t
	}
	return 0.2
}

func chunkFindings(findings []models.FindingSummary, size int) [][]models.FindingSummary {
	if size <= 0 || len(findings) == 0 {
		return nil
	}
	out := make([][]models.FindingSummary, 0, (len(findings)+size-1)/size)
	for i := 0; i < len(findings); i += size {
		end := i + size
		if end > len(findings) {
			end = len(findings)
		}
		chunk := make([]models.FindingSummary, end-i)
		copy(chunk, findings[i:end])
		out = append(out, chunk)
	}
	return out
}

type dedupeFindingStats struct {
	duplicateCount int
}

func dedupeFindingsForTriage(findings []models.FindingSummary) ([]models.FindingSummary, dedupeFindingStats) {
	if len(findings) == 0 {
		return nil, dedupeFindingStats{}
	}
	type ranked struct {
		f models.FindingSummary
	}
	seen := make(map[string]ranked, len(findings))
	stats := dedupeFindingStats{}
	for _, fd := range findings {
		key := triageDedupeKey(fd)
		if key == "" {
			key = fd.ID
		}
		if existing, ok := seen[key]; ok {
			stats.duplicateCount++
			if preferFindingForTriage(fd, existing.f) {
				seen[key] = ranked{f: fd}
			}
			continue
		}
		seen[key] = ranked{f: fd}
	}
	out := make([]models.FindingSummary, 0, len(seen))
	for _, v := range seen {
		out = append(out, v.f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		wi := fallbackFindingWeight(out[i])
		wj := fallbackFindingWeight(out[j])
		if wi != wj {
			return wi > wj
		}
		return out[i].ID < out[j].ID
	})
	return out, stats
}

func triageDedupeKey(f models.FindingSummary) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.Type)),
		strings.ToLower(strings.TrimSpace(f.Scanner)),
		strings.ToLower(strings.TrimSpace(f.Title)),
		strings.ToLower(strings.TrimSpace(strings.ReplaceAll(f.FilePath, "\\", "/"))),
		strings.ToLower(strings.TrimSpace(f.Package)),
	}
	// Preserve multiple distinct findings on same rule/path if line exists.
	if f.LineNumber > 0 {
		parts = append(parts, fmt.Sprintf("line:%d", f.LineNumber))
	}
	key := strings.Join(parts, "|")
	return strings.Trim(key, "|")
}

func preferFindingForTriage(a, b models.FindingSummary) bool {
	wa := fallbackFindingWeight(a)
	wb := fallbackFindingWeight(b)
	if wa != wb {
		return wa > wb
	}
	ha := boolToInt(strings.TrimSpace(a.Description) != "")
	hb := boolToInt(strings.TrimSpace(b.Description) != "")
	if ha != hb {
		return ha > hb
	}
	return len(a.Description) > len(b.Description)
}

func selectFallbackFixCandidates(findings []models.FindingSummary, limit int) []models.FindingSummary {
	if limit <= 0 || len(findings) <= limit {
		out := make([]models.FindingSummary, len(findings))
		copy(out, findings)
		return out
	}
	out := make([]models.FindingSummary, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		wi := fallbackFindingWeight(out[i])
		wj := fallbackFindingWeight(out[j])
		if wi != wj {
			return wi > wj
		}
		// Prefer findings with file context over package-only suggestions.
		hi := boolToInt(strings.TrimSpace(out[i].FilePath) != "")
		hj := boolToInt(strings.TrimSpace(out[j].FilePath) != "")
		if hi != hj {
			return hi > hj
		}
		return out[i].ID < out[j].ID
	})
	return out[:limit]
}

func fallbackFindingWeight(f models.FindingSummary) int {
	sev := strings.ToUpper(strings.TrimSpace(string(f.Severity)))
	base := 0
	switch sev {
	case "CRITICAL":
		base = 400
	case "HIGH":
		base = 300
	case "MEDIUM", "WARNING", "WARN":
		base = 200
	case "LOW", "INFO":
		base = 100
	default:
		base = 50
	}
	kind := strings.ToLower(strings.TrimSpace(f.Type))
	switch kind {
	case "sast", "iac":
		base += 30
	case "sca":
		base += 10
	case "secrets":
		base += 5
	}
	return base
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func remediationJobLogFields(job fixJob) []any {
	fields := make([]any, 0, 14)
	if job.ScanJobID > 0 {
		fields = append(fields, "scan_job_id", job.ScanJobID)
	}
	if job.RemediationTaskID > 0 {
		fields = append(fields, "task_id", job.RemediationTaskID)
	}
	repoFull := strings.Trim(strings.TrimSpace(job.Owner)+"/"+strings.TrimSpace(job.Repo), "/")
	if repoFull != "" {
		fields = append(fields, "repo", repoFull)
	}
	if s := strings.TrimSpace(job.Provider); s != "" {
		fields = append(fields, "provider", s)
	}
	if s := strings.TrimSpace(job.Branch); s != "" {
		fields = append(fields, "branch", s)
	}
	if s := strings.TrimSpace(job.Commit); s != "" {
		fields = append(fields, "commit", s)
	}
	if s := strings.TrimSpace(job.WorkerName); s != "" {
		fields = append(fields, "worker", s)
	}
	return fields
}

func (f *FixerAgent) generateAndQueueFix(ctx context.Context, finding models.FindingSummary, job fixJob) fixAttemptOutcome {
	// SCA findings with a known fix version are better handled deterministically
	// (npm install, go get, etc.) than via AI patch generation. Skip the AI
	// round-trip and go straight to the dependency bump path.
	if strings.EqualFold(strings.TrimSpace(finding.Type), "sca") &&
		strings.TrimSpace(finding.FixVersion) != "" {
		if f.queueDeterministicSCABumpFallback(ctx, finding, job, "sca_has_fix_version") {
			return fixAttemptQueued
		}
		// No deterministic handler for this ecosystem — fall through to AI.
	}

	// Build code context. For small files return the full content; for larger
	// files use a wide window around the finding line.
	contextLines := f.resolveFixCodeContextLines()
	fileContent, totalLines := f.readFileForFix(job.RepoPath, finding.FilePath)
	codeCtx := f.readCodeContext(job.RepoPath, finding.FilePath, finding.LineNumber, contextLines)
	lang := detectLanguage(finding.FilePath)

	fixResult, err := f.ai.GenerateFix(ctx, aiPkg.FixRequest{
		Finding:     finding,
		CodeContext: codeCtx,
		FileContent: fileContent,
		TotalLines:  totalLines,
		FilePath:    finding.FilePath,
		Language:    lang,
	})
	if err != nil {
		args := append(remediationJobLogFields(job), "finding_id", finding.ID, "error", err)
		slog.Warn("Fix generation failed", args...)
		if f.queueDeterministicSCABumpFallback(ctx, finding, job, "ai_error") {
			return fixAttemptQueued
		}
		return fixAttemptFailed
	}

	minConfidence := f.resolveMinFixConfidence()

	requiredConfidence := minConfidence

	severityConfidenceThreshold := f.resolveSeverityConfidenceThreshold(string(finding.Severity))
	if severityConfidenceThreshold > 0 {
		requiredConfidence = severityConfidenceThreshold
	}

	if fixResult.Confidence < requiredConfidence {
		args := append(remediationJobLogFields(job),
			"finding_id", finding.ID,
			"severity", finding.Severity,
			"confidence", fixResult.Confidence,
			"required_confidence", requiredConfidence,
			"min_confidence", minConfidence,
		)
		slog.Info("Skipping low-confidence fix", args...)
		if f.queueDeterministicSCABumpFallback(ctx, finding, job, "low_confidence") {
			return fixAttemptQueued
		}
		return fixAttemptLowConf
	}
	fixResult.Patch = cleanPatch(fixResult.Patch)
	if !looksLikeUnifiedDiffPatch(fixResult.Patch) {
		args := append(remediationJobLogFields(job),
			"finding_id", finding.ID,
			"has_patch_text", strings.TrimSpace(fixResult.Patch) != "",
			"confidence", fixResult.Confidence,
		)
		slog.Warn("Skipping invalid patch output from AI", args...)
		if f.queueDeterministicSCABumpFallback(ctx, finding, job, "invalid_patch") {
			return fixAttemptQueued
		}
		return fixAttemptFailed
	}

	// Store fix in fix_queue with status based on agent mode.
	status := "pending"
	if f.cfg.Agent.Mode == "auto" {
		status = "approved"
	}

	now := time.Now().UTC()
	applyHintsJSON := ""
	if fixResult.ApplyHints != nil {
		if b, err := json.Marshal(fixResult.ApplyHints); err == nil {
			applyHintsJSON = string(b)
		}
	}
	fix := &models.FixQueue{
		ScanJobID:      job.ScanJobID,
		FindingType:    finding.Type,
		FindingRef:     finding.ID,
		AIProvider:     strings.TrimSpace(f.ai.Name()),
		AIModel:        strings.TrimSpace(f.cfg.AI.Model),
		AIEndpoint:     strings.TrimSpace(resolveAIEndpointURL(f.cfg.AI)),
		ApplyHintsJSON: applyHintsJSON,
		Patch:          fixResult.Patch,
		PRTitle:        fmt.Sprintf("fix(security): %s", truncate(finding.Title, 60)),
		PRBody:         fixResult.Explanation,
		Status:         status,
		GeneratedAt:    now,
	}

	if _, err := f.db.Insert(ctx, "fix_queue", fix); err != nil {
		args := append(remediationJobLogFields(job), "finding_id", finding.ID, "error", err)
		slog.Error("Failed to save fix to queue", args...)
		return fixAttemptFailed
	}

	args := append(remediationJobLogFields(job),
		"finding_id", finding.ID,
		"confidence", fmt.Sprintf("%.0f%%", fixResult.Confidence*100),
		"status", status,
	)
	slog.Info("Fix queued", args...)

	if f.onFixQueued != nil {
		repoKey := fmt.Sprintf("%s/%s", job.Owner, job.Repo)
		f.onFixQueued(repoKey, finding.ID, strings.ToLower(string(finding.Severity)))
	}

	// In semi mode: open browser to show the pending fix.
	if f.cfg.Agent.Mode == "semi" {
		args := append(remediationJobLogFields(job), "finding_id", finding.ID)
		slog.Info("Semi mode: fix queued for manual review in ctrlscan ui", args...)
	}
	return fixAttemptQueued
}

func (f *FixerAgent) queueDeterministicSCABumpFallback(ctx context.Context, finding models.FindingSummary, job fixJob, reason string) bool {
	hints, ok := buildSCADependencyBumpHints(finding)
	if !ok {
		return false
	}
	applyHintsJSON := ""
	if b, err := json.Marshal(hints); err == nil {
		applyHintsJSON = string(b)
	}
	status := "pending"
	if f.cfg.Agent.Mode == "auto" {
		status = "approved"
	}
	now := time.Now().UTC()
	title := fmt.Sprintf("fix(deps): bump %s to %s", truncate(strings.TrimSpace(hints.DependencyName), 40), strings.TrimSpace(hints.TargetVersion))
	if strings.TrimSpace(hints.DependencyName) == "" || strings.TrimSpace(hints.TargetVersion) == "" {
		title = fmt.Sprintf("fix(deps): remediate %s", truncate(strings.TrimSpace(finding.Title), 50))
	}
	body := fmt.Sprintf(
		"Deterministic dependency bump fallback queued by ctrlscan.\n\nFinding: %s\nPackage: %s\nTarget version: %s\nEcosystem: %s\nReason: %s\n\nThis fix uses PR-agent apply strategy `dependency_bump` instead of an AI-generated unified diff.",
		strings.TrimSpace(finding.Title),
		strings.TrimSpace(hints.DependencyName),
		strings.TrimSpace(hints.TargetVersion),
		strings.TrimSpace(hints.Ecosystem),
		strings.TrimSpace(reason),
	)
	fix := &models.FixQueue{
		ScanJobID:      job.ScanJobID,
		FindingType:    finding.Type,
		FindingRef:     finding.ID,
		AIProvider:     strings.TrimSpace(f.ai.Name()),
		AIModel:        strings.TrimSpace(f.cfg.AI.Model),
		AIEndpoint:     strings.TrimSpace(resolveAIEndpointURL(f.cfg.AI)),
		ApplyHintsJSON: applyHintsJSON,
		Patch:          "",
		PRTitle:        title,
		PRBody:         body,
		Status:         status,
		GeneratedAt:    now,
	}
	if _, err := f.db.Insert(ctx, "fix_queue", fix); err != nil {
		args := append(remediationJobLogFields(job), "finding_id", finding.ID, "reason", reason, "error", err)
		slog.Error("Failed to save deterministic SCA bump fallback to queue", args...)
		return false
	}
	args := append(remediationJobLogFields(job),
		"finding_id", finding.ID,
		"package", hints.DependencyName,
		"target_version", hints.TargetVersion,
		"ecosystem", hints.Ecosystem,
		"reason", reason,
		"status", status,
	)
	slog.Info("Queued deterministic SCA dependency bump fallback", args...)
	return true
}

func buildSCADependencyBumpHints(finding models.FindingSummary) (aiPkg.ApplyHints, bool) {
	if !strings.EqualFold(strings.TrimSpace(finding.Type), "sca") {
		return aiPkg.ApplyHints{}, false
	}
	pkg := strings.TrimSpace(finding.Package)
	ver := strings.TrimSpace(finding.FixVersion)
	if pkg == "" || ver == "" {
		return aiPkg.ApplyHints{}, false
	}
	path := strings.TrimSpace(strings.ReplaceAll(finding.FilePath, "\\", "/"))
	lowerPath := strings.ToLower(path)
	h := aiPkg.ApplyHints{
		ApplyStrategy:  "dependency_bump",
		DependencyName: pkg,
		TargetVersion:  ver,
		Prerequisites: []string{
			"Repository must clone successfully and dependency tooling must be available on PATH.",
		},
	}
	switch {
	case lowerPath == "go.mod" || strings.HasSuffix(lowerPath, "/go.mod"):
		h.Ecosystem = "go"
		h.ManifestPath = path
		h.TargetFiles = []string{path}
		h.PostApplyChecks = []string{"go mod tidy", "go test ./... (if tests exist)"}
		h.FallbackPatchNotes = "Use `go get <module>@<version>` in the module directory, then `go mod tidy`."
		h.RiskNotes = "May update go.sum and transitive dependencies."
		return h, true
	case lowerPath == "package-lock.json" || strings.HasSuffix(lowerPath, "/package-lock.json"):
		h.Ecosystem = "npm"
		h.LockfilePath = path
		dir := strings.TrimSuffix(path, "/package-lock.json")
		if dir == path {
			dir = ""
		}
		if dir == "" {
			h.ManifestPath = "package.json"
			h.TargetFiles = []string{"package-lock.json", "package.json"}
		} else {
			h.ManifestPath = dir + "/package.json"
			h.TargetFiles = []string{path, h.ManifestPath}
		}
		h.PostApplyChecks = []string{"npm install --package-lock-only --ignore-scripts", "npm audit (optional reviewer check)"}
		h.FallbackPatchNotes = "package-lock.json is a lockfile, not the source manifest. Prefer npm command-based update in the lockfile directory."
		h.RiskNotes = "Command may update package-lock.json and package.json depending on dependency type."
		return h, true
	case lowerPath == "package.json" || strings.HasSuffix(lowerPath, "/package.json"):
		h.Ecosystem = "npm"
		h.ManifestPath = path
		dir := strings.TrimSuffix(path, "/package.json")
		if dir == path {
			dir = ""
		}
		if dir == "" {
			h.LockfilePath = "package-lock.json"
			h.TargetFiles = []string{"package.json", "package-lock.json"}
		} else {
			h.LockfilePath = dir + "/package-lock.json"
			h.TargetFiles = []string{path, h.LockfilePath}
		}
		h.PostApplyChecks = []string{"npm install --package-lock-only --ignore-scripts", "npm test (if configured)"}
		h.FallbackPatchNotes = "Use npm command-based bump in the package directory to keep package.json and lockfile consistent."
		h.RiskNotes = "May affect lockfile and transitive resolutions."
		return h, true
	default:
		return aiPkg.ApplyHints{}, false
	}
}

func (f *FixerAgent) filterAlreadyGeneratedFixes(ctx context.Context, scanJobID int64, findings []models.FindingSummary) ([]models.FindingSummary, int) {
	if scanJobID <= 0 || len(findings) == 0 {
		return findings, 0
	}
	var rows []struct {
		FindingRef string `db:"finding_ref"`
	}
	if err := f.db.Migrate(ctx); err != nil {
		return findings, 0
	}
	if err := f.db.Select(ctx, &rows, `
		SELECT finding_ref
		FROM fix_queue
		WHERE scan_job_id = ?
		  AND finding_ref <> ''
		  AND status IN ('pending','approved','rejected','pr_open','pr_merged','pr_failed')
	`, scanJobID); err != nil {
		return findings, 0
	}
	if len(rows) == 0 {
		return findings, 0
	}
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		ref := strings.TrimSpace(r.FindingRef)
		if ref != "" {
			seen[ref] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return findings, 0
	}
	out := make([]models.FindingSummary, 0, len(findings))
	skipped := 0
	for _, fd := range findings {
		if _, ok := seen[strings.TrimSpace(fd.ID)]; ok {
			skipped++
			continue
		}
		out = append(out, fd)
	}
	return out, skipped
}

func forceRetryGeneratedFixes() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("CTRLSCAN_AI_FORCE_RETRY_FIXES")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func (f *FixerAgent) loadRemediationTaskResumeState(ctx context.Context, taskID int64) (remediationTaskResumeState, bool) {
	if taskID <= 0 {
		return remediationTaskResumeState{}, false
	}
	_ = f.db.Migrate(ctx)
	var row remediationTaskResumeState
	if err := f.db.Get(ctx, &row, `
		SELECT
		  COALESCE(ai_findings_loaded, 0) AS ai_findings_loaded,
		  COALESCE(ai_findings_deduped, 0) AS ai_findings_deduped,
		  COALESCE(ai_triage_status, '') AS ai_triage_status,
		  COALESCE(ai_triage_batches, 0) AS ai_triage_batches,
		  COALESCE(ai_triage_summary, '') AS ai_triage_summary,
		  COALESCE(ai_triage_json, '') AS ai_triage_json,
		  COALESCE(ai_progress_phase, '') AS ai_progress_phase,
		  COALESCE(ai_progress_current, 0) AS ai_progress_current,
		  COALESCE(ai_progress_total, 0) AS ai_progress_total,
		  COALESCE(ai_progress_percent, 0) AS ai_progress_percent,
		  COALESCE(ai_progress_note, '') AS ai_progress_note,
		  COALESCE(ai_fix_attempted, 0) AS ai_fix_attempted,
		  COALESCE(ai_fix_queued, 0) AS ai_fix_queued,
		  COALESCE(ai_fix_skipped_low_conf, 0) AS ai_fix_skipped_low_conf,
		  COALESCE(ai_fix_failed, 0) AS ai_fix_failed
		FROM remediation_tasks
		WHERE id = ?`, taskID); err != nil {
		return remediationTaskResumeState{}, false
	}
	return row, true
}

func (f *FixerAgent) canResumeFromSavedTriage(resume remediationTaskResumeState) bool {
	if strings.TrimSpace(resume.TriageStatus) != "completed" {
		return false
	}
	if strings.TrimSpace(resume.TriagePrioritisedJSON) == "" {
		return false
	}
	phase := strings.TrimSpace(resume.ProgressPhase)
	return phase == "fixing" || phase == "done" || phase == ""
}

func canResumeChunkedTriage(resume remediationTaskResumeState, totalBatches int) bool {
	if totalBatches <= 1 {
		return false
	}
	if strings.TrimSpace(resume.ProgressPhase) != "triage" {
		return false
	}
	if resume.ProgressCurrent <= 0 || resume.ProgressCurrent >= totalBatches {
		return false
	}
	if strings.TrimSpace(resume.TriagePrioritisedJSON) == "" {
		return false
	}
	return true
}

func parseSavedTriagedFindings(raw string) ([]aiPkg.TriagedFinding, error) {
	var rows []aiPkg.TriagedFinding
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []aiPkg.TriagedFinding{}
	}
	return rows, nil
}

func (f *FixerAgent) resumeFixesFromSavedTriage(ctx context.Context, job fixJob, outcome *aiRemediationOutcome, resume remediationTaskResumeState) (bool, error) {
	var prioritised []aiPkg.TriagedFinding
	if err := json.Unmarshal([]byte(resume.TriagePrioritisedJSON), &prioritised); err != nil {
		return false, fmt.Errorf("parsing saved ai_triage_json: %w", err)
	}
	if len(prioritised) == 0 {
		// Nothing left to do; treat as completed path.
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100, Note: "no prioritized findings in saved triage output",
		})
		return true, nil
	}

	totalPlanned := plannedFixAttempts(len(prioritised))
	alreadyAttempted := outcome.FixAttempted
	if alreadyAttempted < resume.ProgressCurrent {
		alreadyAttempted = resume.ProgressCurrent
	}
	if alreadyAttempted < 0 {
		alreadyAttempted = 0
	}
	if alreadyAttempted > totalPlanned {
		alreadyAttempted = totalPlanned
	}
	if outcome.FixAttempted < alreadyAttempted {
		outcome.FixAttempted = alreadyAttempted
	}

	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase:      "fixing",
		PhaseLabel: "resuming fixes",
		Current:    alreadyAttempted,
		Total:      totalPlanned,
		Percent:    progressPercent(alreadyAttempted, totalPlanned),
		Note:       fmt.Sprintf("resuming from saved triage pointer at %d/%d", alreadyAttempted, totalPlanned),
	})

	if alreadyAttempted >= totalPlanned {
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase: "done", PhaseLabel: "complete", Percent: 100,
			Note: fmt.Sprintf("resume found all %d fix attempts already processed", totalPlanned),
		})
		return true, nil
	}

	for idx, tf := range prioritised {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		if idx >= totalPlanned {
			break
		}
		if idx < alreadyAttempted {
			continue
		}

		res := f.generateAndQueueFix(ctx, tf.Finding, job)
		switch res {
		case fixAttemptQueued:
			outcome.FixAttempted++
			outcome.FixQueued++
		case fixAttemptLowConf:
			outcome.FixAttempted++
			outcome.FixSkippedLowConfidence++
		default:
			outcome.FixAttempted++
			outcome.FixFailed++
		}

		findingID := strings.TrimSpace(tf.Finding.ID)
		if findingID == "" {
			findingID = strings.TrimSpace(tf.FindingID)
		}
		f.reportRemediationProgress(ctx, job, remediationProgressEvent{
			Phase:      "fixing",
			PhaseLabel: "resuming fixes",
			Current:    outcome.FixAttempted,
			Total:      totalPlanned,
			Percent:    progressPercent(outcome.FixAttempted, totalPlanned),
			Note:       fmt.Sprintf("%s %s", fixAttemptLabel(res), findingID),
			FindingID:  findingID,
		})
	}

	f.reportRemediationProgress(ctx, job, remediationProgressEvent{
		Phase: "done", PhaseLabel: "complete", Percent: 100,
		Note: fmt.Sprintf("resume complete; queued %d/%d fixes", outcome.FixQueued, outcome.FixAttempted),
	})
	return true, nil
}

func (f *FixerAgent) persistTriageCheckpoint(ctx context.Context, taskID int64, merged *aiPkg.TriageResult, batchesDone, totalBatches int) {
	if taskID <= 0 || merged == nil {
		return
	}
	b, err := json.Marshal(merged.Prioritised)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_ = f.db.Exec(ctx, `
		UPDATE remediation_tasks
		   SET ai_triage_status = ?,
		       ai_triage_batches = ?,
		       ai_triage_summary = ?,
		       ai_triage_json = ?,
		       ai_progress_phase = 'triage',
		       ai_progress_current = ?,
		       ai_progress_total = ?,
		       ai_progress_percent = ?,
		       ai_progress_note = ?,
		       ai_progress_updated_at = ?,
		       ai_updated_at = ?
		 WHERE id = ?`,
		"running",
		batchesDone,
		merged.Summary,
		string(b),
		batchesDone,
		totalBatches,
		progressPercent(batchesDone, totalBatches),
		fmt.Sprintf("triage checkpoint %d/%d", batchesDone, totalBatches),
		now,
		now,
		taskID,
	)
}

func (f *FixerAgent) reportRemediationProgress(ctx context.Context, job fixJob, ev remediationProgressEvent) {
	if ev.Percent < 0 {
		ev.Percent = 0
	}
	if ev.Percent > 100 {
		ev.Percent = 100
	}
	if ev.Total > 0 && ev.Current > ev.Total {
		ev.Current = ev.Total
	}
	if ev.Current < 0 {
		ev.Current = 0
	}
	if job.RemediationTaskID > 0 {
		_ = f.db.Exec(ctx, `
			UPDATE remediation_tasks
			   SET ai_progress_phase = ?,
			       ai_progress_current = ?,
			       ai_progress_total = ?,
			       ai_progress_percent = ?,
			       ai_progress_note = ?,
			       ai_progress_updated_at = ?
			 WHERE id = ?`,
			ev.Phase,
			ev.Current,
			ev.Total,
			ev.Percent,
			ev.Note,
			time.Now().UTC().Format(time.RFC3339),
			job.RemediationTaskID,
		)
	}
	if f.progressNotify != nil {
		f.progressNotify(ev)
	}
}

func progressPercent(current, total int) int {
	if total <= 0 {
		if current > 0 {
			return 100
		}
		return 0
	}
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}
	return int(float64(current) * 100 / float64(total))
}

func plannedFixAttempts(n int) int {
	if n < 0 {
		return 0
	}
	if n > maxFixAttemptsPerTaskDefault {
		return maxFixAttemptsPerTaskDefault
	}
	return n
}

func fixAttemptLabel(outcome fixAttemptOutcome) string {
	switch outcome {
	case fixAttemptQueued:
		return "queued"
	case fixAttemptLowConf:
		return "skipped-low-confidence"
	default:
		return "failed"
	}
}

func (f *FixerAgent) persistRemediationTaskOutcome(ctx context.Context, taskID int64, outcome aiRemediationOutcome) {
	if taskID <= 0 {
		return
	}
	if err := f.db.Migrate(ctx); err != nil {
		return
	}
	_ = f.db.Exec(ctx, `
		UPDATE remediation_tasks
		SET ai_findings_loaded = ?,
		    ai_findings_deduped = ?,
		    ai_triage_status = ?,
		    ai_triage_batches = ?,
		    ai_triage_summary = ?,
		    ai_triage_json = ?,
		    ai_provider = ?,
		    ai_model = ?,
		    ai_endpoint = ?,
		    ai_fix_attempted = ?,
		    ai_fix_queued = ?,
		    ai_fix_skipped_low_conf = ?,
		    ai_fix_failed = ?,
		    ai_updated_at = ?
		WHERE id = ?`,
		outcome.FindingsLoaded,
		outcome.FindingsDeduped,
		outcome.TriageStatus,
		outcome.TriageBatches,
		outcome.TriageSummary,
		outcome.TriagePrioritisedJSON,
		outcome.AIProvider,
		outcome.AIModel,
		outcome.AIEndpoint,
		outcome.FixAttempted,
		outcome.FixQueued,
		outcome.FixSkippedLowConfidence,
		outcome.FixFailed,
		time.Now().UTC().Format(time.RFC3339),
		taskID,
	)
}

func (f *FixerAgent) aiLineage() (provider, model, endpoint string) {
	provider = strings.TrimSpace(f.ai.Name())
	if provider == "" || provider == "none" {
		provider = strings.TrimSpace(f.cfg.AI.Provider)
	}
	model = strings.TrimSpace(f.cfg.AI.Model)
	endpoint = strings.TrimSpace(resolveAIEndpointURL(f.cfg.AI))
	return provider, model, endpoint
}

func resolveAIEndpointURL(cfg config.AIConfig) string {
	switch strings.TrimSpace(strings.ToLower(cfg.Provider)) {
	case "ollama":
		return strings.TrimSpace(cfg.OllamaURL)
	case "openai":
		return strings.TrimSpace(cfg.BaseURL)
	default:
		if strings.TrimSpace(cfg.BaseURL) != "" {
			return strings.TrimSpace(cfg.BaseURL)
		}
		return strings.TrimSpace(cfg.OllamaURL)
	}
}

// loadFindings collects open findings from all finding tables for a given scan job.
func (f *FixerAgent) loadFindings(ctx context.Context, scanJobID int64) []models.FindingSummary {
	var out []models.FindingSummary

	// Prefer unified normalized findings persisted at scan time.
	type unifiedRow struct {
		ID       int64  `db:"id"`
		Kind     string `db:"kind"`
		Scanner  string `db:"scanner"`
		Severity string `db:"severity"`
		Title    string `db:"title"`
		FilePath string `db:"file_path"`
		Line     int    `db:"line"`
		Message  string `db:"message"`
		Package  string `db:"package_name"`
		Version  string `db:"package_version"`
		FixHint  string `db:"fix_hint"`
		Status   string `db:"status"`
	}
	var unified []unifiedRow
	if err := f.db.Select(ctx, &unified, `
		SELECT id, kind, scanner, severity, title, file_path, line, message, package_name, package_version, fix_hint, status
		FROM scan_job_findings
		WHERE scan_job_id = ? AND status = 'open'
		ORDER BY id DESC`, scanJobID); err == nil && len(unified) > 0 {
		for _, u := range unified {
			title := strings.TrimSpace(u.Title)
			desc := strings.TrimSpace(u.Message)
			switch strings.TrimSpace(strings.ToLower(u.Kind)) {
			case "sca":
				// Keep AI prompt shape close to legacy SCA rows.
				if title != "" && u.Package != "" {
					title = fmt.Sprintf("%s in %s@%s", title, u.Package, u.Version)
				}
			case "secrets":
				if desc == "" {
					desc = "Potential secret detected"
				}
			}
			out = append(out, models.FindingSummary{
				ID:          fmt.Sprintf("unified-%s-%d", u.Kind, u.ID),
				Type:        u.Kind,
				Scanner:     u.Scanner,
				Severity:    models.MapSeverity(u.Severity),
				Title:       title,
				Description: desc,
				FilePath:    u.FilePath,
				LineNumber:  u.Line,
				CVE:         mapSCACVEFromUnified(u.Kind, u.Title),
				Package:     u.Package,
				FixVersion:  u.FixHint,
			})
		}
	}
	if len(out) == 0 {
		// SCA findings.
		var scaVulns []models.SCAVuln
		if err := f.db.Select(ctx, &scaVulns,
			`SELECT * FROM sca_vulns WHERE scan_job_id = ? AND status = 'open' ORDER BY cvss DESC`,
			scanJobID,
		); err == nil {
			for _, v := range scaVulns {
				out = append(out, models.FindingSummary{
					ID:          fmt.Sprintf("sca-%d", v.ID),
					Type:        "sca",
					Scanner:     "grype",
					Severity:    v.Severity,
					Title:       fmt.Sprintf("%s in %s@%s", v.CVE, v.PackageName, v.VersionAffected),
					Description: v.Description,
					CVE:         v.CVE,
					Package:     v.PackageName,
					FixVersion:  v.VersionRemediation,
				})
			}
		}

		// SAST findings.
		var sastFindings []models.SASTFinding
		if err := f.db.Select(ctx, &sastFindings,
			`SELECT * FROM sast_findings WHERE scan_job_id = ? AND status = 'open'`,
			scanJobID,
		); err == nil {
			for _, v := range sastFindings {
				out = append(out, models.FindingSummary{
					ID:          fmt.Sprintf("sast-%d", v.ID),
					Type:        "sast",
					Scanner:     v.Scanner,
					Severity:    v.Severity,
					Title:       v.CheckID,
					Description: v.Message,
					FilePath:    v.FilePath,
					LineNumber:  v.LineStart,
				})
			}
		}

		// Secrets findings.
		var secretsFindings []models.SecretsFinding
		if err := f.db.Select(ctx, &secretsFindings,
			`SELECT * FROM secrets_findings WHERE scan_job_id = ? AND status = 'open'`,
			scanJobID,
		); err == nil {
			for _, v := range secretsFindings {
				out = append(out, models.FindingSummary{
					ID:          fmt.Sprintf("secrets-%d", v.ID),
					Type:        "secrets",
					Scanner:     "trufflehog",
					Severity:    v.Severity,
					Title:       v.DetectorName,
					Description: "Potential secret detected",
					FilePath:    v.FilePath,
					LineNumber:  v.LineNumber,
				})
			}
		}

		// IaC findings.
		var iacFindings []models.IaCFinding
		if err := f.db.Select(ctx, &iacFindings,
			`SELECT * FROM iac_findings WHERE scan_job_id = ? AND status = 'open'`,
			scanJobID,
		); err == nil {
			for _, v := range iacFindings {
				out = append(out, models.FindingSummary{
					ID:          fmt.Sprintf("iac-%d", v.ID),
					Type:        "iac",
					Scanner:     v.Scanner,
					Severity:    v.Severity,
					Title:       v.Title,
					Description: v.Description,
					FilePath:    v.FilePath,
					LineNumber:  v.LineStart,
				})
			}
		}

		if len(out) == 0 {
			rawFindings := f.loadFindingsFromRawOutputs(ctx, scanJobID)
			if len(rawFindings) > 0 {
				slog.Info("Loaded findings from raw output fallback for AI triage",
					"scan_job_id", scanJobID,
					"count", len(rawFindings))
				out = append(out, rawFindings...)
			}
		}
	}

	if rules := f.loadEnabledPathIgnoreSubstrings(ctx); len(rules) > 0 {
		filtered := make([]models.FindingSummary, 0, len(out))
		for _, fd := range out {
			if shouldIgnoreFindingPathForFixer(fd.FilePath, rules) {
				continue
			}
			filtered = append(filtered, fd)
		}
		out = filtered
	}

	return out
}

func mapSCACVEFromUnified(kind, title string) string {
	if strings.EqualFold(strings.TrimSpace(kind), "sca") && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(title)), "CVE-") {
		return strings.TrimSpace(title)
	}
	return ""
}

func (f *FixerAgent) loadEnabledPathIgnoreSubstrings(ctx context.Context) []string {
	var rows []struct {
		Substring string `db:"substring"`
	}
	if err := f.db.Migrate(ctx); err != nil {
		return nil
	}
	if err := f.db.Select(ctx, &rows, `SELECT substring FROM finding_path_ignore_rules WHERE enabled = 1 ORDER BY id ASC`); err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		s := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(r.Substring, "\\", "/")))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func shouldIgnoreFindingPathForFixer(path string, rules []string) bool {
	if len(rules) == 0 {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(path, "\\", "/")))
	if p == "" {
		return false
	}
	for _, sub := range rules {
		if sub != "" && strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func (f *FixerAgent) loadFindingsFromRawOutputs(ctx context.Context, scanJobID int64) []models.FindingSummary {
	type rawRow struct {
		ScannerName string `db:"scanner_name"`
		RawOutput   []byte `db:"raw_output"`
	}
	var raws []rawRow
	if err := f.db.Select(ctx, &raws, `SELECT scanner_name, raw_output FROM scan_job_raw_outputs WHERE scan_job_id = ?`, scanJobID); err != nil {
		return nil
	}
	var out []models.FindingSummary
	for _, rr := range raws {
		switch rr.ScannerName {
		case "opengrep":
			out = append(out, parseOpengrepRawFindingSummaries(rr.RawOutput)...)
		case "trivy":
			out = append(out, parseTrivyRawFindingSummaries(rr.RawOutput)...)
		case "trufflehog":
			out = append(out, parseTrufflehogRawFindingSummaries(rr.RawOutput)...)
		case "grype":
			out = append(out, parseGrypeRawFindingSummaries(rr.RawOutput)...)
		}
	}
	return out
}

func parseOpengrepRawFindingSummaries(data []byte) []models.FindingSummary {
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
	out := make([]models.FindingSummary, 0, len(payload.Results))
	for i, r := range payload.Results {
		out = append(out, models.FindingSummary{
			ID:          fmt.Sprintf("raw-sast-%d", i+1),
			Type:        "sast",
			Scanner:     "opengrep",
			Severity:    models.MapSeverity(r.Extra.Severity),
			Title:       r.CheckID,
			Description: r.Extra.Message,
			FilePath:    normalizeRepoRelativePathForFixer(r.Path),
			LineNumber:  r.Start.Line,
		})
	}
	return out
}

func parseTrivyRawFindingSummaries(data []byte) []models.FindingSummary {
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
	var out []models.FindingSummary
	n := 1
	for _, r := range payload.Results {
		for _, m := range r.Misconfigurations {
			title := strings.TrimSpace(m.Title)
			if title == "" {
				title = m.ID
			}
			out = append(out, models.FindingSummary{
				ID:          fmt.Sprintf("raw-iac-%d", n),
				Type:        "iac",
				Scanner:     "trivy",
				Severity:    models.MapSeverity(m.Severity),
				Title:       title,
				Description: m.Description,
				FilePath:    normalizeRepoRelativePathForFixer(r.Target),
				LineNumber:  m.IacMetadata.StartLine,
			})
			n++
		}
	}
	return out
}

func parseTrufflehogRawFindingSummaries(data []byte) []models.FindingSummary {
	var out []models.FindingSummary
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
		file, lineNo := extractTrufflehogPathLineForFixer(rec.SourceMetadata)
		sev := models.SeverityMedium
		if rec.Verified {
			sev = models.SeverityHigh
		}
		title := strings.TrimSpace(rec.DetectorName)
		if title == "" {
			title = "Secret"
		}
		out = append(out, models.FindingSummary{
			ID:          fmt.Sprintf("raw-secrets-%d", i),
			Type:        "secrets",
			Scanner:     "trufflehog",
			Severity:    sev,
			Title:       title,
			Description: map[bool]string{true: "Verified secret detected", false: "Unverified secret candidate"}[rec.Verified],
			FilePath:    normalizeRepoRelativePathForFixer(file),
			LineNumber:  lineNo,
		})
		i++
	}
	return out
}

func parseGrypeRawFindingSummaries(data []byte) []models.FindingSummary {
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
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	out := make([]models.FindingSummary, 0, len(payload.Matches))
	for i, m := range payload.Matches {
		fixVersion := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixVersion = m.Vulnerability.Fix.Versions[0]
		}
		out = append(out, models.FindingSummary{
			ID:          fmt.Sprintf("raw-sca-%d", i+1),
			Type:        "sca",
			Scanner:     "grype",
			Severity:    models.MapSeverity(m.Vulnerability.Severity),
			Title:       m.Vulnerability.ID,
			Description: m.Vulnerability.Description,
			CVE:         m.Vulnerability.ID,
			Package:     m.Artifact.Name,
			FixVersion:  fixVersion,
		})
	}
	return out
}

func normalizeRepoRelativePathForFixer(path string) string {
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

func extractTrufflehogPathLineForFixer(source map[string]any) (string, int) {
	if len(source) == 0 {
		return "", 0
	}
	if data, ok := source["Data"].(map[string]any); ok {
		if p, l := findPathLineInAnyMapForFixer(data); p != "" || l != 0 {
			return p, l
		}
	}
	return findPathLineInAnyMapForFixer(source)
}

func findPathLineInAnyMapForFixer(m map[string]any) (string, int) {
	var path string
	var line int
	var walk func(any)
	walk = func(v any) {
		if path != "" && line != 0 {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				kl := strings.ToLower(strings.TrimSpace(k))
				switch kl {
				case "file", "filepath", "path":
					if path == "" {
						if s, ok := vv.(string); ok && strings.TrimSpace(s) != "" {
							path = s
						}
					}
				case "line", "linenumber", "line_number":
					if line == 0 {
						switch n := vv.(type) {
						case float64:
							line = int(n)
						case int:
							line = n
						}
					}
				}
				walk(vv)
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(m)
	return path, line
}

// readCodeContext reads lines around lineNum from filePath with line numbers.
// contextLines controls the window on each side of the finding.
func (f *FixerAgent) readCodeContext(repoPath, filePath string, lineNum, contextLines int) string {
	if filePath == "" {
		return ""
	}
	full, pathErr := safeRepoJoin(repoPath, filePath)
	if pathErr != nil {
		return ""
	}
	data, err := os.ReadFile(full) // #nosec G304 -- path validated by safeRepoJoin
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	// When the finding has no specific line number, return the full file
	// (capped at 300 lines so the prompt stays manageable).
	if lineNum <= 0 {
		end := len(lines)
		if end > 300 {
			end = 300
		}
		var sb strings.Builder
		for i := 0; i < end; i++ {
			sb.WriteString(fmt.Sprintf("%4d | %s\n", i+1, lines[i]))
		}
		return sb.String()
	}
	start := lineNum - contextLines - 1
	if start < 0 {
		start = 0
	}
	end := lineNum + contextLines
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		// Mark the exact finding line with ">>" so the model can locate it.
		marker := "  "
		if i+1 == lineNum {
			marker = ">>"
		}
		sb.WriteString(fmt.Sprintf("%4d%s| %s\n", i+1, marker, lines[i]))
	}
	return sb.String()
}

// readFileForFix returns (fullContent, totalLines).
// For files ≤ fullFileMaxLines it returns the entire content; for larger files
// it returns an empty string so the caller falls back to readCodeContext.
func (f *FixerAgent) readFileForFix(repoPath, filePath string) (string, int) {
	const fullFileMaxLines = 300
	if filePath == "" {
		return "", 0
	}
	safePath, pathErr := safeRepoJoin(repoPath, filePath)
	if pathErr != nil {
		return "", 0
	}
	data, err := os.ReadFile(safePath) // #nosec G304 -- path validated by safeRepoJoin
	if err != nil {
		return "", 0
	}
	lines := strings.Split(string(data), "\n")
	total := len(lines)
	if total > fullFileMaxLines {
		return "", total
	}
	var sb strings.Builder
	for i, l := range lines {
		sb.WriteString(fmt.Sprintf("%4d | %s\n", i+1, l))
	}
	return sb.String(), total
}

// detectLanguage guesses the programming language from a file extension.
func detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".go":
		return "Go"
	case ".js", ".mjs", ".cjs":
		return "JavaScript"
	case ".ts", ".tsx":
		return "TypeScript"
	case ".py":
		return "Python"
	case ".rb":
		return "Ruby"
	case ".java":
		return "Java"
	case ".rs":
		return "Rust"
	case ".php":
		return "PHP"
	case ".cs":
		return "C#"
	case ".cpp", ".cc", ".cxx":
		return "C++"
	case ".c":
		return "C"
	default:
		return "unknown"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// openBrowser opens a URL in the default browser.
func openBrowser(url string) {
	cmd := exec.Command("open", url) // #nosec G204 -- "open" is a macOS launcher literal; url is an https URL
	_ = cmd.Start()
}
