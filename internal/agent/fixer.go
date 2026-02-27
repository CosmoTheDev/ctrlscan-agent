package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	aiPkg "github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
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
