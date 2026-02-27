package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	aiPkg "github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

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
