package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"

	aiPkg "github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

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
