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
	cfg *config.Config
	db  database.DB
	ai  aiPkg.AIProvider
}

type aiRemediationOutcome struct {
	FindingsLoaded         int
	FindingsDeduped        int
	TriageStatus           string
	TriageBatches          int
	TriageSummary          string
	TriagePrioritisedJSON  string
	FixAttempted           int
	FixQueued              int
	FixSkippedLowConfidence int
	FixFailed              int
}

type fixAttemptOutcome string

const (
	fixAttemptQueued   fixAttemptOutcome = "queued"
	fixAttemptLowConf  fixAttemptOutcome = "low_conf"
	fixAttemptFailed   fixAttemptOutcome = "failed"
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
				slog.Error("Fixer job failed",
					"scan_job_id", job.ScanJobID,
					"error", err,
				)
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
	slog.Info("Fixer processing scan job", "scan_job_id", job.ScanJobID)
	outcome := aiRemediationOutcome{}
	defer f.persistRemediationTaskOutcome(ctx, job.RemediationTaskID, outcome)

	// If no AI is configured, scan results are already stored — nothing more to do.
	if !f.ai.IsAvailable(ctx) {
		slog.Info("Scan-only mode: findings stored, skipping AI triage and fix generation",
			"scan_job_id", job.ScanJobID)
		outcome.TriageStatus = "ai_unavailable"
		return nil
	}

	// Load open findings for this scan job.
	findings := f.loadFindings(ctx, job.ScanJobID)
	outcome.FindingsLoaded = len(findings)
	if len(findings) == 0 {
		slog.Info("No open findings for scan job", "scan_job_id", job.ScanJobID)
		outcome.TriageStatus = "no_findings"
		return nil
	}

	slog.Info("Loaded findings for triage", "count", len(findings), "scan_job_id", job.ScanJobID)
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

	// Triage with AI (chunked for large scans).
	triage, triageBatches, err := f.triageFindingsChunked(ctx, deduped)
	outcome.TriageBatches = triageBatches
	if err != nil {
		outcome.TriageStatus = "failed_fallback"
		outcome.TriageSummary = fmt.Sprintf("AI triage failed; processed fallback subset. Error: %v", err)
		fallback := deduped
		if len(fallback) > 40 {
			fallback = selectFallbackFixCandidates(deduped, 40)
		}
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
			switch f.generateAndQueueFix(ctx, fallback[i], job) {
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
		}
		return nil
	}
	outcome.TriageStatus = "completed"
	outcome.TriageSummary = triage.Summary
	if b, err := json.Marshal(triage.Prioritised); err == nil {
		outcome.TriagePrioritisedJSON = string(b)
	}

	slog.Info("Triage complete", "summary", triage.Summary)

	// Generate fixes in priority order.
	for _, tf := range triage.Prioritised {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch f.generateAndQueueFix(ctx, tf.Finding, job) {
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
	}

	return nil
}

func (f *FixerAgent) triageFindingsChunked(ctx context.Context, findings []models.FindingSummary) (*aiPkg.TriageResult, int, error) {
	if len(findings) == 0 {
		return &aiPkg.TriageResult{Summary: "No findings to triage."}, 0, nil
	}
	// Keep prompts under TPM ceilings for large scans. We use a chunk size small
	// enough to survive verbose finding descriptions but large enough to preserve
	// some local ranking context.
	const chunkSize = 40
	if len(findings) <= chunkSize {
		res, err := f.ai.TriageFindings(ctx, findings)
		return res, 1, err
	}

	chunks := chunkFindings(findings, chunkSize)
	merged := &aiPkg.TriageResult{
		Summary:     fmt.Sprintf("Chunked triage over %d findings across %d batches.", len(findings), len(chunks)),
		Prioritised: make([]aiPkg.TriagedFinding, 0, len(findings)),
	}
	nextPriority := 1

	for idx, chunk := range chunks {
		if ctx.Err() != nil {
			return nil, len(chunks), ctx.Err()
		}
		slog.Info("Running chunked AI triage batch",
			"batch", idx+1,
			"batches", len(chunks),
			"chunk_size", len(chunk),
		)
		res, err := f.ai.TriageFindings(ctx, chunk)
		if err != nil {
			return nil, len(chunks), err
		}
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
	}
	return merged, len(chunks), nil
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

func (f *FixerAgent) generateAndQueueFix(ctx context.Context, finding models.FindingSummary, job fixJob) fixAttemptOutcome {
	// Read code context from the clone.
	codeCtx := f.readCodeContext(job.RepoPath, finding.FilePath, finding.LineNumber, 10)
	lang := detectLanguage(finding.FilePath)

	fixResult, err := f.ai.GenerateFix(ctx, aiPkg.FixRequest{
		Finding:     finding,
		CodeContext: codeCtx,
		FilePath:    finding.FilePath,
		Language:    lang,
	})
	if err != nil {
		slog.Warn("Fix generation failed", "finding_id", finding.ID, "error", err)
		return fixAttemptFailed
	}

	if fixResult.Confidence < 0.3 {
		slog.Info("Skipping low-confidence fix",
			"finding_id", finding.ID,
			"confidence", fixResult.Confidence,
		)
		return fixAttemptLowConf
	}

	// Store fix in fix_queue with status based on agent mode.
	status := "pending"
	if f.cfg.Agent.Mode == "auto" {
		status = "approved"
	}

	now := time.Now().UTC()
	fix := &models.FixQueue{
		ScanJobID:   job.ScanJobID,
		FindingType: finding.Type,
		Patch:       fixResult.Patch,
		PRTitle:     fmt.Sprintf("fix(security): %s", truncate(finding.Title, 60)),
		PRBody:      fixResult.Explanation,
		Status:      status,
		GeneratedAt: now,
	}

	if _, err := f.db.Insert(ctx, "fix_queue", fix); err != nil {
		slog.Error("Failed to save fix to queue", "error", err)
		return fixAttemptFailed
	}

	slog.Info("Fix queued",
		"finding_id", finding.ID,
		"confidence", fmt.Sprintf("%.0f%%", fixResult.Confidence*100),
		"status", status,
	)

	// In semi mode: open browser to show the pending fix.
	if f.cfg.Agent.Mode == "semi" {
		slog.Info("Semi mode: fix queued for manual review in ctrlscan ui",
			"finding_id", finding.ID)
	}
	return fixAttemptQueued
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
		outcome.FixAttempted,
		outcome.FixQueued,
		outcome.FixSkippedLowConfidence,
		outcome.FixFailed,
		time.Now().UTC().Format(time.RFC3339),
		taskID,
	)
}

// loadFindings collects open findings from all finding tables for a given scan job.
func (f *FixerAgent) loadFindings(ctx context.Context, scanJobID int64) []models.FindingSummary {
	var out []models.FindingSummary

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

// readCodeContext reads lines around lineNum from filePath.
func (f *FixerAgent) readCodeContext(repoPath, filePath string, lineNum, contextLines int) string {
	if filePath == "" {
		return ""
	}
	full := filepath.Join(repoPath, filePath)
	data, err := os.ReadFile(full)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
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
		sb.WriteString(fmt.Sprintf("%4d | %s\n", i+1, lines[i]))
	}
	return sb.String()
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
	cmd := exec.Command("open", url)
	_ = cmd.Start()
}
