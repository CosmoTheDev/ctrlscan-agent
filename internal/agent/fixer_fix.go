package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	aiPkg "github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

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

