package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
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
	cfg   *config.Config
	db    database.DB
	ai    aiPkg.AIProvider
}

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

	// If no AI is configured, scan results are already stored — nothing more to do.
	if !f.ai.IsAvailable(ctx) {
		slog.Info("Scan-only mode: findings stored, skipping AI triage and fix generation",
			"scan_job_id", job.ScanJobID)
		return nil
	}

	// Load open findings for this scan job.
	findings := f.loadFindings(ctx, job.ScanJobID)
	if len(findings) == 0 {
		slog.Info("No open findings for scan job", "scan_job_id", job.ScanJobID)
		return nil
	}

	slog.Info("Loaded findings for triage", "count", len(findings), "scan_job_id", job.ScanJobID)

	// Triage with AI.
	triage, err := f.ai.TriageFindings(ctx, findings)
	if err != nil {
		slog.Warn("AI triage failed, processing all findings", "error", err)
		// Fall back: process all findings without prioritisation.
		for i := range findings {
			f.generateAndQueueFix(ctx, findings[i], job)
		}
		return nil
	}

	slog.Info("Triage complete", "summary", triage.Summary)

	// Generate fixes in priority order.
	for _, tf := range triage.Prioritised {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.generateAndQueueFix(ctx, tf.Finding, job)
	}

	return nil
}

func (f *FixerAgent) generateAndQueueFix(ctx context.Context, finding models.FindingSummary, job fixJob) {
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
		return
	}

	if fixResult.Confidence < 0.3 {
		slog.Info("Skipping low-confidence fix",
			"finding_id", finding.ID,
			"confidence", fixResult.Confidence,
		)
		return
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
		return
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
				ID:         fmt.Sprintf("sast-%d", v.ID),
				Type:       "sast",
				Scanner:    v.Scanner,
				Severity:   v.Severity,
				Title:      v.CheckID,
				Description: v.Message,
				FilePath:   v.FilePath,
				LineNumber: v.LineStart,
			})
		}
	}

	return out
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
