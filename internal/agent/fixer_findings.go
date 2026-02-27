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
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

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
