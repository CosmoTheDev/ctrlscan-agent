package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
)

const enrichBatchSize = 1000

// scaFinding is a lightweight projection of scan_job_findings for SCA rows.
type scaFinding struct {
	ID             int64  `db:"id"`
	Title          string `db:"title"`
	PackageName    string `db:"package_name"`
	PackageVersion string `db:"package_version"`
	FilePath       string `db:"file_path"`
}

// enrichmentRow maps to osv_enrichments for upsert.
type enrichmentRow struct {
	ScanJobID      int64   `db:"scan_job_id"`
	FindingID      int64   `db:"finding_id"`
	CVEID          string  `db:"cve_id"`
	OSVID          string  `db:"osv_id"`
	OSVAliases     string  `db:"osv_aliases"`
	CVSSScore      float64 `db:"cvss_score"`
	CVSSVector     string  `db:"cvss_vector"`
	CVSSSource     string  `db:"cvss_source"`
	OSVReferences  string  `db:"osv_references"`
	AffectedRanges string  `db:"affected_ranges"`
	Published      string  `db:"published"`
	Modified       string  `db:"modified"`
	EnrichedAt     string  `db:"enriched_at"`
}

// EnrichScanJob enriches scan_job_findings rows for jobID with OSV metadata.
// It is safe to call concurrently and is best-effort: if the OSV API is
// unreachable or a table is missing, it logs and returns nil so the caller's
// scan pipeline is never blocked.
func EnrichScanJob(ctx context.Context, db database.DB, jobID int64) error {
	var findings []scaFinding
	err := db.Select(ctx, &findings, `
		SELECT id, title, package_name, package_version, file_path
		FROM scan_job_findings
		WHERE scan_job_id = ? AND kind = 'sca' AND package_name != ''`,
		jobID,
	)
	if err != nil {
		if isNoSuchTableError(err) {
			return nil // migration hasn't run yet
		}
		return fmt.Errorf("osv: load findings for job %d: %w", jobID, err)
	}
	if len(findings) == 0 {
		return nil
	}

	client := New()
	enriched := 0
	failed := 0

	// Process in batches of enrichBatchSize.
	for start := 0; start < len(findings); start += enrichBatchSize {
		end := start + enrichBatchSize
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[start:end]

		queries := make([]PackageQuery, len(batch))
		for i, f := range batch {
			queries[i] = PackageQuery{
				Package: PackageID{
					Name:      f.PackageName,
					Ecosystem: ecosystemFromPath(f.FilePath),
				},
				Version:   f.PackageVersion,
				FindingID: f.ID,
			}
		}

		results, err := client.BatchQuery(ctx, queries)
		if err != nil {
			slog.Warn("osv: batch query failed", "job_id", jobID, "error", err)
			failed += len(batch)
			continue
		}

		now := time.Now().UTC().Format(time.RFC3339)
		for i, result := range results {
			if i >= len(batch) {
				break
			}
			if len(result.Vulns) == 0 {
				continue
			}

			f := batch[i]
			vuln := result.Vulns[0] // use the first (most relevant) match

			row := enrichmentRow{
				ScanJobID:      jobID,
				FindingID:      f.ID,
				CVEID:          extractCVE(vuln),
				OSVID:          vuln.ID,
				OSVAliases:     marshalJSON(vuln.Aliases),
				CVSSScore:      extractCVSSScore(vuln.Severity),
				CVSSVector:     extractCVSSVector(vuln.Severity),
				CVSSSource:     "osv",
				OSVReferences:  marshalRefURLs(vuln.References),
				AffectedRanges: marshalAffected(vuln.Affected),
				Published:      vuln.Published,
				Modified:       vuln.Modified,
				EnrichedAt:     now,
			}

			if err := db.Upsert(ctx, "osv_enrichments", row, []string{"finding_id"}); err != nil {
				if isNoSuchTableError(err) {
					return nil // migration not applied yet
				}
				slog.Warn("osv: upsert enrichment failed", "finding_id", f.ID, "error", err)
				failed++
				continue
			}
			enriched++
		}

		if ctx.Err() != nil {
			break
		}
	}

	slog.Info("osv: enrichment complete", "job_id", jobID, "enriched", enriched, "failed", failed, "total", len(findings))
	return nil
}

// ecosystemFromPath guesses the OSV ecosystem from a file path.
func ecosystemFromPath(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "node_modules") || strings.Contains(p, "package.json") || strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".ts"):
		return "npm"
	case strings.Contains(p, "go.mod") || strings.Contains(p, "go.sum") || strings.HasSuffix(p, ".go"):
		return "Go"
	case strings.Contains(p, "requirements") || strings.Contains(p, "site-packages") || strings.HasSuffix(p, ".py"):
		return "PyPI"
	case strings.Contains(p, "pom.xml") || strings.HasSuffix(p, ".jar") || strings.Contains(p, "gradle"):
		return "Maven"
	case strings.Contains(p, "cargo.toml") || strings.Contains(p, "cargo.lock") || strings.HasSuffix(p, ".rs"):
		return "crates.io"
	case strings.Contains(p, "gemfile") || strings.HasSuffix(p, ".rb") || strings.Contains(p, ".gemspec"):
		return "RubyGems"
	case strings.HasSuffix(p, ".nuspec") || strings.HasSuffix(p, ".nupkg") || strings.Contains(p, "packages.config"):
		return "NuGet"
	case strings.Contains(p, "composer.json") || strings.HasSuffix(p, ".php"):
		return "Packagist"
	default:
		return ""
	}
}

// extractCVE returns the first CVE alias from a vuln, or the OSV ID if none.
func extractCVE(v Vuln) string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	// OSV ID itself may be a CVE
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	return ""
}

// extractCVSSScore returns the CVSS v3 base score from a vector string.
// OSV returns the full vector; we extract the numeric score by calling out to
// a simple parser rather than pulling in a CVSS library.
func extractCVSSScore(severities []Severity) float64 {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			return parseCVSSScore(s.Score)
		}
	}
	for _, s := range severities {
		if s.Type == "CVSS_V2" {
			return parseCVSSScore(s.Score)
		}
	}
	return 0
}

func extractCVSSVector(severities []Severity) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			return s.Score
		}
	}
	for _, s := range severities {
		if s.Type == "CVSS_V2" {
			return s.Score
		}
	}
	return ""
}

// parseCVSSScore extracts the base score embedded in a CVSS vector.
// CVSS vectors look like: "CVSS:3.1/AV:N/.../E:U/RL:O/RC:C" — the base score
// is not in the vector string itself; OSV sometimes puts just the score as the
// Score field instead of a vector. Handle both cases.
func parseCVSSScore(score string) float64 {
	// If score is purely numeric (e.g. "9.8"), parse directly.
	var f float64
	_, err := fmt.Sscanf(score, "%f", &f)
	if err == nil && f > 0 {
		return f
	}
	return 0
}

func marshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func marshalRefURLs(refs []Reference) string {
	urls := make([]string, 0, len(refs))
	for _, r := range refs {
		urls = append(urls, r.URL)
	}
	return marshalJSON(urls)
}

func marshalAffected(affected []Affected) string {
	return marshalJSON(affected)
}

func isNoSuchTableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such table")
}
