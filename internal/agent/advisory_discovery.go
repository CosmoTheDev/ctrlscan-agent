package agent

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/osv"
)

// advisoryPollStateRow maps to the advisory_poll_state table.
type advisoryPollStateRow struct {
	ID             int64  `db:"id"`
	Source         string `db:"source"`
	LastPolledAt   string `db:"last_polled_at"`
	LastModified   string `db:"last_modified"`
	AdvisoriesSeen int64  `db:"advisories_seen"`
	ReposQueued    int64  `db:"repos_queued"`
	CreatedAt      string `db:"created_at"`
	UpdatedAt      string `db:"updated_at"`
}

// runAdvisoryFeedDiscovery polls the OSV advisory feed for new/updated
// vulnerabilities and queues repos that use the affected packages.
// It is called from RunOnce when "advisory_feed" is in scan_targets.
func (d *DiscoveryAgent) runAdvisoryFeedDiscovery(ctx context.Context, out chan<- repoJob) error {
	now := time.Now().UTC()

	// Load (or initialise) the poll state cursor.
	var state advisoryPollStateRow
	err := d.db.Get(ctx, &state, `SELECT * FROM advisory_poll_state WHERE source = 'osv' LIMIT 1`)
	if err != nil {
		if !isNoSuchTableOrRow(err) {
			slog.Warn("advisory: failed to load poll state", "error", err)
			return nil
		}
		// First run — insert blank state.
		state = advisoryPollStateRow{
			Source:    "osv",
			CreatedAt: now.Format(time.RFC3339),
			UpdatedAt: now.Format(time.RFC3339),
		}
		if insErr := d.db.Exec(ctx,
			`INSERT INTO advisory_poll_state (source, last_polled_at, last_modified, advisories_seen, repos_queued, created_at, updated_at)
			 VALUES ('osv', '', '', 0, 0, ?, ?)`,
			state.CreatedAt, state.UpdatedAt,
		); insErr != nil {
			if isNoSuchTableOrRow(insErr) {
				return nil // migration not applied yet; silently skip
			}
			slog.Warn("advisory: failed to init poll state", "error", insErr)
			return nil
		}
	}

	slog.Info("advisory: polling OSV feed", "since", state.LastModified)

	client := osv.New()
	vulns, err := client.ListModifiedSince(ctx, state.LastModified)
	if err != nil {
		slog.Warn("advisory: OSV list failed", "error", err)
		return nil
	}

	if len(vulns) == 0 {
		slog.Info("advisory: no new advisories since last poll")
		_ = d.updatePollState(ctx, state.LastModified, 0, 0)
		return nil
	}

	slog.Info("advisory: fetched advisories", "count", len(vulns))

	// Filter by configured ecosystems and min severity.
	ecosystems := d.cfg.AdvisoryFeed.Ecosystems
	minSev := d.cfg.AdvisoryFeed.MinSeverity
	if minSev == "" {
		minSev = "high"
	}
	maxPerAdvisory := d.cfg.AdvisoryFeed.MaxReposPerAdvisory
	if maxPerAdvisory <= 0 {
		maxPerAdvisory = 20
	}

	var newestModified string
	totalReposQueued := int64(0)
	advisoriesSeen := int64(0)

	for _, vuln := range vulns {
		if ctx.Err() != nil {
			break
		}

		// Track the newest modified timestamp as our next cursor.
		if vuln.Modified > newestModified {
			newestModified = vuln.Modified
		}

		// Filter by minimum severity.
		if !meetsSeverity(vuln.Severity, minSev) {
			continue
		}

		advisoriesSeen++

		// For each affected package in the advisory, search for repos.
		reposQueued := 0
		for _, affected := range vuln.Affected {
			if reposQueued >= maxPerAdvisory {
				break
			}
			if ctx.Err() != nil {
				break
			}

			pkg := affected.Package
			if pkg.Name == "" {
				continue
			}
			if len(ecosystems) > 0 && !containsStr(ecosystems, pkg.Ecosystem) {
				continue
			}

			query := buildSearchQuery(pkg.Name, pkg.Ecosystem)
			if query == "" {
				continue
			}

			for _, p := range d.providers {
				if reposQueued >= maxPerAdvisory {
					break
				}
				repos, err := p.SearchRepos(ctx, query)
				if err != nil {
					slog.Warn("advisory: repo search failed",
						"package", pkg.Name, "ecosystem", pkg.Ecosystem,
						"provider", p.Name(), "error", err)
					continue
				}
				for _, r := range repos {
					if reposQueued >= maxPerAdvisory {
						break
					}
					select {
					case out <- repoJob{
						Provider: p,
						Owner:    r.Owner,
						Name:     r.Name,
						CloneURL: r.CloneURL,
						Branch:   r.DefaultBranch,
					}:
						reposQueued++
					case <-ctx.Done():
						break
					}
				}
			}
		}
		totalReposQueued += int64(reposQueued)
	}

	cursor := newestModified
	if cursor == "" {
		cursor = state.LastModified
	}
	_ = d.updatePollState(ctx, cursor, advisoriesSeen, totalReposQueued)

	slog.Info("advisory: discovery complete",
		"advisories_seen", advisoriesSeen,
		"repos_queued", totalReposQueued,
	)
	return nil
}

func (d *DiscoveryAgent) updatePollState(ctx context.Context, lastModified string, advisoriesSeen, reposQueued int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return d.db.Exec(ctx, `
		UPDATE advisory_poll_state
		SET last_polled_at  = ?,
		    last_modified   = ?,
		    advisories_seen = advisories_seen + ?,
		    repos_queued    = repos_queued + ?,
		    updated_at      = ?
		WHERE source = 'osv'`,
		now, lastModified, advisoriesSeen, reposQueued, now,
	)
}

// buildSearchQuery constructs a GitHub code search query for a package.
func buildSearchQuery(pkgName, ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return `"` + pkgName + `" filename:package.json`
	case "go":
		return `"` + pkgName + `" filename:go.mod`
	case "pypi":
		return `"` + pkgName + `" filename:requirements.txt`
	case "maven":
		return `"` + pkgName + `" filename:pom.xml`
	case "crates.io":
		return `"` + pkgName + `" filename:Cargo.toml`
	case "rubygems":
		return `"` + pkgName + `" filename:Gemfile`
	case "nuget":
		return `"` + pkgName + `" filename:packages.config`
	case "packagist":
		return `"` + pkgName + `" filename:composer.json`
	default:
		if pkgName == "" {
			return ""
		}
		return `"` + pkgName + `"`
	}
}

// severityOrder maps severity strings to numeric weights for comparison.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"":         0,
}

// meetsSeverity reports whether the vuln's highest CVSS score meets the minimum.
func meetsSeverity(severities []osv.Severity, minSev string) bool {
	if minSev == "" || minSev == "low" {
		return true
	}
	minWeight := severityOrder[strings.ToLower(minSev)]
	for _, s := range severities {
		score := parseCVSSFloat(s.Score)
		if severityWeight(score) >= minWeight {
			return true
		}
	}
	// If no severity info, include by default.
	return len(severities) == 0
}

func severityWeight(cvssScore float64) int {
	switch {
	case cvssScore >= 9.0:
		return 4
	case cvssScore >= 7.0:
		return 3
	case cvssScore >= 4.0:
		return 2
	case cvssScore > 0:
		return 1
	default:
		return 0
	}
}

func parseCVSSFloat(score string) float64 {
	s := strings.TrimSpace(score)
	// CVSS vector strings like "CVSS:3.1/AV:N/..." are not numeric.
	if strings.Contains(s, "/") || strings.Contains(s, ":") {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}

func isNoSuchTableOrRow(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such table") ||
		strings.Contains(msg, "no rows") ||
		strings.Contains(msg, "sql: no rows in result set")
}
