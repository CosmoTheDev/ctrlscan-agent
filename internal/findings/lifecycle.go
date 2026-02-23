package findings

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
)

type RawOutputRow struct {
	ScannerName string `db:"scanner_name"`
	RawOutput   []byte `db:"raw_output"`
}

type PersistScanOptions struct {
	ScanJobID int64
	Provider  string
	Owner     string
	Repo      string
	Branch    string
	CommitSHA string
	ScannedAt time.Time
}

type ScanSummary struct {
	PresentCount      int
	IntroducedCount   int
	FixedCount        int
	ReintroducedCount int
}

type lifecycleRow struct {
	ID              int64   `db:"id"`
	Kind            string  `db:"kind"`
	Fingerprint     string  `db:"fingerprint"`
	Status          string  `db:"status"`
	FirstSeenAt     string  `db:"first_seen_at"`
	LastSeenAt      string  `db:"last_seen_at"`
	ReintroducedCnt int     `db:"reintroduced_count"`
	TotalSeenCount  int     `db:"total_seen_count"`
	FirstSeenScanID int64   `db:"first_seen_scan_job_id"`
	LastSeenScanID  int64   `db:"last_seen_scan_job_id"`
	FixedAtScanID   *int64  `db:"fixed_at_scan_job_id"`
	FirstSeenCommit string  `db:"first_seen_commit_sha"`
	LastSeenCommit  string  `db:"last_seen_commit_sha"`
	FixedAtCommit   *string `db:"fixed_at_commit_sha"`
}

// PersistNormalizedFromRaw parses scanner raw outputs, stores per-scan normalized findings,
// updates lifecycle state, and records per-scan summary deltas.
func PersistNormalizedFromRaw(ctx context.Context, db database.DB, opts PersistScanOptions) (*ScanSummary, error) {
	if db == nil || opts.ScanJobID <= 0 {
		return nil, nil
	}
	var raws []RawOutputRow
	if err := db.Select(ctx, &raws, `SELECT scanner_name, raw_output FROM scan_job_raw_outputs WHERE scan_job_id = ?`, opts.ScanJobID); err != nil {
		return nil, err
	}
	if len(raws) == 0 {
		return &ScanSummary{}, nil
	}

	parsed := make([]NormalizedFinding, 0, 256)
	for _, rr := range raws {
		parsed = append(parsed, ParseRawScannerOutput(rr.ScannerName, rr.RawOutput)...)
	}
	parsed = Dedup(parsed)

	now := opts.ScannedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowStr := now.Format(time.RFC3339)

	if err := db.Exec(ctx, `DELETE FROM scan_job_findings WHERE scan_job_id = ?`, opts.ScanJobID); err != nil {
		return nil, err
	}

	var existing []lifecycleRow
	if err := db.Select(ctx, &existing, `SELECT id, kind, fingerprint, status, first_seen_at, last_seen_at,
		reintroduced_count, total_seen_count, first_seen_scan_job_id, last_seen_scan_job_id, fixed_at_scan_job_id,
		first_seen_commit_sha, last_seen_commit_sha, fixed_at_commit_sha
		FROM repo_finding_lifecycles
		WHERE provider = ? AND owner = ? AND repo = ? AND branch = ?`,
		opts.Provider, opts.Owner, opts.Repo, opts.Branch); err != nil {
		return nil, err
	}

	lifeByKey := make(map[string]lifecycleRow, len(existing))
	for _, r := range existing {
		lifeByKey[keyFor(r.Kind, r.Fingerprint)] = r
	}

	summary := &ScanSummary{PresentCount: len(parsed)}
	presentKeys := make(map[string]struct{}, len(parsed))
	type snapshotMeta struct {
		FirstSeen string
		LastSeen  string
		Status    string
		Intro     bool
		Reintro   bool
	}
	snapshot := make(map[string]snapshotMeta, len(parsed))

	for _, f := range parsed {
		k := keyFor(f.Kind, f.Fingerprint)
		presentKeys[k] = struct{}{}
		prev, hasPrev := lifeByKey[k]

		introduced := !hasPrev
		reintroduced := hasPrev && strings.EqualFold(strings.TrimSpace(prev.Status), "fixed")
		if introduced {
			summary.IntroducedCount++
			if err := db.Exec(ctx, `INSERT INTO repo_finding_lifecycles (
				provider, owner, repo, branch, kind, scanner, fingerprint, status,
				first_seen_scan_job_id, first_seen_commit_sha, first_seen_at,
				last_seen_scan_job_id, last_seen_commit_sha, last_seen_at,
				fixed_at_scan_job_id, fixed_at_commit_sha, fixed_at,
				reintroduced_count, total_seen_count,
				latest_severity, latest_title, latest_file_path, latest_line, latest_message, latest_package, latest_version, latest_fix
			) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
				opts.Provider, opts.Owner, opts.Repo, opts.Branch, f.Kind, f.Scanner, f.Fingerprint,
				opts.ScanJobID, opts.CommitSHA, nowStr,
				opts.ScanJobID, opts.CommitSHA, nowStr,
				f.Severity, f.Title, f.FilePath, f.Line, f.Message, f.Package, f.Version, f.Fix,
			); err != nil {
				return nil, err
			}
			snapshot[k] = snapshotMeta{FirstSeen: nowStr, LastSeen: nowStr, Status: "open", Intro: true}
			continue
		}

		reintroInc := 0
		if reintroduced {
			reintroInc = 1
			summary.ReintroducedCount++
		}
		if err := db.Exec(ctx, `UPDATE repo_finding_lifecycles
			SET status = 'open',
			    last_seen_scan_job_id = ?, last_seen_commit_sha = ?, last_seen_at = ?,
			    fixed_at_scan_job_id = NULL, fixed_at_commit_sha = NULL, fixed_at = NULL,
			    reintroduced_count = reintroduced_count + ?,
			    total_seen_count = total_seen_count + 1,
			    latest_severity = ?, latest_title = ?, latest_file_path = ?, latest_line = ?,
			    latest_message = ?, latest_package = ?, latest_version = ?, latest_fix = ?
			WHERE provider = ? AND owner = ? AND repo = ? AND branch = ? AND kind = ? AND fingerprint = ?`,
			opts.ScanJobID, opts.CommitSHA, nowStr,
			reintroInc,
			f.Severity, f.Title, f.FilePath, f.Line, f.Message, f.Package, f.Version, f.Fix,
			opts.Provider, opts.Owner, opts.Repo, opts.Branch, f.Kind, f.Fingerprint,
		); err != nil {
			return nil, err
		}
		firstSeen := strings.TrimSpace(prev.FirstSeenAt)
		if firstSeen == "" {
			firstSeen = nowStr
		}
		snapshot[k] = snapshotMeta{
			FirstSeen: firstSeen,
			LastSeen:  nowStr,
			Status:    "open",
			Reintro:   reintroduced,
		}
	}

	for _, prev := range existing {
		k := keyFor(prev.Kind, prev.Fingerprint)
		if _, ok := presentKeys[k]; ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(prev.Status), "open") {
			continue
		}
		summary.FixedCount++
		if err := db.Exec(ctx, `UPDATE repo_finding_lifecycles
			SET status = 'fixed', fixed_at_scan_job_id = ?, fixed_at_commit_sha = ?, fixed_at = ?
			WHERE provider = ? AND owner = ? AND repo = ? AND branch = ? AND kind = ? AND fingerprint = ?`,
			opts.ScanJobID, opts.CommitSHA, nowStr,
			opts.Provider, opts.Owner, opts.Repo, opts.Branch, prev.Kind, prev.Fingerprint,
		); err != nil {
			return nil, err
		}
	}

	for _, f := range parsed {
		meta := snapshot[keyFor(f.Kind, f.Fingerprint)]
		if err := db.Exec(ctx, `INSERT INTO scan_job_findings (
			scan_job_id, kind, scanner, fingerprint, severity, title, file_path, line, message, package_name, package_version, fix_hint,
			status, first_seen_at, last_seen_at, introduced, reintroduced
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			opts.ScanJobID, f.Kind, f.Scanner, f.Fingerprint, f.Severity, f.Title, f.FilePath, f.Line, f.Message, f.Package, f.Version, f.Fix,
			firstNonEmpty(meta.Status, "open"), firstNonEmpty(meta.FirstSeen, nowStr), firstNonEmpty(meta.LastSeen, nowStr),
			boolToInt(meta.Intro), boolToInt(meta.Reintro),
		); err != nil {
			return nil, err
		}
	}

	if err := db.Exec(ctx, `INSERT INTO scan_job_finding_summaries (
		scan_job_id, provider, owner, repo, branch, commit_sha,
		present_count, introduced_count, fixed_count, reintroduced_count, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(scan_job_id) DO UPDATE SET
		provider = excluded.provider,
		owner = excluded.owner,
		repo = excluded.repo,
		branch = excluded.branch,
		commit_sha = excluded.commit_sha,
		present_count = excluded.present_count,
		introduced_count = excluded.introduced_count,
		fixed_count = excluded.fixed_count,
		reintroduced_count = excluded.reintroduced_count,
		created_at = excluded.created_at`,
		opts.ScanJobID, opts.Provider, opts.Owner, opts.Repo, opts.Branch, opts.CommitSHA,
		summary.PresentCount, summary.IntroducedCount, summary.FixedCount, summary.ReintroducedCount, nowStr,
	); err != nil {
		return nil, err
	}

	return summary, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// IsNoSuchTableError helps callers gracefully degrade before migrations are applied.
func IsNoSuchTableError(err error) bool {
	if err == nil {
		return false
	}
	if err == sql.ErrNoRows {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}

func LogPersistError(jobID int64, err error) {
	if err == nil {
		return
	}
	slog.Warn("Failed to persist normalized findings lifecycle", "job_id", jobID, "error", err)
}

func SummaryDebugString(s *ScanSummary) string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("present=%d introduced=%d fixed=%d reintroduced=%d", s.PresentCount, s.IntroducedCount, s.FixedCount, s.ReintroducedCount)
}
