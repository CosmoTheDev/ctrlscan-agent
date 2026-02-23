package models

import "time"

// ScanJob tracks an individual scan of a repository.
type ScanJob struct {
	ID               int64      `json:"id"                db:"id"`
	UniqueKey        string     `json:"unique_key"        db:"unique_key"`  // provider:owner:repo:branch:commit
	Provider         string     `json:"provider"          db:"provider"`
	Owner            string     `json:"owner"             db:"owner"`
	Repo             string     `json:"repo"              db:"repo"`
	Branch           string     `json:"branch"            db:"branch"`
	Commit           string     `json:"commit"            db:"commit_sha"`
	Status           string     `json:"status"            db:"status"`      // pending|running|completed|failed|partial
	ScanMode         string     `json:"scan_mode"         db:"scan_mode"`   // local|docker
	FindingsCritical int        `json:"findings_critical" db:"findings_critical"`
	FindingsHigh     int        `json:"findings_high"     db:"findings_high"`
	FindingsMedium   int        `json:"findings_medium"   db:"findings_medium"`
	FindingsLow      int        `json:"findings_low"      db:"findings_low"`
	StartedAt        time.Time  `json:"started_at"        db:"started_at"`
	CompletedAt      *time.Time `json:"completed_at"      db:"completed_at"`
	ErrorMsg         string     `json:"error_msg"         db:"error_msg"`
}

// ScanJobScanner tracks individual scanner results within a job.
type ScanJobScanner struct {
	ID            int64  `json:"id"             db:"id"`
	ScanJobID     int64  `json:"scan_job_id"    db:"scan_job_id"`
	ScannerName   string `json:"scanner_name"   db:"scanner_name"`
	ScannerType   string `json:"scanner_type"   db:"scanner_type"`   // sca|sast|secrets|iac
	Status        string `json:"status"         db:"status"`         // pending|running|completed|failed|skipped
	FindingsCount int    `json:"findings_count" db:"findings_count"`
	DurationMs    int64  `json:"duration_ms"    db:"duration_ms"`
	ErrorMsg      string `json:"error_msg"      db:"error_msg"`
}

// FindingSummary is a lightweight representation passed to AI for triage.
type FindingSummary struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`        // sca|sast|secrets|iac
	Scanner     string        `json:"scanner"`
	Severity    SeverityLevel `json:"severity"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	FilePath    string        `json:"file_path"`
	LineNumber  int           `json:"line_number"`
	CVE         string        `json:"cve,omitempty"`
	Package     string        `json:"package,omitempty"`
	FixVersion  string        `json:"fix_version,omitempty"`
}
