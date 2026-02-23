package models

import (
	"encoding/json"
	"time"
)

// jsonUnmarshal is a local alias to avoid circular imports.
var jsonUnmarshal = json.Unmarshal

// SASTFinding represents a static analysis finding (opengrep/semgrep).
type SASTFinding struct {
	ID          int64         `json:"id"           db:"id"`
	UniqueKey   string        `json:"unique_key"   db:"unique_key"` // provider:owner:repo:branch:check_id:fingerprint
	ScanJobID   int64         `json:"scan_job_id"  db:"scan_job_id"`
	Scanner     string        `json:"scanner"      db:"scanner"` // opengrep
	CheckID     string        `json:"check_id"     db:"check_id"`
	Severity    SeverityLevel `json:"severity"     db:"severity"`
	FilePath    string        `json:"file_path"    db:"file_path"`
	LineStart   int           `json:"line_start"   db:"line_start"`
	LineEnd     int           `json:"line_end"     db:"line_end"`
	ColStart    int           `json:"col_start"    db:"col_start"`
	ColEnd      int           `json:"col_end"      db:"col_end"`
	Message     string        `json:"message"      db:"message"`
	Fingerprint string        `json:"fingerprint"  db:"fingerprint"`
	Category    string        `json:"category"     db:"category"`
	Confidence  string        `json:"confidence"   db:"confidence"`
	CWEs        string        `json:"cwes"         db:"cwes"`   // JSON array
	OWASP       string        `json:"owasp"        db:"owasp"`  // JSON array
	Status      string        `json:"status"       db:"status"` // open|fixed|ignored|pr_open|pr_merged
	PRNumber    int           `json:"pr_number"    db:"pr_number"`
	FirstSeenAt time.Time     `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt  time.Time     `json:"last_seen_at"  db:"last_seen_at"`
}

// SecretsFinding represents a secret/credential detected by trufflehog.
type SecretsFinding struct {
	ID             int64         `json:"id"               db:"id"`
	UniqueKey      string        `json:"unique_key"       db:"unique_key"` // provider:owner:repo:branch:cred_hash:loc_hash
	ScanJobID      int64         `json:"scan_job_id"      db:"scan_job_id"`
	DetectorName   string        `json:"detector_name"    db:"detector_name"`
	DetectorType   string        `json:"detector_type"    db:"detector_type"`
	Verified       bool          `json:"verified"         db:"verified"`
	CredentialHash string        `json:"credential_hash"  db:"credential_hash"` // hash only, never raw
	LocationHash   string        `json:"location_hash"    db:"location_hash"`
	FilePath       string        `json:"file_path"        db:"file_path"`
	LineNumber     int           `json:"line_number"      db:"line_number"`
	Severity       SeverityLevel `json:"severity"         db:"severity"`
	RawMetadata    string        `json:"raw_metadata"     db:"raw_metadata"` // redacted JSON
	Status         string        `json:"status"           db:"status"`       // open|fixed|ignored|pr_open|pr_merged
	PRNumber       int           `json:"pr_number"        db:"pr_number"`
	FirstSeenAt    time.Time     `json:"first_seen_at"    db:"first_seen_at"`
	LastSeenAt     time.Time     `json:"last_seen_at"     db:"last_seen_at"`
}

// IaCFinding represents an infrastructure-as-code misconfiguration (trivy).
type IaCFinding struct {
	ID          int64         `json:"id"           db:"id"`
	UniqueKey   string        `json:"unique_key"   db:"unique_key"`
	ScanJobID   int64         `json:"scan_job_id"  db:"scan_job_id"`
	Scanner     string        `json:"scanner"      db:"scanner"` // trivy
	CheckID     string        `json:"check_id"     db:"check_id"`
	Title       string        `json:"title"        db:"title"`
	Description string        `json:"description"  db:"description"`
	Severity    SeverityLevel `json:"severity"     db:"severity"`
	FilePath    string        `json:"file_path"    db:"file_path"`
	LineStart   int           `json:"line_start"   db:"line_start"`
	Resource    string        `json:"resource"     db:"resource"`
	Status      string        `json:"status"       db:"status"`
	PRNumber    int           `json:"pr_number"    db:"pr_number"`
	FirstSeenAt time.Time     `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt  time.Time     `json:"last_seen_at"  db:"last_seen_at"`
}

// FixQueue tracks AI-generated fixes awaiting PR creation.
type FixQueue struct {
	ID          int64      `json:"id"            db:"id"`
	ScanJobID   int64      `json:"scan_job_id"   db:"scan_job_id"`
	FindingType string     `json:"finding_type"  db:"finding_type"` // sca|sast|secrets|iac
	FindingID   int64      `json:"finding_id"    db:"finding_id"`
	FindingRef  string     `json:"finding_ref"   db:"finding_ref"`
	AIProvider  string     `json:"ai_provider"   db:"ai_provider"`
	AIModel     string     `json:"ai_model"      db:"ai_model"`
	AIEndpoint  string     `json:"ai_endpoint"   db:"ai_endpoint"`
	Patch       string     `json:"patch"         db:"patch"` // unified diff
	PRTitle     string     `json:"pr_title"      db:"pr_title"`
	PRBody      string     `json:"pr_body"       db:"pr_body"`
	Status      string     `json:"status"        db:"status"` // pending|approved|rejected|pr_open|pr_merged
	PRNumber    int        `json:"pr_number"     db:"pr_number"`
	PRURL       string     `json:"pr_url"        db:"pr_url"`
	GeneratedAt time.Time  `json:"generated_at"  db:"generated_at"`
	ApprovedAt  *time.Time `json:"approved_at"   db:"approved_at"`
}
