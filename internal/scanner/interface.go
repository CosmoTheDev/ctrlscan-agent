package scanner

import (
	"context"
)

// ScannerType identifies the category of scanner.
type ScannerType string

const (
	ScannerTypeSCA     ScannerType = "sca"     // software composition analysis (grype/syft)
	ScannerTypeSAST    ScannerType = "sast"    // static application security testing (opengrep)
	ScannerTypeSecrets ScannerType = "secrets" // secret detection (trufflehog)
	ScannerTypeIaC     ScannerType = "iac"     // infrastructure as code (trivy)
)

// ScanOptions contains the parameters passed to each scanner.
type ScanOptions struct {
	// RepoPath is the filesystem path to the cloned repository.
	RepoPath string
	// BinDir is where ctrlscan stores scanner binaries.
	BinDir string
	// UseDocker forces execution via docker even if local binary is present.
	UseDocker bool
}

// ScanResult holds the parsed output from a single scanner run.
type ScanResult struct {
	// Scanner name (e.g. "grype", "opengrep").
	Scanner string
	// Type of scanner.
	Type ScannerType
	// Status: "completed", "failed", "skipped".
	Status string
	// DurationSec is how long the scan took.
	DurationSec float64
	// FindingsCount is the total number of findings.
	FindingsCount int
	// Severity breakdown.
	Critical, High, Medium, Low int
	// Raw is the unparsed scanner JSON output for debugging.
	Raw []byte
	// Error holds the error message if Status == "failed".
	Error string
}

// Scanner is the interface every scanning tool must implement.
// To add a new scanner:
//  1. Create a new file in internal/scanner/ (e.g. mynewtool.go)
//  2. Implement the Scanner interface
//  3. Register it in BuildScanners()
type Scanner interface {
	// Name returns the human-readable tool name (e.g. "grype").
	Name() string

	// ScannerType returns the category this scanner belongs to.
	ScannerType() ScannerType

	// IsAvailableLocal checks if the local binary is available and executable.
	IsAvailableLocal(ctx context.Context) bool

	// IsAvailableDocker checks if the Docker daemon is reachable and the image exists.
	IsAvailableDocker(ctx context.Context) bool

	// DockerImage returns the Docker image used as a fallback.
	DockerImage() string

	// Scan runs the scanner against opts.RepoPath and returns structured results.
	// Implementations should persist findings to the DB via the provided job ID.
	Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error)
}

// RunOptions parameterises a full scan run (across multiple scanners).
type RunOptions struct {
	RepoPath string
	JobKey   string
	Provider string
	Owner    string
	Repo     string
	Branch   string
	Commit   string
	Parallel bool
}

// RunResults aggregates the results from all scanners.
type RunResults struct {
	// Status: "completed", "partial", "failed".
	Status         string
	ScannerResults map[string]*ScanResult
	JobID          int64
}
