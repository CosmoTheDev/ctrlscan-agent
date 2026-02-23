package scanner

import (
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

// GrypeScanner implements Scanner using the syft + grype pipeline for SCA.
// Workflow: syft generates an SBOM → grype scans the SBOM for CVEs.
type GrypeScanner struct {
	binDir string
}

func NewGrypeScanner(binDir string) *GrypeScanner {
	return &GrypeScanner{binDir: binDir}
}

func (g *GrypeScanner) Name() string             { return "grype" }
func (g *GrypeScanner) ScannerType() ScannerType { return ScannerTypeSCA }
func (g *GrypeScanner) DockerImage() string      { return "anchore/grype:latest" }

func (g *GrypeScanner) IsAvailableLocal(ctx context.Context) bool {
	return isBinaryAvailable(ctx, "grype", g.binDir) &&
		isBinaryAvailable(ctx, "syft", g.binDir)
}

func (g *GrypeScanner) IsAvailableDocker(ctx context.Context) bool {
	return isDockerAvailable(ctx)
}

func (g *GrypeScanner) Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	tmpDir, err := os.MkdirTemp("", "ctrlscan-grype-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	sbomFile := filepath.Join(tmpDir, "sbom.json")
	vulnFile := filepath.Join(tmpDir, "vulns.json")

	// Step 1: Generate SBOM with syft.
	slog.Debug("Generating SBOM with syft", "repo", opts.RepoPath)
	if err := g.runSyft(ctx, opts, sbomFile); err != nil {
		return nil, fmt.Errorf("syft: %w", err)
	}

	// Check if SBOM is empty.
	sbomData, err := os.ReadFile(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM: %w", err)
	}

	var syftResult models.SyftResult
	if err := json.Unmarshal(sbomData, &syftResult); err != nil {
		return nil, fmt.Errorf("parsing SBOM JSON: %w", err)
	}

	if len(syftResult.Artifacts) == 0 {
		slog.Info("No artifacts found in SBOM, skipping grype scan", "repo", opts.RepoPath)
		return &ScanResult{
			Scanner:       "grype",
			Type:          ScannerTypeSCA,
			Status:        "completed",
			FindingsCount: 0,
		}, nil
	}

	// Step 2: Run grype against the SBOM.
	slog.Debug("Scanning SBOM with grype", "sbom", sbomFile)
	if err := g.runGrype(ctx, opts, sbomFile, vulnFile); err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}

	// Parse findings.
	vulnData, err := os.ReadFile(vulnFile)
	if err != nil {
		return nil, fmt.Errorf("reading grype output: %w", err)
	}

	result := &ScanResult{
		Scanner: "grype",
		Type:    ScannerTypeSCA,
		Status:  "completed",
		Raw:     vulnData,
	}

	if err := g.parseFindings(vulnData, result); err != nil {
		slog.Warn("Failed to parse grype findings", "error", err)
	}

	return result, nil
}

func (g *GrypeScanner) runSyft(ctx context.Context, opts ScanOptions, sbomFile string) error {
	var cmd *exec.Cmd
	syft := resolveBinary("syft", g.binDir)

	if opts.UseDocker {
		cmd = dockerRun(ctx, "anchore/syft:latest", opts.RepoPath,
			[]string{"/scan", "-o", "json"})
	} else {
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		cmd = exec.CommandContext(ctx, syft, opts.RepoPath, "-o", "json")
	}

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if ok := isExitError(err, &exitErr); ok {
			slog.Debug("syft stderr", "output", string(exitErr.Stderr))
		}
		return fmt.Errorf("executing syft: %w", err)
	}

	return os.WriteFile(sbomFile, out, 0o644)
}

func (g *GrypeScanner) runGrype(ctx context.Context, opts ScanOptions, sbomFile, vulnFile string) error {
	var cmd *exec.Cmd
	grype := resolveBinary("grype", g.binDir)

	if opts.UseDocker {
		// Mount the SBOM file into the container.
		dockerArgs := []string{
			"run", "--rm",
			"-v", filepath.Dir(sbomFile) + ":/sbom:ro",
			"anchore/grype:latest",
			"sbom:/sbom/" + filepath.Base(sbomFile),
			"-o", "json",
		}
			// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
			cmd = exec.CommandContext(ctx, "docker", dockerArgs...)
	} else {
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		cmd = exec.CommandContext(ctx, grype, "sbom:"+sbomFile, "-o", "json")
	}

	out, err := cmd.Output()
	if err != nil {
		// grype exits non-zero when vulnerabilities are found — that's OK.
		if !isExitCode(err, 1) {
			return fmt.Errorf("executing grype: %w", err)
		}
		// Exit code 1 means findings were found; output is still valid.
		if len(out) == 0 {
			return fmt.Errorf("grype returned no output")
		}
	}

	return os.WriteFile(vulnFile, out, 0o644)
}

func (g *GrypeScanner) parseFindings(data []byte, result *ScanResult) error {
	var grypeResult models.GrypeResult
	if err := json.Unmarshal(data, &grypeResult); err != nil {
		return fmt.Errorf("parsing grype JSON: %w", err)
	}

	result.FindingsCount = len(grypeResult.Matches)
	for _, m := range grypeResult.Matches {
		sev := models.MapSeverity(m.Vulnerability.Severity)
		switch sev {
		case models.SeverityCritical:
			result.Critical++
		case models.SeverityHigh:
			result.High++
		case models.SeverityMedium:
			result.Medium++
		case models.SeverityLow, models.SeverityInfo, models.SeverityUnknown:
			result.Low++
		}
	}
	return nil
}

// isExitError checks if err is an *exec.ExitError and assigns it.
func isExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// isExitCode checks if err is an ExitError with the given code.
func isExitCode(err error, code int) bool {
	if e, ok := err.(*exec.ExitError); ok {
		return e.ExitCode() == code
	}
	return false
}

// ensureValidJSON returns "[]" if data is nil or marshals to null.
func ensureValidJSON(v interface{}) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil || strings.TrimSpace(string(b)) == "null" {
		return "[]"
	}
	return string(b)
}
