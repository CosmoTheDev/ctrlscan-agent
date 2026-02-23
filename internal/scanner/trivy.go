package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// TrivyScanner implements Scanner using trivy for IaC/misconfiguration scanning.
type TrivyScanner struct {
	binDir string
}

func NewTrivyScanner(binDir string) *TrivyScanner {
	return &TrivyScanner{binDir: binDir}
}

func (t *TrivyScanner) Name() string             { return "trivy" }
func (t *TrivyScanner) ScannerType() ScannerType { return ScannerTypeIaC }
func (t *TrivyScanner) DockerImage() string      { return "aquasec/trivy:latest" }

func (t *TrivyScanner) IsAvailableLocal(ctx context.Context) bool {
	return isBinaryAvailable(ctx, "trivy", t.binDir)
}

func (t *TrivyScanner) IsAvailableDocker(ctx context.Context) bool {
	return isDockerAvailable(ctx)
}

// trivyOutput mirrors the relevant parts of trivy's JSON output.
type trivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Misconfigurations []struct {
			ID          string `json:"ID"`
			Title       string `json:"Title"`
			Description string `json:"Description"`
			Severity    string `json:"Severity"`
			Resolution  string `json:"Resolution"`
			IacMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"IacMetadata"`
			Status string `json:"Status"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func (t *TrivyScanner) Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	trivy := resolveBinary("trivy", t.binDir)

	var cmd *exec.Cmd
	if opts.UseDocker {
		cmd = dockerRun(ctx, t.DockerImage(), opts.RepoPath,
			[]string{"fs", "/scan", "--format", "json", "--scanners", "misconfig"})
	} else {
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		cmd = exec.CommandContext(ctx, trivy,
			"fs", opts.RepoPath,
			"--format", "json",
			"--scanners", "misconfig",
			"--exit-code", "0", // always exit 0 so we can parse JSON
		)
	}

	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		var exitErr *exec.ExitError
		if isExitError(err, &exitErr) {
			slog.Debug("trivy stderr", "output", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("executing trivy: %w", err)
	}

	result := &ScanResult{
		Scanner: "trivy",
		Type:    ScannerTypeIaC,
		Status:  "completed",
		Raw:     out,
	}

	if err := t.parseFindings(out, result); err != nil {
		slog.Warn("Failed to parse trivy findings", "error", err)
	}

	return result, nil
}

func (t *TrivyScanner) parseFindings(data []byte, result *ScanResult) error {
	var output trivyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return fmt.Errorf("parsing trivy JSON: %w", err)
	}

	for _, res := range output.Results {
		for _, m := range res.Misconfigurations {
			result.FindingsCount++
			sev := models.MapSeverity(m.Severity)
			switch sev {
			case models.SeverityCritical:
				result.Critical++
			case models.SeverityHigh:
				result.High++
			case models.SeverityMedium:
				result.Medium++
			default:
				result.Low++
			}
		}
	}
	return nil
}
