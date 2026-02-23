package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// opengrepStringList tolerates schema drift where fields may be a string,
// array of strings, null, or omitted.
type opengrepStringList []string

func (l *opengrepStringList) UnmarshalJSON(data []byte) error {
	if l == nil {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*l = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one == "" {
			*l = nil
		} else {
			*l = []string{one}
		}
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*l = nil
		return nil
	}
	return fmt.Errorf("unsupported string-list JSON shape: %s", string(data))
}

// OpengrepScanner implements Scanner using opengrep for SAST.
type OpengrepScanner struct {
	binDir string
}

func NewOpengrepScanner(binDir string) *OpengrepScanner {
	return &OpengrepScanner{binDir: binDir}
}

func (o *OpengrepScanner) Name() string             { return "opengrep" }
func (o *OpengrepScanner) ScannerType() ScannerType { return ScannerTypeSAST }
func (o *OpengrepScanner) DockerImage() string      { return "opengrep/opengrep:latest" }

func (o *OpengrepScanner) IsAvailableLocal(ctx context.Context) bool {
	return isBinaryAvailable(ctx, "opengrep", o.binDir)
}

func (o *OpengrepScanner) IsAvailableDocker(ctx context.Context) bool {
	return isDockerAvailable(ctx)
}

// opengrepOutput mirrors the opengrep JSON output schema.
type opengrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line   int `json:"line"`
			Col    int `json:"col"`
			Offset int `json:"offset"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				Category   string             `json:"category"`
				Confidence string             `json:"confidence"`
				CWE        opengrepStringList `json:"cwe"`
				OWASP      opengrepStringList `json:"owasp"`
			} `json:"metadata"`
			Fingerprint string `json:"fingerprint"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (o *OpengrepScanner) Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	opengrep := resolveBinary("opengrep", o.binDir)

	var cmd *exec.Cmd
	if opts.UseDocker {
		cmd = dockerRun(ctx, o.DockerImage(), opts.RepoPath,
			[]string{"scan", "--json", "/scan"})
	} else {
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		cmd = exec.CommandContext(ctx, opengrep,
			"scan",
			"--json",
			opts.RepoPath,
		)
	}

	out, err := cmd.Output()
	if err != nil {
		// opengrep exits 1 when it finds issues — that's normal.
		if !isExitCode(err, 1) {
			var exitErr *exec.ExitError
			if isExitError(err, &exitErr) {
				stderr := compactScannerOutput(string(exitErr.Stderr), 1200)
				stdout := compactScannerOutput(string(out), 600)
				slog.Warn("opengrep process failed",
					"stderr", stderr,
					"stdout", stdout,
				)
				detail := stderr
				if detail == "" {
					detail = stdout
				}
				if detail != "" {
					return nil, fmt.Errorf("executing opengrep: %w (detail: %s)", err, detail)
				}
			}
			return nil, fmt.Errorf("executing opengrep: %w", err)
		}
		// findings present; out still contains the JSON
		if len(out) == 0 {
			return &ScanResult{
				Scanner: "opengrep",
				Type:    ScannerTypeSAST,
				Status:  "completed",
			}, nil
		}
	}

	result := &ScanResult{
		Scanner: "opengrep",
		Type:    ScannerTypeSAST,
		Status:  "completed",
		Raw:     out,
	}

	o.parseFindings(out, result)
	return result, nil
}

func compactScannerOutput(s string, max int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	s = strings.Join(lines, " | ")
	s = strings.Join(strings.Fields(s), " ")
	if max > 0 && len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func (o *OpengrepScanner) parseFindings(data []byte, result *ScanResult) {
	var output opengrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		slog.Warn("Failed to parse opengrep output", "error", err)
		return
	}

	result.FindingsCount = len(output.Results)
	for _, r := range output.Results {
		sev := models.MapSeverity(r.Extra.Severity)
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
