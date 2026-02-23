package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// TrufflehogScanner implements Scanner using trufflehog for secret detection.
// trufflehog outputs NDJSON (one JSON object per line).
type TrufflehogScanner struct {
	binDir string
}

func NewTrufflehogScanner(binDir string) *TrufflehogScanner {
	return &TrufflehogScanner{binDir: binDir}
}

func (t *TrufflehogScanner) Name() string             { return "trufflehog" }
func (t *TrufflehogScanner) ScannerType() ScannerType { return ScannerTypeSecrets }
func (t *TrufflehogScanner) DockerImage() string      { return "trufflesecurity/trufflehog:latest" }

func (t *TrufflehogScanner) IsAvailableLocal(ctx context.Context) bool {
	return isBinaryAvailable(ctx, "trufflehog", t.binDir)
}

func (t *TrufflehogScanner) IsAvailableDocker(ctx context.Context) bool {
	return isDockerAvailable(ctx)
}

type trufflehogFinding struct {
	DetectorName string `json:"DetectorName"`
	DetectorType string `json:"DetectorType"`
	Verified     bool   `json:"Verified"`
	Raw          string `json:"Raw"`
	SourceData   struct {
		File   string `json:"file"`
		Line   int    `json:"line"`
	} `json:"SourceMetadata"`
}

func (t *TrufflehogScanner) Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	trufflehog := resolveBinary("trufflehog", t.binDir)

	var cmd *exec.Cmd
	if opts.UseDocker {
		cmd = dockerRun(ctx, t.DockerImage(), opts.RepoPath,
			[]string{"filesystem", "/scan", "--json", "--no-update"})
	} else {
		cmd = exec.CommandContext(ctx, trufflehog,
			"filesystem", opts.RepoPath,
			"--json",
			"--no-update",
		)
	}

	out, err := cmd.Output()
	// trufflehog exits non-zero when secrets are found — that's OK.
	if err != nil && len(out) == 0 {
		var exitErr *exec.ExitError
		if isExitError(err, &exitErr) {
			slog.Debug("trufflehog stderr", "output", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("executing trufflehog: %w", err)
	}

	result := &ScanResult{
		Scanner: "trufflehog",
		Type:    ScannerTypeSecrets,
		Status:  "completed",
		Raw:     out,
	}

	t.parseFindings(out, result)
	return result, nil
}

// parseFindings parses the NDJSON output from trufflehog.
func (t *TrufflehogScanner) parseFindings(data []byte, result *ScanResult) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var finding trufflehogFinding
		if err := json.Unmarshal(line, &finding); err != nil {
			continue
		}
		result.FindingsCount++
		if finding.Verified {
			// Verified secrets are always HIGH severity.
			result.High++
		} else {
			result.Medium++
		}
	}

	// Map findings to severity for the summary.
	_ = models.SeverityHigh // ensure models package is used
}
