package ai

import (
	"context"
	"fmt"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// AIProvider abstracts calls to a language model.
// To add a new provider:
//  1. Create a file in internal/ai/ (e.g. mymodel.go)
//  2. Implement AIProvider
//  3. Register in New()
type AIProvider interface {
	// Name returns the provider identifier (e.g. "openai", "ollama").
	Name() string

	// IsAvailable verifies the provider is reachable and configured.
	IsAvailable(ctx context.Context) bool

	// TriageFindings ranks and summarises a list of findings.
	TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error)

	// GenerateFix produces a code patch for a single finding.
	GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error)

	// GeneratePRDescription drafts a pull request title and body.
	GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error)
}

// TriageResult is the AI's prioritised view of all findings.
type TriageResult struct {
	Summary     string           `json:"summary"`
	Prioritised []TriagedFinding `json:"prioritised"`
}

// TriagedFinding pairs a finding with the AI's risk assessment.
type TriagedFinding struct {
	FindingID    string                `json:"finding_id"`
	Priority     int                   `json:"priority"` // 1 = highest
	Rationale    string                `json:"rationale"`
	SuggestedFix string                `json:"suggested_fix"`
	Finding      models.FindingSummary `json:"finding"`
}

// FixRequest contains all the context needed to generate a fix.
type FixRequest struct {
	Finding models.FindingSummary `json:"finding"`
	// CodeContext is the finding's surrounding lines (with line numbers).
	CodeContext string `json:"code_context"`
	// FileContent is the full file content when the file is small enough to
	// include entirely, giving the model complete context. Empty when the file
	// is too large (use CodeContext instead).
	FileContent string `json:"file_content,omitempty"`
	// TotalLines is the total number of lines in the target file.
	TotalLines int `json:"total_lines,omitempty"`
	// FilePath is the path relative to the repo root.
	FilePath string `json:"file_path"`
	// Language is the programming language (e.g. "Go", "Python").
	Language string `json:"language"`
}

// ApplyHints gives the PR agent structured guidance for applying and validating
// a model-generated patch while keeping git/network actions deterministic.
type ApplyHints struct {
	TargetFiles        []string `json:"target_files,omitempty"`
	ApplyStrategy      string   `json:"apply_strategy,omitempty"` // git_apply|edit_file_directly|dependency_bump
	DependencyName     string   `json:"dependency_name,omitempty"`
	TargetVersion      string   `json:"target_version,omitempty"`
	Ecosystem          string   `json:"ecosystem,omitempty"`     // go|npm|unknown
	ManifestPath       string   `json:"manifest_path,omitempty"` // repo-relative path
	LockfilePath       string   `json:"lockfile_path,omitempty"` // repo-relative path
	Prerequisites      []string `json:"prerequisites,omitempty"`
	PostApplyChecks    []string `json:"post_apply_checks,omitempty"`
	FallbackPatchNotes string   `json:"fallback_patch_notes,omitempty"`
	RiskNotes          string   `json:"risk_notes,omitempty"`
}

// FixResult contains the AI-generated patch and explanation.
type FixResult struct {
	Finding     models.FindingSummary `json:"finding"`
	Patch       string                `json:"patch"` // unified diff
	Explanation string                `json:"explanation"`
	Confidence  float64               `json:"confidence"` // 0.0 – 1.0
	ApplyHints  *ApplyHints           `json:"apply_hints,omitempty"`
	Language    string                `json:"language"`
	FilePath    string                `json:"file_path"`
}

// PRDescription is the AI-drafted pull request title and body.
type PRDescription struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// New returns the configured AIProvider.
// If no provider or API key is set, it returns a NoopProvider — callers should
// check IsAvailable() before using any AI features.
func New(cfg config.AIConfig) (AIProvider, error) {
	switch cfg.Provider {
	case "", "none":
		return &NoopProvider{}, nil
	case "openai":
		if cfg.OpenAIKey == "" {
			return &NoopProvider{}, nil
		}
		return NewOpenAI(cfg)
	case "ollama":
		return NewOllama(cfg)
	default:
		return nil, fmt.Errorf("unsupported AI provider %q (supported: openai, ollama)", cfg.Provider)
	}
}
