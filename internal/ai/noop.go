package ai

import (
	"context"
	"errors"

	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// errNoAI is returned by NoopProvider for all AI operations.
var errNoAI = errors.New("AI provider not configured — run 'ctrlscan onboard' to enable OpenAI, Ollama, or LM Studio")

// NoopProvider is used when no AI provider is configured.
// IsAvailable always returns false; all other methods return errNoAI.
// This allows the rest of the codebase to check IsAvailable() and degrade
// gracefully to scan-only mode instead of crashing.
type NoopProvider struct{}

func (n *NoopProvider) Name() string                       { return "none" }
func (n *NoopProvider) IsAvailable(_ context.Context) bool { return false }

func (n *NoopProvider) TriageFindings(_ context.Context, _ []models.FindingSummary) (*TriageResult, error) {
	return nil, errNoAI
}

func (n *NoopProvider) GenerateFix(_ context.Context, _ FixRequest) (*FixResult, error) {
	return nil, errNoAI
}

func (n *NoopProvider) GeneratePRDescription(_ context.Context, _ []FixResult) (*PRDescription, error) {
	return nil, errNoAI
}
