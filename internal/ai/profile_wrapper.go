package ai

import (
	"context"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/profiles"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// profiledProvider wraps an AIProvider to inject scan profile instructions
// into all AI calls. It also applies scanner_focus filtering before triage.
type profiledProvider struct {
	inner   AIProvider
	profile *profiles.Profile
}

// WithProfile wraps inner so that every AI call carries the active profile.
// If p is nil, inner is returned unchanged.
func WithProfile(inner AIProvider, p *profiles.Profile) AIProvider {
	if p == nil {
		return inner
	}
	return &profiledProvider{inner: inner, profile: p}
}

func (pw *profiledProvider) Name() string { return pw.inner.Name() }

func (pw *profiledProvider) IsAvailable(ctx context.Context) bool {
	return pw.inner.IsAvailable(pw.withProfile(ctx))
}

func (pw *profiledProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
	// Apply scanner_focus filter — only pass finding types the profile cares about.
	if len(pw.profile.ScannerFocus) > 0 {
		filtered := make([]models.FindingSummary, 0, len(findings))
		for _, f := range findings {
			if pw.profile.AllowsFindingType(f.Type) {
				filtered = append(filtered, f)
			}
		}
		if len(filtered) == 0 {
			return &TriageResult{
				Summary: "No findings match the active scan profile's scanner_focus filter.",
			}, nil
		}
		findings = filtered
	}
	return pw.inner.TriageFindings(pw.withProfile(ctx), findings)
}

func (pw *profiledProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
	return pw.inner.GenerateFix(pw.withProfile(ctx), req)
}

func (pw *profiledProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
	return pw.inner.GeneratePRDescription(pw.withProfile(ctx), fixes)
}

// withProfile attaches the profile to ctx so providers can read it via
// profiles.FromContext.
func (pw *profiledProvider) withProfile(ctx context.Context) context.Context {
	return profiles.ToContext(ctx, pw.profile)
}

// profileSystemAddendum returns the profile body formatted as a system prompt
// addendum, or an empty string if no profile is set in ctx.
// Call this from each provider's prompt construction to inject profile context.
func profileSystemAddendum(ctx context.Context) string {
	p := profiles.FromContext(ctx)
	if p == nil || strings.TrimSpace(p.Body) == "" {
		return ""
	}
	return "\n\n## ACTIVE SCAN POLICY: " + p.Name + "\n" + p.Body
}
