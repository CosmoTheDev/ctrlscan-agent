//go:build darwin && apple_intelligence

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/models"
	"github.com/CosmoTheDev/go-apple-intelligence/fm"
)

const appleSystemPrompt = "You are an expert security engineer assisting with vulnerability remediation."

// AppleIntelligenceProvider implements AIProvider using Apple's on-device Foundation Models.
// Requires macOS 26+ with Apple Intelligence enabled on Apple Silicon hardware.
// The model runs entirely on-device — no data leaves the machine.
type AppleIntelligenceProvider struct{}

func NewAppleIntelligence() *AppleIntelligenceProvider {
	return &AppleIntelligenceProvider{}
}

// appendAppleFallback appends an AppleIntelligenceProvider to the chain if not already present.
// Called from New() on darwin/apple_intelligence builds to provide a zero-config local fallback.
func appendAppleFallback(chain []AIProvider) []AIProvider {
	for _, p := range chain {
		if p.Name() == "apple" {
			return chain
		}
	}
	return append(chain, NewAppleIntelligence())
}

func (a *AppleIntelligenceProvider) Name() string { return "apple" }

func (a *AppleIntelligenceProvider) IsAvailable(_ context.Context) bool {
	ok, err := fm.DefaultModel().IsAvailable()
	if !ok {
		slog.Debug("apple intelligence unavailable", "error", err)
	}
	return ok
}

func (a *AppleIntelligenceProvider) complete(ctx context.Context, prompt string) (string, error) {
	session, err := fm.NewSession(fm.SessionOptions{
		Instructions: appleSystemPrompt,
	})
	if err != nil {
		return "", fmt.Errorf("apple intelligence session: %w", err)
	}
	return session.Respond(ctx, prompt)
}

func (a *AppleIntelligenceProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
	if len(findings) == 0 {
		return &TriageResult{Summary: "No findings to triage."}, nil
	}

	findingsJSON, _ := json.MarshalIndent(findings, "", "  ")
	prompt := fmt.Sprintf(`You are a security engineer. The following vulnerabilities were found in a repository.
Analyse them and return a JSON object with:
- "summary": a brief (2-3 sentence) executive summary of the overall risk
- "prioritised": an array of objects, each with:
  - "finding_id": the ID from the input
  - "priority": integer 1 (most urgent) to N (least urgent)
  - "rationale": 1-2 sentence explanation of why this priority
  - "suggested_fix": a concise description of how to fix it

Findings:
%s

Respond ONLY with valid JSON, no markdown code blocks.`, string(findingsJSON))

	resp, err := a.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("apple triage: %w", err)
	}

	resp = stripMarkdownFences(resp)

	var result TriageResult
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		result.Summary = resp
	}

	findingMap := make(map[string]models.FindingSummary, len(findings))
	for _, f := range findings {
		findingMap[f.ID] = f
	}
	for i := range result.Prioritised {
		if f, ok := findingMap[result.Prioritised[i].FindingID]; ok {
			result.Prioritised[i].Finding = f
		}
	}

	return &result, nil
}

func (a *AppleIntelligenceProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
	var fileSectionBuf strings.Builder
	if req.FileContent != "" {
		fmt.Fprintf(&fileSectionBuf,
			"Full file content (%s, %d lines total):\n```\n%s```\n",
			req.FilePath, req.TotalLines, req.FileContent)
	} else if req.CodeContext != "" {
		fmt.Fprintf(&fileSectionBuf,
			"Relevant excerpt from %s (line %d is marked >>):\n```\n%s```\n",
			req.FilePath, req.Finding.LineNumber, req.CodeContext)
	}

	findingJSON, _ := json.MarshalIndent(req.Finding, "", "  ")
	prompt := fmt.Sprintf(`You are a security engineer generating minimal, correct code fixes.

FINDING:
%s

FILE PATH: %s
LANGUAGE: %s
%s
TASK: Produce a unified diff patch that fixes the vulnerability above.

PATCH FORMAT RULES (critical — git apply will reject malformed patches):
1. Header lines:
     --- a/<filepath>
     +++ b/<filepath>
2. Hunk header MUST include real line numbers in this exact format:
      @@ -<old_start>,<old_count> +<new_start>,<new_count> @@
3. Context lines start with a single space. Added lines start with +. Removed lines start with -.
4. Never emit bare "@@ @@" or "@@ " with no numbers.

Return ONLY a JSON object — no markdown fences, no extra text:
{
  "patch": "<unified diff as described above>",
  "explanation": "<concise explanation of the change>",
  "confidence": <0.0-1.0>,
  "apply_hints": {
    "target_files": ["<repo-relative path>"],
    "apply_strategy": "git_apply",
    "post_apply_checks": ["<command to verify>"],
    "risk_notes": "<any caveats>"
  }
}

If you cannot produce a reliable patch, set confidence < 0.5 and leave "patch" empty.`,
		string(findingJSON), req.FilePath, req.Language, fileSectionBuf.String())

	resp, err := a.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("apple fix: %w", err)
	}

	resp = stripMarkdownFences(resp)

	result := &FixResult{
		Finding:  req.Finding,
		FilePath: req.FilePath,
		Language: req.Language,
	}
	if err := json.Unmarshal([]byte(resp), result); err != nil {
		result.Explanation = resp
		result.Confidence = 0
	}
	return result, nil
}

func (a *AppleIntelligenceProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
	if len(fixes) == 0 {
		return &PRDescription{
			Title: "chore(security): fix vulnerabilities",
			Body:  "Automated security fixes generated by ctrlscan.",
		}, nil
	}

	var sb strings.Builder
	for _, f := range fixes {
		sb.WriteString(fmt.Sprintf("- %s [%s]: %s\n",
			f.Finding.Type, f.Finding.Severity, f.Finding.Title))
	}

	prompt := fmt.Sprintf(`You are writing a pull request description for the following security fixes.

Fixes applied:
%s

Write a pull request with:
- "title": a concise PR title following conventional commits (e.g. "fix(security): resolve CVE-2024-1234 in lodash")
- "body": a markdown PR body with sections:
  ## Summary
  (brief description of what was fixed)

  ## Changes
  (bulleted list of each fix)

  ## Testing
  (note that changes were generated by automated analysis)

Return ONLY valid JSON with "title" and "body" fields. No markdown code blocks.`, sb.String())

	resp, err := a.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("apple PR description: %w", err)
	}

	resp = stripMarkdownFences(resp)

	var desc PRDescription
	if err := json.Unmarshal([]byte(resp), &desc); err != nil {
		desc.Title = "fix(security): automated vulnerability fixes"
		desc.Body = resp
	}
	return &desc, nil
}

// stripMarkdownFences removes ```json ... ``` or ``` ... ``` wrapping if the model adds it
// despite being told not to, which on-device models sometimes do.
func stripMarkdownFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if nl := strings.Index(s, "\n"); nl >= 0 {
		s = s[nl+1:]
	}
	if end := strings.LastIndex(s, "```"); end >= 0 {
		s = s[:end]
	}
	return strings.TrimSpace(s)
}
