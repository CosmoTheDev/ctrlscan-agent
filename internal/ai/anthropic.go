package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

const (
	anthropicMessagesEndpoint = "https://api.anthropic.com/v1/messages"
	anthropicModelsEndpoint   = "https://api.anthropic.com/v1/models"
	anthropicVersionHeader    = "2023-06-01"
	anthropicDefaultModel     = "claude-sonnet-4-6"
)

// AnthropicProvider implements AIProvider using Anthropic Claude REST API.
type AnthropicProvider struct {
	cfg          config.AIConfig
	client       *http.Client
	debug        bool
	debugPrompts bool
}

// NewAnthropic creates an AnthropicProvider from cfg.
func NewAnthropic(cfg config.AIConfig) *AnthropicProvider {
	return &AnthropicProvider{
		cfg:          cfg,
		client:       &http.Client{Timeout: 90 * time.Second},
		debug:        isDebug() || getLegacyDebug("anthropic"),
		debugPrompts: isDebugPrompts() || getLegacyDebugPrompts("anthropic"),
	}
}

func (c *AnthropicProvider) Name() string { return "anthropic" }

func (c *AnthropicProvider) IsAvailable(ctx context.Context) bool {
	// #nosec G107 -- anthropicModelsEndpoint is a compile-time constant.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, anthropicModelsEndpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("x-api-key", c.cfg.AnthropicKey)
	req.Header.Set("anthropic-version", anthropicVersionHeader)

	resp, err := c.client.Do(req) // #nosec G107 -- URL is compile-time constant anthropicModelsEndpoint
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TriageFindings sends all findings to Claude and asks it to rank and summarise them.
func (c *AnthropicProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
	if len(findings) == 0 {
		return &TriageResult{Summary: "No findings to triage."}, nil
	}

	findingsJSON, _ := json.MarshalIndent(findings, "", "  ")

	systemPrompt := "You are an expert security engineer assisting with vulnerability remediation."
	userPrompt := fmt.Sprintf(`You are a security engineer. The following vulnerabilities were found in a repository.
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

	resp, err := c.complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	var result TriageResult
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		// Fallback: return raw summary if JSON parsing fails.
		result.Summary = resp
	}

	// Attach original finding data to each prioritised item.
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

// GenerateFix asks Claude to produce a unified diff patch for a single finding.
func (c *AnthropicProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
	// Build the file-content section of the prompt.
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

	systemPrompt := "You are an expert security engineer assisting with vulnerability remediation."
	userPrompt := fmt.Sprintf(`You are a security engineer generating minimal, correct code fixes.

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
   Example for a 3-line context block where you add 1 line at line 42:
     @@ -41,3 +41,4 @@
      context_line_before
     +your_added_line
      context_line_after
3. Context lines start with a single space. Added lines start with +. Removed lines start with -.
4. Never emit bare "@@ @@" or "@@ " with no numbers.

Return ONLY a JSON object — no markdown fences, no extra text:
{
  "patch": "<unified diff as described above>",
  "explanation": "<concise explanation of the change>",
  "confidence": <0.0–1.0>,
  "apply_hints": {
    "target_files": ["<repo-relative path>"],
    "apply_strategy": "git_apply",
    "post_apply_checks": ["<command to verify>"],
    "risk_notes": "<any caveats>"
  }
}

If you cannot produce a reliable patch, set confidence < 0.5 and leave "patch" empty.`,
		string(findingJSON), req.FilePath, req.Language, fileSectionBuf.String())

	resp, err := c.complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	var result FixResult
	result.Finding = req.Finding
	result.FilePath = req.FilePath
	result.Language = req.Language

	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		result.Explanation = resp
		result.Confidence = 0
	}

	return &result, nil
}

// GeneratePRDescription drafts a PR title and body from a list of fixes.
func (c *AnthropicProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
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

	systemPrompt := "You are an expert security engineer assisting with vulnerability remediation."
	userPrompt := fmt.Sprintf(`You are writing a pull request description for the following security fixes.

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

	resp, err := c.complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	var desc PRDescription
	if err := json.Unmarshal([]byte(resp), &desc); err != nil {
		desc.Title = "fix(security): automated vulnerability fixes"
		desc.Body = resp
	}
	return &desc, nil
}

// --- Internal ---

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *AnthropicProvider) complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	model := c.cfg.Model
	if model == "" {
		model = anthropicDefaultModel
	}

	payload := anthropicRequest{
		Model:     model,
		MaxTokens: 4096,
		System:    systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling Anthropic request: %w", err)
	}

	if c.debug {
		slog.Debug("Anthropic request",
			"model", model,
			"prompt_chars", len(userPrompt),
			"request_bytes", len(body),
		)
	}
	if c.debugPrompts {
		slog.Debug("Anthropic prompt", "prompt", userPrompt)
	}

	// #nosec G107 -- anthropicMessagesEndpoint is a compile-time constant.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicMessagesEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating Anthropic request: %w", err)
	}
	req.Header.Set("x-api-key", c.cfg.AnthropicKey)
	req.Header.Set("anthropic-version", anthropicVersionHeader)
	req.Header.Set("content-type", "application/json")

	resp, err := c.client.Do(req) // #nosec G107 -- URL is compile-time constant anthropicMessagesEndpoint
	if err != nil {
		return "", fmt.Errorf("calling Anthropic API: %w", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("reading Anthropic response body: %w", err)
	}
	if closeErr != nil {
		if c.debug {
			slog.Debug("closing Anthropic response body", "error", closeErr)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Anthropic API error %d: %s", resp.StatusCode, string(respBody))
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("parsing Anthropic API response: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("Anthropic error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("Anthropic returned no content")
	}

	return strings.TrimSpace(apiResp.Content[0].Text), nil
}
