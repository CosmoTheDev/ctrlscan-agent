package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

const defaultOpenAIBase = "https://api.openai.com/v1"

// OpenAIProvider implements AIProvider using the OpenAI REST API.
type OpenAIProvider struct {
	apiKey       string
	model        string
	baseURL      string
	client       *http.Client
	debug        bool
	debugPrompts bool
}

// NewOpenAI creates an OpenAIProvider from cfg.
func NewOpenAI(cfg config.AIConfig) (*OpenAIProvider, error) {
	base := cfg.BaseURL
	if base == "" {
		base = defaultOpenAIBase
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid OpenAI base URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid OpenAI base URL scheme %q", u.Scheme)
	}
	model := cfg.Model
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAIProvider{
		apiKey:       cfg.OpenAIKey,
		model:        model,
		baseURL:      strings.TrimRight(base, "/"),
		client:       &http.Client{Timeout: 120 * time.Second},
		debug:        isDebug() || getLegacyDebug("openai"),
		debugPrompts: isDebugPrompts() || getLegacyDebugPrompts("openai"),
	}, nil
}

func (o *OpenAIProvider) Name() string { return "openai" }

func (o *OpenAIProvider) IsAvailable(ctx context.Context) bool {
	// Probe the models endpoint.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/models", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+o.apiKey)
	// #nosec G107,G704 -- baseURL is loaded from trusted local config and validated in NewOpenAI.
	resp, err := o.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TriageFindings sends all findings to GPT and asks it to rank and summarise them.
func (o *OpenAIProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
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

	resp, err := o.complete(ctx, prompt, 2048)
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

// GenerateFix asks GPT to produce a unified diff patch for a single finding.
func (o *OpenAIProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
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

	resp, err := o.complete(ctx, prompt, 2048)
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
func (o *OpenAIProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
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

	resp, err := o.complete(ctx, prompt, 1024)
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

type openAIRequest struct {
	Model               string      `json:"model"`
	Messages            []openAIMsg `json:"messages"`
	MaxTokens           int         `json:"max_tokens,omitempty"`
	MaxCompletionTokens int         `json:"max_completion_tokens,omitempty"`
}

type openAIMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (o *OpenAIProvider) complete(ctx context.Context, prompt string, maxTokens int) (string, error) {
	payload := openAIRequest{
		Model: o.model,
		Messages: []openAIMsg{
			{Role: "system", Content: "You are an expert security engineer assisting with vulnerability remediation." + profileSystemAddendum(ctx)},
			{Role: "user", Content: prompt},
		},
	}
	if usesMaxCompletionTokensParam(o.model) {
		payload.MaxCompletionTokens = maxTokens
	} else {
		payload.MaxTokens = maxTokens
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	if o.debug {
		slog.Info("OpenAI request",
			"model", o.model,
			"max_tokens", maxTokens,
			"prompt_chars", len(prompt),
			"request_bytes", len(body),
		)
		if o.debugPrompts {
			slog.Info("OpenAI prompt body", "prompt", prompt)
		}
	}

	const maxAttempts = 6
	var respBody []byte
	var respStatus int
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			o.baseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
		req.Header.Set("Content-Type", "application/json")

		// #nosec G107,G704 -- baseURL is loaded from trusted local config and validated in NewOpenAI.
		resp, err := o.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("calling OpenAI API: %w", err)
		}
		respStatus = resp.StatusCode
		respBody, err = io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if err != nil {
			return "", fmt.Errorf("reading response body: %w", err)
		}
		if closeErr != nil {
			slog.Debug("closing OpenAI response body", "error", closeErr)
		}

		if resp.StatusCode == http.StatusOK {
			break
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxAttempts {
			wait := openAIRetryDelay(resp.Header.Get("Retry-After"), string(respBody), attempt)
			slog.Warn("OpenAI rate limited; retrying",
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"wait", wait.String(),
				"model", o.model,
			)
			if err := sleepWithContext(ctx, wait); err != nil {
				return "", err
			}
			continue
		}
		break
	}

	if respStatus != http.StatusOK {
		return "", fmt.Errorf("OpenAI API error %d: %s", respStatus, string(respBody))
	}

	var apiResp openAIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("parsing API response: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("OpenAI error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("OpenAI returned no choices")
	}

	return strings.TrimSpace(apiResp.Choices[0].Message.Content), nil
}

func usesMaxCompletionTokensParam(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	switch {
	case strings.Contains(m, "gpt-5"):
		return true
	case strings.Contains(m, "codex"):
		return true
	case strings.HasPrefix(m, "o1"),
		strings.HasPrefix(m, "o3"),
		strings.HasPrefix(m, "o4"):
		return true
	default:
		return false
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func openAIRetryDelay(retryAfterHeader, body string, attempt int) time.Duration {
	if ra := strings.TrimSpace(retryAfterHeader); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	bl := strings.ToLower(body)
	if idx := strings.Index(bl, "please try again in "); idx >= 0 {
		rest := bl[idx+len("please try again in "):]
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			token := strings.Trim(fields[0], ".,")
			if strings.HasSuffix(token, "ms") {
				if n, err := strconv.ParseFloat(strings.TrimSuffix(token, "ms"), 64); err == nil && n > 0 {
					return time.Duration(n * float64(time.Millisecond))
				}
			}
			if strings.HasSuffix(token, "s") {
				if n, err := strconv.ParseFloat(strings.TrimSuffix(token, "s"), 64); err == nil && n > 0 {
					return time.Duration(n * float64(time.Second))
				}
			}
		}
	}
	// Exponential-ish fallback with a cap.
	d := time.Duration(attempt*attempt) * 500 * time.Millisecond
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}
