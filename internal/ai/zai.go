package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

const (
	zaiCodingEndpoint  = "https://api.z.ai/api/coding/paas/v4"
	zaiGeneralEndpoint = "https://api.z.ai/api/paas/v4"
	zaiDefaultModel    = "glm-5"
)

// ZAIProvider implements AIProvider using Z.AI's OpenAI-compatible API.
type ZAIProvider struct {
	apiKey       string
	model        string
	baseURL      string
	client       *http.Client
	debug        bool
	debugPrompts bool
}

// NewZAI creates a ZAIProvider from cfg.
func NewZAI(cfg config.AIConfig) (*ZAIProvider, error) {
	model := cfg.Model
	if model == "" {
		model = zaiDefaultModel
	}

	// Use coding endpoint by default for better code generation
	base := cfg.BaseURL
	if base == "" {
		base = zaiCodingEndpoint
	}

	return &ZAIProvider{
		apiKey:       cfg.ZAIKey,
		model:        model,
		baseURL:      strings.TrimRight(base, "/"),
		client:       &http.Client{Timeout: 120 * time.Second},
		debug:        isDebug() || getLegacyDebug("zai"),
		debugPrompts: isDebugPrompts() || getLegacyDebugPrompts("zai"),
	}, nil
}

func (z *ZAIProvider) Name() string { return "zai" }

func (z *ZAIProvider) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, z.baseURL+"/models", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+z.apiKey)
	resp, err := z.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type zaiRequest struct {
	Model       string   `json:"model"`
	Messages    []zaiMsg `json:"messages"`
	MaxTokens   int      `json:"max_tokens,omitempty"`
	Temperature float64  `json:"temperature,omitempty"`
}

type zaiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type zaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// TriageFindings sends all findings to Z.AI and asks it to rank and summarise them.
func (z *ZAIProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
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

	resp, err := z.complete(ctx, prompt, 2048, 0.7)
	if err != nil {
		return nil, err
	}

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

// GenerateFix asks Z.AI to produce a unified diff patch for a single finding.
func (z *ZAIProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
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

	resp, err := z.complete(ctx, prompt, 2048, 0.3)
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
func (z *ZAIProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
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

	resp, err := z.complete(ctx, prompt, 1024, 0.7)
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

func (z *ZAIProvider) complete(ctx context.Context, prompt string, maxTokens int, temperature float64) (string, error) {
	payload := zaiRequest{
		Model: z.model,
		Messages: []zaiMsg{
			{Role: "system", Content: "You are an expert security engineer assisting with vulnerability remediation."},
			{Role: "user", Content: prompt},
		},
		MaxTokens:   maxTokens,
		Temperature: temperature,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	if z.debug {
		slog.Info("Z.AI request",
			"model", z.model,
			"max_tokens", maxTokens,
			"temperature", temperature,
			"prompt_chars", len(prompt),
			"request_bytes", len(body),
		)
		if z.debugPrompts {
			slog.Info("Z.AI prompt body", "prompt", prompt)
		}
	}

	const maxAttempts = 6
	var respBody []byte
	var respStatus int
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			z.baseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+z.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := z.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("calling Z.AI API: %w", err)
		}
		respStatus = resp.StatusCode
		respBody, err = io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if err != nil {
			return "", fmt.Errorf("reading response body: %w", err)
		}
		if closeErr != nil {
			slog.Debug("closing Z.AI response body", "error", closeErr)
		}

		if resp.StatusCode == http.StatusOK {
			break
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxAttempts {
			wait := zaiRetryDelay(resp.Header.Get("Retry-After"), string(respBody), attempt)
			slog.Warn("Z.AI rate limited; retrying",
				"attempt", attempt,
				"max_attempts", maxAttempts,
				"wait", wait.String(),
				"model", z.model,
			)
			if err := sleepWithContext(ctx, wait); err != nil {
				return "", err
			}
			continue
		}
		break
	}

	if respStatus != http.StatusOK {
		return "", fmt.Errorf("Z.AI API error %d: %s", respStatus, string(respBody))
	}

	var apiResp zaiResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("parsing API response: %w", err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("Z.AI error: %s", apiResp.Error.Message)
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("Z.AI returned no choices")
	}

	return strings.TrimSpace(apiResp.Choices[0].Message.Content), nil
}

func zaiRetryDelay(retryAfterHeader, body string, attempt int) time.Duration {
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
	d := time.Duration(attempt*attempt) * 500 * time.Millisecond
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}
