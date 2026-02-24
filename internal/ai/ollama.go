package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// OllamaProvider implements AIProvider using a local Ollama server.
// Configure with: ai.provider = "ollama", ai.ollama_url = "http://localhost:11434"
type OllamaProvider struct {
	baseURL      string
	model        string
	client       *http.Client
	maxAttempts  int
	retryBackoff time.Duration
	debug        bool
	debugPrompts bool
}

// NewOllama creates an OllamaProvider from cfg.
func NewOllama(cfg config.AIConfig) (*OllamaProvider, error) {
	base := cfg.OllamaURL
	if base == "" {
		base = "http://localhost:11434"
	}
	base, err := normalizeLocalOllamaBaseURL(base)
	if err != nil {
		return nil, err
	}
	model := cfg.Model
	if model == "" {
		model = "llama3.2"
	}
	timeout := 180 * time.Second
	maxAttempts := 1
	retryBackoff := 2 * time.Second
	if cfg.OptimizeForLocal {
		// Fail faster and retry once for local models that frequently time out or
		// hit transient Ollama 5xx errors under load.
		timeout = 90 * time.Second
		maxAttempts = 2
		retryBackoff = 1500 * time.Millisecond
	}
	return &OllamaProvider{
		baseURL:      base,
		model:        model,
		client:       &http.Client{Timeout: timeout},
		maxAttempts:  maxAttempts,
		retryBackoff: retryBackoff,
		debug:        envBool("CTRLSCAN_OLLAMA_DEBUG"),
		debugPrompts: envBool("CTRLSCAN_OLLAMA_DEBUG_PROMPTS"),
	}, nil
}

func (o *OllamaProvider) Name() string { return "ollama" }

func (o *OllamaProvider) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	// #nosec G704 -- o.baseURL is restricted to localhost/loopback and validated in normalizeLocalOllamaBaseURL.
	resp, err := o.client.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("closing Ollama tags response body failed", "error", closeErr)
		}
	}()
	return resp.StatusCode == http.StatusOK
}

func (o *OllamaProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
	if len(findings) == 0 {
		return &TriageResult{Summary: "No findings to triage."}, nil
	}
	findingsJSON, _ := json.MarshalIndent(findings, "", "  ")
	prompt := fmt.Sprintf(`Analyse these security findings and return JSON with "summary" and "prioritised" array.
Findings: %s
Return only valid JSON.`, string(findingsJSON))

	resp, err := o.complete(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result TriageResult
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		result.Summary = resp
	}

	// Attach original finding data to each prioritised item (mirrors OpenAI provider).
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

func (o *OllamaProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
	// Build the file-content section.
	var fileSectionBuf strings.Builder
	if req.FileContent != "" {
		fmt.Fprintf(&fileSectionBuf,
			"FULL FILE (%s, %d lines):\n%s\n",
			req.FilePath, req.TotalLines, req.FileContent)
	} else if req.CodeContext != "" {
		fmt.Fprintf(&fileSectionBuf,
			"FILE EXCERPT (%s, finding line marked >>):\n%s\n",
			req.FilePath, req.CodeContext)
	}

	findingJSON, _ := json.MarshalIndent(req.Finding, "", "  ")

	// The patch hunk header example uses placeholder numbers so the model
	// understands the required format concretely.
	prompt := fmt.Sprintf(`You are a security engineer. Fix the vulnerability below by producing a unified diff.

FINDING:
%s

%s
PATCH RULES — follow exactly or git apply will fail:
- Header: "--- a/<path>" then "+++ b/<path>"
- Hunk header MUST have real line numbers: "@@ -OLD_START,OLD_COUNT +NEW_START,NEW_COUNT @@"
  CORRECT:   @@ -10,3 +10,4 @@
  WRONG:     @@
  WRONG:     @@ @@
- Context lines: leading space. Added: leading +. Removed: leading -.
- Do NOT wrap the patch in markdown code fences.

Return ONLY valid JSON (no extra text, no markdown):
{"patch":"<unified diff>","explanation":"<why>","confidence":<0.0-1.0>,"apply_hints":{"target_files":["%s"],"apply_strategy":"git_apply","post_apply_checks":[],"risk_notes":""}}`,
		string(findingJSON), fileSectionBuf.String(), req.FilePath)

	resp, err := o.complete(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var result FixResult
	result.Finding = req.Finding
	result.FilePath = req.FilePath
	result.Language = req.Language
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		result.Explanation = resp
	}
	return &result, nil
}

func (o *OllamaProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
	var sb strings.Builder
	for _, f := range fixes {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", f.Finding.Type, f.Finding.Title))
	}
	prompt := fmt.Sprintf(`Write a PR description as JSON with "title" and "body" for these fixes:
%s
Return only valid JSON.`, sb.String())

	resp, err := o.complete(ctx, prompt)
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

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func (o *OllamaProvider) complete(ctx context.Context, prompt string) (string, error) {
	payload := ollamaRequest{
		Model:  o.model,
		Prompt: prompt,
		Stream: false,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshalling ollama request: %w", err)
	}
	if o.debug {
		slog.Info("Ollama request",
			"model", o.model,
			"prompt_chars", len(prompt),
			"request_bytes", len(body),
			"base_url", o.baseURL,
		)
		if o.debugPrompts {
			slog.Info("Ollama prompt body", "prompt", prompt)
		}
	}

	attempts := o.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			o.baseURL+"/api/generate", bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")

		// #nosec G704 -- o.baseURL is restricted to localhost/loopback and validated in normalizeLocalOllamaBaseURL.
		resp, err := o.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("calling Ollama API: %w", err)
		} else {
			data, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil {
				if closeErr != nil {
					lastErr = fmt.Errorf("reading Ollama response: %w (close body: %v)", readErr, closeErr)
				} else {
					lastErr = fmt.Errorf("reading Ollama response: %w", readErr)
				}
			} else if closeErr != nil {
				lastErr = fmt.Errorf("closing Ollama response body: %w", closeErr)
			} else if resp.StatusCode != http.StatusOK {
				msg := strings.TrimSpace(string(data))
				if msg == "" {
					msg = http.StatusText(resp.StatusCode)
				}
				lastErr = fmt.Errorf("ollama /api/generate returned %d: %s", resp.StatusCode, truncateForError(msg, 300))
				if !shouldRetryOllamaStatus(resp.StatusCode) {
					return "", lastErr
				}
			} else {
				var apiResp ollamaResponse
				if err := json.Unmarshal(data, &apiResp); err != nil {
					return "", fmt.Errorf("parsing Ollama response: %w", err)
				}
				return strings.TrimSpace(apiResp.Response), nil
			}
		}

		if attempt >= attempts || ctx.Err() != nil {
			break
		}
		slog.Warn("Ollama generate failed; retrying",
			"attempt", attempt,
			"max_attempts", attempts,
			"error", lastErr,
		)
		if o.retryBackoff > 0 {
			select {
			case <-time.After(o.retryBackoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ollama /api/generate failed")
	}
	return "", lastErr
}

func shouldRetryOllamaStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func truncateForError(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func normalizeLocalOllamaBaseURL(raw string) (string, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(raw), "/")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid Ollama URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid Ollama URL scheme %q (expected http or https)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("invalid Ollama URL: missing host")
	}
	if u.User != nil {
		return "", fmt.Errorf("invalid Ollama URL: credentials are not supported")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid Ollama URL: query and fragment are not supported")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("invalid Ollama URL: base path is not supported")
	}

	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return strings.TrimRight(u.String(), "/"), nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return strings.TrimRight(u.String(), "/"), nil
	}

	return "", fmt.Errorf("Ollama URL must point to localhost or a loopback address")
}

func envBool(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
