package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
		baseURL:      strings.TrimRight(base, "/"),
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
	resp, err := o.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
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
	reqJSON, _ := json.MarshalIndent(req, "", "  ")
	prompt := fmt.Sprintf(`Generate a minimal security fix as JSON with "patch", "explanation", "confidence".
Context: %s
Return only valid JSON.`, string(reqJSON))

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

		resp, err := o.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("calling Ollama API: %w", err)
		} else {
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastErr = fmt.Errorf("reading Ollama response: %w", readErr)
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

func envBool(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
