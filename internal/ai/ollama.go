package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// OllamaProvider implements AIProvider using a local Ollama server.
// Configure with: ai.provider = "ollama", ai.ollama_url = "http://localhost:11434"
type OllamaProvider struct {
	baseURL string
	model   string
	client  *http.Client
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
	return &OllamaProvider{
		baseURL: strings.TrimRight(base, "/"),
		model:   model,
		client:  &http.Client{Timeout: 180 * time.Second},
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling Ollama API: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading Ollama response: %w", err)
	}

	var apiResp ollamaResponse
	if err := json.Unmarshal(data, &apiResp); err != nil {
		return "", fmt.Errorf("parsing Ollama response: %w", err)
	}

	return strings.TrimSpace(apiResp.Response), nil
}
