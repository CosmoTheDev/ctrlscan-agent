package controlplane

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
)

const defaultURL = "https://ctrlscan.com"

// Client is a minimal HTTP client for the ctrlscan.com control plane API.
// It is intentionally thin — only the calls needed for registration and health
// checks are implemented here. Scan submission is added in a later phase.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New returns a Client configured from cfg.
// baseURL defaults to https://ctrlscan.com when cfg.URL is empty.
func New(cfg config.ControlPlaneConfig) *Client {
	base := strings.TrimRight(cfg.URL, "/")
	if base == "" {
		base = defaultURL
	}
	return &Client{
		baseURL: base,
		apiKey:  cfg.APIKey,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// NewWithKey returns a Client pointing at baseURL authenticated with apiKey.
// Used during the register flow before config has been saved.
func NewWithKey(baseURL, apiKey string) *Client {
	base := strings.TrimRight(baseURL, "/")
	if base == "" {
		base = defaultURL
	}
	return &Client{
		baseURL: base,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Register creates a new agent entry on the control plane.
// It should only be called once during `ctrlscan register`.
// The returned RegisterResponse contains the APIKey that must be saved to config.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/agents/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var out RegisterResponse
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if out.APIKey == "" {
		return nil, fmt.Errorf("control plane returned empty api_key — check the response format")
	}
	return &out, nil
}

// Ping validates the configured API key by calling GET /api/v1/agents/me.
// Returns the agent's info if the key is valid.
func (c *Client) Ping(ctx context.Context) (*AgentInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/agents/me", nil)
	if err != nil {
		return nil, err
	}
	var out AgentInfo
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &out, nil
}

// do executes an authenticated HTTP request and returns the response body.
// Non-2xx responses are converted to descriptive errors.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	res, err := c.http.Do(req) // #nosec G107 -- baseURL defaults to compile-time constant; user-configured value is intentional
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", c.baseURL+path, err)
	}
	defer res.Body.Close() //nolint:errcheck

	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// Try to extract a human-readable error from the response body.
		var apiErr struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if jsonErr := json.Unmarshal(b, &apiErr); jsonErr == nil {
			if apiErr.Error != "" {
				return nil, fmt.Errorf("control plane error (%d): %s", res.StatusCode, apiErr.Error)
			}
			if apiErr.Message != "" {
				return nil, fmt.Errorf("control plane error (%d): %s", res.StatusCode, apiErr.Message)
			}
		}
		return nil, fmt.Errorf("control plane returned %d", res.StatusCode)
	}

	return b, nil
}
