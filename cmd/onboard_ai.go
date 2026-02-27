package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
)

func isLikelyLMStudioURL(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	return strings.Contains(s, "127.0.0.1:1234") || strings.Contains(s, "localhost:1234")
}

func reportAIProbe(parent context.Context, aiCfg config.AIConfig, label string) {
	if strings.TrimSpace(aiCfg.Provider) == "" || aiCfg.Provider == "none" {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	provider, err := ai.New(aiCfg)
	if err != nil {
		fmt.Println(warnStyle.Render(fmt.Sprintf("  %s endpoint check skipped: %v", label, err)))
		return
	}
	if provider.IsAvailable(ctx) {
		fmt.Println(successStyle.Render(fmt.Sprintf("  %s endpoint reachable — AI enabled.", label)))
		return
	}
	fmt.Println(warnStyle.Render(fmt.Sprintf("  %s endpoint not reachable right now.", label)))
	fmt.Println(dimStyle.Render("  You can continue setup and start the local server/model later, then run 'ctrlscan doctor'."))
}

type ollamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

func fetchOllamaModelNames(parent context.Context, baseURL string) ([]string, error) {
	baseURL, err := normalizeLocalOllamaBaseURL(baseURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	// #nosec G704 -- baseURL is restricted to localhost/loopback in normalizeLocalOllamaBaseURL.
	resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, fmt.Errorf("GET /api/tags returned %d (%s)", resp.StatusCode, msg)
	}

	var payload ollamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("parsing /api/tags response: %w", err)
	}

	seen := make(map[string]struct{}, len(payload.Models))
	names := make([]string, 0, len(payload.Models))
	for _, m := range payload.Models {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
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

	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return strings.TrimRight(u.String(), "/"), nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return strings.TrimRight(u.String(), "/"), nil
	}

	return "", fmt.Errorf("Ollama URL must point to localhost or a loopback address")
}
