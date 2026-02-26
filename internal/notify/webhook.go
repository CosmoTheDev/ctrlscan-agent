package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
)

// WebhookChannel sends notifications to a generic HTTP endpoint with optional
// HMAC-SHA256 signing.
type WebhookChannel struct {
	cfg    config.WebhookNotifyConfig
	client *http.Client
}

// NewWebhook creates a WebhookChannel from cfg.
func NewWebhook(cfg config.WebhookNotifyConfig) *WebhookChannel {
	return &WebhookChannel{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}
}

func (w *WebhookChannel) Name() string        { return "webhook" }
func (w *WebhookChannel) IsConfigured() bool { return w.cfg.URL != "" }

func (w *WebhookChannel) Send(ctx context.Context, evt Event) error {
	payload := map[string]any{
		"type":     evt.Type,
		"title":    evt.Title,
		"body":     evt.Body,
		"severity": evt.Severity,
		"repo":     evt.RepoKey,
		"url":      evt.URL,
		"ts":       time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		mac.Write(b)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Ctrlscan-Signature", "sha256="+sig)
	}
	resp, err := w.client.Do(req) // #nosec G107 -- URL is a user-configured webhook endpoint
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
