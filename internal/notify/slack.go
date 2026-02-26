package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
)

// SlackChannel sends notifications to a Slack incoming webhook URL.
type SlackChannel struct {
	cfg    config.SlackNotifyConfig
	client *http.Client
}

// NewSlack creates a SlackChannel from cfg.
func NewSlack(cfg config.SlackNotifyConfig) *SlackChannel {
	return &SlackChannel{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}
}

func (s *SlackChannel) Name() string        { return "slack" }
func (s *SlackChannel) IsConfigured() bool { return s.cfg.WebhookURL != "" }

func (s *SlackChannel) Send(ctx context.Context, evt Event) error {
	color := severityColor(evt.Severity)
	attachment := map[string]any{
		"color":  color,
		"title":  evt.Title,
		"text":   evt.Body,
		"footer": "ctrlscan-agent",
		"ts":     time.Now().Unix(),
	}
	if evt.URL != "" {
		attachment["title_link"] = evt.URL
	}
	payload := map[string]any{
		"text":        evt.Title,
		"attachments": []map[string]any{attachment},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req) // #nosec G107 -- WebhookURL is a user-configured Slack incoming webhook URL
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

func severityColor(sev string) string {
	switch sev {
	case "critical":
		return "#FF0000"
	case "high":
		return "#FF6600"
	case "medium":
		return "#FFAA00"
	case "low":
		return "#0099FF"
	default:
		return "#888888"
	}
}
