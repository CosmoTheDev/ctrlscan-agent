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

// TelegramChannel sends notifications via the Telegram Bot API.
type TelegramChannel struct {
	cfg    config.TelegramNotifyConfig
	client *http.Client
}

// NewTelegram creates a TelegramChannel from cfg.
func NewTelegram(cfg config.TelegramNotifyConfig) *TelegramChannel {
	return &TelegramChannel{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}}
}

func (t *TelegramChannel) Name() string        { return "telegram" }
func (t *TelegramChannel) IsConfigured() bool { return t.cfg.BotToken != "" && t.cfg.ChatID != "" }

func (t *TelegramChannel) Send(ctx context.Context, evt Event) error {
	text := evt.Title + "\n\n" + evt.Body
	if evt.URL != "" {
		text += "\n" + evt.URL
	}
	// Telegram max message length is 4096 chars.
	if len(text) > 4096 {
		text = text[:4093] + "..."
	}
	payload := map[string]any{
		"chat_id":    t.cfg.ChatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.cfg.BotToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req) // #nosec G107 -- URL is constructed from the Telegram API base + user-configured bot token
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API returned %d", resp.StatusCode)
	}
	return nil
}
