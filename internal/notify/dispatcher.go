package notify

import (
	"context"
	"log/slog"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
)

// Dispatcher fans out events to all configured channels.
type Dispatcher struct {
	channels []Channel
	minSev   string          // minimum severity to notify on (empty = all)
	events   map[string]bool // event types to send (empty map = use defaults)
}

// defaultEvents is the set of event types that trigger notifications when cfg.Events is empty.
var defaultEvents = map[string]bool{
	"critical_finding": true,
	"pr_opened":        true,
	"sweep_failed":     true,
}

// NewDispatcher creates a Dispatcher from the given config.
// Only channels with IsConfigured() == true are active.
func NewDispatcher(cfg config.NotifyConfig) *Dispatcher {
	d := &Dispatcher{
		minSev: cfg.MinSeverity,
	}
	if len(cfg.Events) > 0 {
		d.events = make(map[string]bool, len(cfg.Events))
		for _, e := range cfg.Events {
			d.events[e] = true
		}
	} else {
		d.events = defaultEvents
	}

	// Register all channels
	channels := []Channel{
		NewSlack(cfg.Slack),
		NewTelegram(cfg.Telegram),
		NewEmail(cfg.Email),
		NewWebhook(cfg.Webhook),
	}
	for _, ch := range channels {
		if ch.IsConfigured() {
			d.channels = append(d.channels, ch)
		}
	}
	return d
}

// IsAnyConfigured returns true if at least one channel is ready to send.
func (d *Dispatcher) IsAnyConfigured() bool {
	return len(d.channels) > 0
}

// Notify sends evt to all configured channels. Errors are logged but never returned.
func (d *Dispatcher) Notify(ctx context.Context, evt Event) {
	if !d.shouldSend(evt) {
		return
	}
	for _, ch := range d.channels {
		if err := ch.Send(ctx, evt); err != nil {
			slog.Warn("notify: channel send failed", "channel", ch.Name(), "event", evt.Type, "error", err)
		}
	}
}

func (d *Dispatcher) shouldSend(evt Event) bool {
	// Check event type filter
	if len(d.events) > 0 && !d.events[evt.Type] {
		return false
	}
	// Check severity filter (only applies to finding events)
	if d.minSev != "" && evt.Severity != "" {
		return severityAtLeast(evt.Severity, d.minSev)
	}
	return true
}

// severityAtLeast returns true if got >= min in severity ordering.
func severityAtLeast(got, min string) bool {
	order := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	return order[got] >= order[min]
}
