package notify

import "context"

// Event represents a notification event from ctrlscan-agent.
type Event struct {
	Type     string         // "critical_finding" | "pr_opened" | "sweep_failed" | "fix_approved" | "sweep_completed"
	Title    string
	Body     string
	URL      string         // optional deep link (e.g. PR URL, gateway UI link)
	Severity string         // "critical" | "high" | "medium" | "low" | ""
	RepoKey  string         // "github.com/owner/repo"
	Metadata map[string]any // extra structured data
}

// Channel is implemented by each notification provider.
type Channel interface {
	Name() string
	IsConfigured() bool
	Send(ctx context.Context, evt Event) error
}
