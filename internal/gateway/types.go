package gateway

// Schedule is a persisted cron entry that triggers the agent orchestrator.
type Schedule struct {
	ID          int64   `db:"id"          json:"id"`
	Name        string  `db:"name"        json:"name"`
	Description string  `db:"description" json:"description"`
	// Expr is a cron expression ("0 2 * * *"), "@every 6h", "@hourly", or "@daily".
	Expr    string `db:"expr"    json:"expr"`
	// Targets is a JSON array that overrides agent.scan_targets for this schedule.
	// Empty array means use the configured defaults.
	Targets string `db:"targets" json:"targets"`
	// Mode overrides agent.mode when non-empty ("triage", "semi", "auto").
	Mode      string  `db:"mode"        json:"mode"`
	Enabled   bool    `db:"enabled"     json:"enabled"`
	LastRunAt *string `db:"last_run_at" json:"last_run_at,omitempty"`
	CreatedAt string  `db:"created_at"  json:"created_at"`
	UpdatedAt string  `db:"updated_at"  json:"updated_at"`
}

// SSEEvent is serialised as JSON and pushed over the GET /events SSE stream.
type SSEEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload,omitempty"`
}

// AgentStatus is a live snapshot of the gateway and orchestrator state.
type AgentStatus struct {
	Running       bool   `json:"running"`
	Paused        bool   `json:"paused"`
	Workers       int    `json:"workers"`
	QueuedRepos   int    `json:"queued_repos"`
	ActiveJobs    int    `json:"active_jobs"`
	PendingFixes  int    `json:"pending_fixes"`
	LastTriggerAt string `json:"last_trigger_at,omitempty"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// countRow is a convenience struct for SELECT COUNT(*) AS n queries.
type countRow struct {
	N int `db:"n"`
}
