package gateway

// Schedule is a persisted cron entry that triggers the agent orchestrator.
type Schedule struct {
	ID          int64  `db:"id"          json:"id"`
	Name        string `db:"name"        json:"name"`
	Description string `db:"description" json:"description"`
	// Expr is a cron expression ("0 2 * * *"), "@every 6h", "@hourly", or "@daily".
	Expr string `db:"expr"    json:"expr"`
	// Targets is a JSON array that overrides agent.scan_targets for this schedule.
	// Empty array means use the configured defaults.
	Targets string `db:"targets" json:"targets"`
	// SelectedRepos is a JSON array of explicit repos for one-shot scheduled sweeps.
	// When non-empty, discovery is skipped and only these repos are scanned.
	SelectedRepos string `db:"selected_repos" json:"selected_repos"`
	// ScopeJSON is the typed schedule scope (targets/mode/owners/prefixes/repos).
	// Empty means fall back to legacy targets/selected_repos/mode fields.
	ScopeJSON string `db:"scope_json" json:"scope_json"`
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
	Running        bool   `json:"running"`
	Paused         bool   `json:"paused"`
	Workers        int    `json:"workers"`
	QueuedRepos    int    `json:"queued_repos"`
	ActiveJobs     int    `json:"active_jobs"`
	PendingFixes   int    `json:"pending_fixes"`
	LastTriggerAt  string `json:"last_trigger_at,omitempty"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	AIProvider     string `json:"ai_provider"`
	AIFallbackMode bool   `json:"ai_fallback_mode"`
}

// HeartbeatStatus describes the liveness of the local orchestrator agent.
// Status values: "idle" | "alive" | "stuck" | "dead"
//   - idle:  no sweep is running — normal while waiting for a cron trigger or manual scan
//   - alive: a sweep is running and the orchestrator emitted activity within the stuck threshold
//   - stuck: a sweep has been running but no orchestrator event has been received for > stuckThreshold
//   - dead:  the gateway has been up past deadThreshold and the orchestrator has never emitted an event
type HeartbeatStatus struct {
	Status         string `json:"status"`
	LastActivityAt string `json:"last_activity_at,omitempty"` // RFC3339; empty if no events yet
	SweepRunning   bool   `json:"sweep_running"`
	StuckForSecs   int64  `json:"stuck_for_seconds,omitempty"`
	Message        string `json:"message,omitempty"`
}

// countRow is a convenience struct for SELECT COUNT(*) AS n queries.
type countRow struct {
	N int `db:"n"`
}
