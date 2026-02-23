-- Gateway scheduler: persisted cron schedules for the agent orchestrator.

CREATE TABLE IF NOT EXISTS gateway_schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    -- expr is a cron expression ("0 2 * * *"), "@every 6h", "@hourly", "@daily", or "@startup".
    expr        TEXT    NOT NULL,
    -- targets is a JSON array that overrides agent.scan_targets for this schedule.
    -- Leave empty ("[]") to use the configured defaults.
    targets     TEXT    NOT NULL DEFAULT '[]',
    -- mode overrides agent.mode when non-empty ("triage", "semi", "auto").
    mode        TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gateway_schedules_enabled ON gateway_schedules(enabled);
