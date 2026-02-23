-- Offline remediation campaigns operate on existing scan findings and can
-- generate fixes / PRs without running a fresh scan sweep.

CREATE TABLE IF NOT EXISTS remediation_campaigns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'draft', -- draft|running|paused|completed|stopped|failed
    mode            TEXT    NOT NULL DEFAULT 'triage', -- triage|semi|auto
    auto_pr         INTEGER NOT NULL DEFAULT 0,
    filters_json    TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,
    error_msg       TEXT    NOT NULL DEFAULT '',
    total_tasks     INTEGER NOT NULL DEFAULT 0,
    pending_tasks   INTEGER NOT NULL DEFAULT 0,
    running_tasks   INTEGER NOT NULL DEFAULT 0,
    completed_tasks INTEGER NOT NULL DEFAULT 0,
    failed_tasks    INTEGER NOT NULL DEFAULT 0,
    skipped_tasks   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS remediation_tasks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id   INTEGER NOT NULL REFERENCES remediation_campaigns(id),
    scan_job_id   INTEGER NOT NULL REFERENCES scan_jobs(id),
    provider      TEXT    NOT NULL,
    owner         TEXT    NOT NULL,
    repo          TEXT    NOT NULL,
    branch        TEXT    NOT NULL DEFAULT 'main',
    clone_url     TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'pending', -- pending|running|completed|failed|skipped|stopped
    worker_name   TEXT    NOT NULL DEFAULT '',
    error_msg     TEXT    NOT NULL DEFAULT '',
    created_at    TEXT    NOT NULL,
    started_at    TEXT,
    completed_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_tasks_campaign_scan_job
    ON remediation_tasks(campaign_id, scan_job_id);
CREATE INDEX IF NOT EXISTS idx_remediation_campaigns_status
    ON remediation_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_campaign
    ON remediation_tasks(campaign_id);
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_status
    ON remediation_tasks(status);
