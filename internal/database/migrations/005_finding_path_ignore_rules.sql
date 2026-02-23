-- User-defined path substring ignore rules for findings and AI remediation.
-- These are applied when reading/processing findings (including raw-output fallback)
-- so existing scans can be re-evaluated without a fresh scan.

CREATE TABLE IF NOT EXISTS finding_path_ignore_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    substring   TEXT    NOT NULL UNIQUE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    note        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_path_ignore_rules_enabled
    ON finding_path_ignore_rules(enabled);
