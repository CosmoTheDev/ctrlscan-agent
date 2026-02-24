CREATE TABLE IF NOT EXISTS scan_job_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id      INTEGER NOT NULL REFERENCES scan_jobs(id),
    kind             TEXT    NOT NULL,
    scanner          TEXT    NOT NULL,
    fingerprint      TEXT    NOT NULL,
    severity         TEXT    NOT NULL DEFAULT '',
    title            TEXT    NOT NULL DEFAULT '',
    file_path        TEXT    NOT NULL DEFAULT '',
    line             INTEGER NOT NULL DEFAULT 0,
    message          TEXT    NOT NULL DEFAULT '',
    package_name     TEXT    NOT NULL DEFAULT '',
    package_version  TEXT    NOT NULL DEFAULT '',
    fix_hint         TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'open',
    first_seen_at    TEXT    NOT NULL DEFAULT '',
    last_seen_at     TEXT    NOT NULL DEFAULT '',
    introduced       INTEGER NOT NULL DEFAULT 0,
    reintroduced     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(scan_job_id, kind, fingerprint)
);

CREATE TABLE IF NOT EXISTS repo_finding_lifecycles (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    provider              TEXT    NOT NULL,
    owner                 TEXT    NOT NULL,
    repo                  TEXT    NOT NULL,
    branch                TEXT    NOT NULL,
    kind                  TEXT    NOT NULL,
    scanner               TEXT    NOT NULL DEFAULT '',
    fingerprint           TEXT    NOT NULL,
    status                TEXT    NOT NULL DEFAULT 'open', -- open|fixed
    first_seen_scan_job_id INTEGER NOT NULL DEFAULT 0,
    first_seen_commit_sha TEXT    NOT NULL DEFAULT '',
    first_seen_at         TEXT    NOT NULL DEFAULT '',
    last_seen_scan_job_id INTEGER NOT NULL DEFAULT 0,
    last_seen_commit_sha  TEXT    NOT NULL DEFAULT '',
    last_seen_at          TEXT    NOT NULL DEFAULT '',
    fixed_at_scan_job_id  INTEGER,
    fixed_at_commit_sha   TEXT,
    fixed_at              TEXT,
    reintroduced_count    INTEGER NOT NULL DEFAULT 0,
    total_seen_count      INTEGER NOT NULL DEFAULT 0,
    latest_severity       TEXT    NOT NULL DEFAULT '',
    latest_title          TEXT    NOT NULL DEFAULT '',
    latest_file_path      TEXT    NOT NULL DEFAULT '',
    latest_line           INTEGER NOT NULL DEFAULT 0,
    latest_message        TEXT    NOT NULL DEFAULT '',
    latest_package        TEXT    NOT NULL DEFAULT '',
    latest_version        TEXT    NOT NULL DEFAULT '',
    latest_fix            TEXT    NOT NULL DEFAULT '',
    UNIQUE(provider, owner, repo, branch, kind, fingerprint)
);

CREATE TABLE IF NOT EXISTS scan_job_finding_summaries (
    scan_job_id         INTEGER PRIMARY KEY REFERENCES scan_jobs(id),
    provider            TEXT    NOT NULL,
    owner               TEXT    NOT NULL,
    repo                TEXT    NOT NULL,
    branch              TEXT    NOT NULL,
    commit_sha          TEXT    NOT NULL DEFAULT '',
    present_count       INTEGER NOT NULL DEFAULT 0,
    introduced_count    INTEGER NOT NULL DEFAULT 0,
    fixed_count         INTEGER NOT NULL DEFAULT 0,
    reintroduced_count  INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_job_findings_job ON scan_job_findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_scan_job_findings_kind ON scan_job_findings(kind);
CREATE INDEX IF NOT EXISTS idx_repo_finding_lifecycle_repo_branch
    ON repo_finding_lifecycles(provider, owner, repo, branch, status);
