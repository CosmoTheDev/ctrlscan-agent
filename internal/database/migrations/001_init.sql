-- ctrlscan initial schema
-- Supports SQLite (default) and MySQL.
-- All timestamps are stored as UTC strings (RFC3339).

CREATE TABLE IF NOT EXISTS repo_queue (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    provider       TEXT    NOT NULL,
    host           TEXT    NOT NULL,
    owner          TEXT    NOT NULL,
    name           TEXT    NOT NULL,
    full_name      TEXT    NOT NULL,
    clone_url      TEXT    NOT NULL,
    default_branch TEXT    NOT NULL DEFAULT 'main',
    status         TEXT    NOT NULL DEFAULT 'pending',
    priority       INTEGER NOT NULL DEFAULT 0,
    discovered_at  TEXT    NOT NULL,
    scanned_at     TEXT,
    UNIQUE(provider, host, owner, name)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_key        TEXT    NOT NULL UNIQUE,
    provider          TEXT    NOT NULL,
    owner             TEXT    NOT NULL,
    repo              TEXT    NOT NULL,
    branch            TEXT    NOT NULL,
    commit_sha        TEXT    NOT NULL DEFAULT '',
    status            TEXT    NOT NULL DEFAULT 'pending',
    scan_mode         TEXT    NOT NULL DEFAULT 'local',
    findings_critical INTEGER NOT NULL DEFAULT 0,
    findings_high     INTEGER NOT NULL DEFAULT 0,
    findings_medium   INTEGER NOT NULL DEFAULT 0,
    findings_low      INTEGER NOT NULL DEFAULT 0,
    started_at        TEXT    NOT NULL,
    completed_at      TEXT,
    error_msg         TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scan_job_scanners (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id    INTEGER NOT NULL REFERENCES scan_jobs(id),
    scanner_name   TEXT    NOT NULL,
    scanner_type   TEXT    NOT NULL,
    status         TEXT    NOT NULL DEFAULT 'pending',
    findings_count INTEGER NOT NULL DEFAULT 0,
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    error_msg      TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sca_vulns (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_key          TEXT    NOT NULL UNIQUE,
    scan_job_id         INTEGER NOT NULL REFERENCES scan_jobs(id),
    package_name        TEXT    NOT NULL,
    version_affected    TEXT    NOT NULL,
    version_remediation TEXT    NOT NULL DEFAULT '',
    cve                 TEXT    NOT NULL DEFAULT '',
    vulnerability_id    TEXT    NOT NULL,
    data_source         TEXT    NOT NULL DEFAULT '',
    namespace           TEXT    NOT NULL DEFAULT '',
    package_type        TEXT    NOT NULL DEFAULT '',
    package_language    TEXT    NOT NULL DEFAULT '',
    severity            TEXT    NOT NULL,
    description         TEXT    NOT NULL DEFAULT '',
    paths_found         TEXT    NOT NULL DEFAULT '[]',
    vuln_urls           TEXT    NOT NULL DEFAULT '[]',
    reference_urls      TEXT    NOT NULL DEFAULT '[]',
    cvss                REAL    NOT NULL DEFAULT 0,
    cvss_vector         TEXT    NOT NULL DEFAULT '',
    cvss_source         TEXT    NOT NULL DEFAULT '',
    epss                REAL    NOT NULL DEFAULT 0,
    epss_percentile     REAL    NOT NULL DEFAULT 0,
    epss_date           TEXT    NOT NULL DEFAULT '',
    cwe                 TEXT    NOT NULL DEFAULT '',
    fix_state           TEXT    NOT NULL DEFAULT '',
    fix_versions        TEXT    NOT NULL DEFAULT '[]',
    cpes                TEXT    NOT NULL DEFAULT '[]',
    purl                TEXT    NOT NULL DEFAULT '',
    match_type          TEXT    NOT NULL DEFAULT '',
    matcher             TEXT    NOT NULL DEFAULT '',
    version_constraint  TEXT    NOT NULL DEFAULT '',
    related_vulns       TEXT    NOT NULL DEFAULT '[]',
    status              TEXT    NOT NULL DEFAULT 'open',
    pr_number           INTEGER NOT NULL DEFAULT 0,
    last_scanned        TEXT    NOT NULL,
    first_seen_at       TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sboms (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id    INTEGER NOT NULL REFERENCES scan_jobs(id),
    tool_name      TEXT    NOT NULL,
    tool_version   TEXT    NOT NULL DEFAULT '',
    artifact_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sbom_artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id       INTEGER NOT NULL REFERENCES sboms(id),
    scan_job_id   INTEGER NOT NULL REFERENCES scan_jobs(id),
    name          TEXT    NOT NULL,
    version       TEXT    NOT NULL DEFAULT '',
    artifact_type TEXT    NOT NULL DEFAULT '',
    language      TEXT    NOT NULL DEFAULT '',
    locations     TEXT    NOT NULL DEFAULT '[]',
    cpes          TEXT    NOT NULL DEFAULT '[]',
    purl          TEXT    NOT NULL DEFAULT '',
    licenses      TEXT    NOT NULL DEFAULT '[]',
    upstreams     TEXT    NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS sast_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_key   TEXT    NOT NULL UNIQUE,
    scan_job_id  INTEGER NOT NULL REFERENCES scan_jobs(id),
    scanner      TEXT    NOT NULL,
    check_id     TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    file_path    TEXT    NOT NULL,
    line_start   INTEGER NOT NULL DEFAULT 0,
    line_end     INTEGER NOT NULL DEFAULT 0,
    col_start    INTEGER NOT NULL DEFAULT 0,
    col_end      INTEGER NOT NULL DEFAULT 0,
    message      TEXT    NOT NULL DEFAULT '',
    fingerprint  TEXT    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT '',
    confidence   TEXT    NOT NULL DEFAULT '',
    cwes         TEXT    NOT NULL DEFAULT '[]',
    owasp        TEXT    NOT NULL DEFAULT '[]',
    status       TEXT    NOT NULL DEFAULT 'open',
    pr_number    INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT   NOT NULL,
    last_seen_at  TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_key      TEXT    NOT NULL UNIQUE,
    scan_job_id     INTEGER NOT NULL REFERENCES scan_jobs(id),
    detector_name   TEXT    NOT NULL,
    detector_type   TEXT    NOT NULL DEFAULT '',
    verified        INTEGER NOT NULL DEFAULT 0,
    credential_hash TEXT    NOT NULL,
    location_hash   TEXT    NOT NULL,
    file_path       TEXT    NOT NULL DEFAULT '',
    line_number     INTEGER NOT NULL DEFAULT 0,
    severity        TEXT    NOT NULL DEFAULT 'HIGH',
    raw_metadata    TEXT    NOT NULL DEFAULT '{}',
    status          TEXT    NOT NULL DEFAULT 'open',
    pr_number       INTEGER NOT NULL DEFAULT 0,
    first_seen_at   TEXT    NOT NULL,
    last_seen_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS iac_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_key   TEXT    NOT NULL UNIQUE,
    scan_job_id  INTEGER NOT NULL REFERENCES scan_jobs(id),
    scanner      TEXT    NOT NULL,
    check_id     TEXT    NOT NULL,
    title        TEXT    NOT NULL DEFAULT '',
    description  TEXT    NOT NULL DEFAULT '',
    severity     TEXT    NOT NULL,
    file_path    TEXT    NOT NULL DEFAULT '',
    line_start   INTEGER NOT NULL DEFAULT 0,
    resource     TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL DEFAULT 'open',
    pr_number    INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT   NOT NULL,
    last_seen_at  TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS fix_queue (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id   INTEGER NOT NULL REFERENCES scan_jobs(id),
    finding_type  TEXT    NOT NULL,
    finding_id    INTEGER NOT NULL,
    patch         TEXT    NOT NULL DEFAULT '',
    pr_title      TEXT    NOT NULL DEFAULT '',
    pr_body       TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'pending',
    pr_number     INTEGER NOT NULL DEFAULT 0,
    pr_url        TEXT    NOT NULL DEFAULT '',
    generated_at  TEXT    NOT NULL,
    approved_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_sca_vulns_job     ON sca_vulns(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_sast_findings_job ON sast_findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_secrets_job       ON secrets_findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_iac_job           ON iac_findings(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_fix_queue_status  ON fix_queue(status);
CREATE INDEX IF NOT EXISTS idx_repo_queue_status ON repo_queue(status);
