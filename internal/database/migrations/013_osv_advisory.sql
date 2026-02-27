CREATE TABLE IF NOT EXISTS osv_enrichments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id     INTEGER NOT NULL,
    finding_id      INTEGER NOT NULL REFERENCES scan_job_findings(id),
    cve_id          TEXT    NOT NULL DEFAULT '',
    osv_id          TEXT    NOT NULL DEFAULT '',
    osv_aliases     TEXT    NOT NULL DEFAULT '[]',
    cvss_score      REAL    NOT NULL DEFAULT 0,
    cvss_vector     TEXT    NOT NULL DEFAULT '',
    cvss_source     TEXT    NOT NULL DEFAULT '',
    osv_references  TEXT    NOT NULL DEFAULT '[]',
    affected_ranges TEXT    NOT NULL DEFAULT '[]',
    published       TEXT    NOT NULL DEFAULT '',
    modified        TEXT    NOT NULL DEFAULT '',
    enriched_at     TEXT    NOT NULL,
    UNIQUE(finding_id)
);

CREATE INDEX IF NOT EXISTS idx_osv_enrichments_job ON osv_enrichments(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_osv_enrichments_cve ON osv_enrichments(cve_id);

CREATE TABLE IF NOT EXISTS advisory_poll_state (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT    NOT NULL UNIQUE,
    last_polled_at  TEXT    NOT NULL DEFAULT '',
    last_modified   TEXT    NOT NULL DEFAULT '',
    advisories_seen INTEGER NOT NULL DEFAULT 0,
    repos_queued    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
