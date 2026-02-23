CREATE TABLE IF NOT EXISTS scan_job_raw_outputs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id    INTEGER NOT NULL REFERENCES scan_jobs(id),
    scanner_name   TEXT    NOT NULL,
    content_type   TEXT    NOT NULL DEFAULT 'application/octet-stream',
    raw_output     BLOB    NOT NULL,
    created_at     TEXT    NOT NULL,
    UNIQUE(scan_job_id, scanner_name)
);

CREATE INDEX IF NOT EXISTS idx_scan_job_raw_outputs_job ON scan_job_raw_outputs(scan_job_id);
