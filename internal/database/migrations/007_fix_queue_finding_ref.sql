-- Persist a string finding reference (raw-* IDs and normalized IDs) so
-- remediation can resume without regenerating prompts for already-processed
-- findings after gateway restarts or cancellations.

ALTER TABLE fix_queue ADD COLUMN finding_ref TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_fix_queue_scan_job_finding_ref
    ON fix_queue(scan_job_id, finding_ref);
