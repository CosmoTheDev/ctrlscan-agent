-- Persist AI triage/fix execution outcomes for remediation tasks so the UI can
-- show what happened even when no fix_queue rows were created.

ALTER TABLE remediation_tasks ADD COLUMN ai_findings_loaded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_findings_deduped INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_triage_status TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_triage_batches INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_triage_summary TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_triage_json TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_fix_attempted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_fix_queued INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_fix_skipped_low_conf INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_fix_failed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_updated_at TEXT;
