-- Persist live remediation AI progress pointers so the UI can show bounded
-- progress and operators can inspect where a task stopped after restarts.

ALTER TABLE remediation_tasks ADD COLUMN ai_progress_phase TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_progress_current INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_progress_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_progress_percent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE remediation_tasks ADD COLUMN ai_progress_note TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_progress_updated_at TEXT;
