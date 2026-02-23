-- Persist AI provider/model/endpoint metadata on remediation task outcomes and
-- queued fixes so the UI can show which model generated what.

ALTER TABLE remediation_tasks ADD COLUMN ai_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_model TEXT NOT NULL DEFAULT '';
ALTER TABLE remediation_tasks ADD COLUMN ai_endpoint TEXT NOT NULL DEFAULT '';

ALTER TABLE fix_queue ADD COLUMN ai_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE fix_queue ADD COLUMN ai_model TEXT NOT NULL DEFAULT '';
ALTER TABLE fix_queue ADD COLUMN ai_endpoint TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_fix_queue_ai_provider_model
    ON fix_queue(ai_provider, ai_model);
