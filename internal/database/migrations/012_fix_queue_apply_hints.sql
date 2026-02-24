-- Persist structured AI apply guidance for PR-agent execution and review.
ALTER TABLE fix_queue ADD COLUMN apply_hints_json TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_fix_queue_apply_hints_nonempty
    ON fix_queue(id, status);
