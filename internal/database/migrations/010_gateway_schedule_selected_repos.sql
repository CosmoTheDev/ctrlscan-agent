-- Add explicit selected repos JSON to gateway schedules for scoped cron runs.
ALTER TABLE gateway_schedules
    ADD COLUMN selected_repos TEXT NOT NULL DEFAULT '[]';
