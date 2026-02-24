-- Add typed scope_json for provider-aware schedule filters (owners, prefixes, repos).
ALTER TABLE gateway_schedules
    ADD COLUMN scope_json TEXT NOT NULL DEFAULT '';
