package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/robfig/cron/v3"
)

// Scheduler loads gateway_schedules from SQLite and registers them with
// robfig/cron. When a schedule fires it calls triggerFn (waking the
// orchestrator) and records last_run_at.
type Scheduler struct {
	db        database.DB
	cron      *cron.Cron
	triggerFn func(Schedule)
	broadcast func(SSEEvent)

	mu      sync.Mutex
	entries map[int64]cron.EntryID // schedule DB id → cron entry id
}

func newScheduler(db database.DB, triggerFn func(Schedule), broadcast func(SSEEvent)) *Scheduler {
	return &Scheduler{
		db:        db,
		cron:      cron.New(),
		triggerFn: triggerFn,
		broadcast: broadcast,
		entries:   make(map[int64]cron.EntryID),
	}
}

// Start loads all enabled schedules from the DB and starts the cron runner.
func (s *Scheduler) Start(ctx context.Context) error {
	var schedules []Schedule
	if err := s.db.Select(ctx, &schedules,
		`SELECT id, name, description, expr, targets, selected_repos, scope_json, mode, profile, enabled, last_run_at, created_at, updated_at
		 FROM gateway_schedules WHERE enabled = 1`,
	); err != nil {
		return fmt.Errorf("loading schedules: %w", err)
	}

	for _, sched := range schedules {
		if err := s.register(sched); err != nil {
			slog.Warn("scheduler: skipping schedule with invalid expression",
				"id", sched.ID, "name", sched.Name, "expr", sched.Expr, "error", err)
		}
	}

	s.cron.Start()
	slog.Info("gateway scheduler started", "schedules_loaded", len(schedules))
	return nil
}

// Stop halts the cron runner gracefully.
func (s *Scheduler) Stop() { s.cron.Stop() }

// register adds a schedule to the running cron instance.
func (s *Scheduler) register(sched Schedule) error {
	if err := s.validateScheduleScope(sched); err != nil {
		return err
	}
	entryID, err := s.cron.AddFunc(sched.Expr, func() {
		if err := s.runSchedule(context.Background(), sched, "schedule.fired"); err != nil {
			slog.Warn("scheduler: firing schedule failed",
				"id", sched.ID, "name", sched.Name, "error", err)
		}
	})
	if err != nil {
		return fmt.Errorf("invalid cron expression %q: %w", sched.Expr, err)
	}
	s.mu.Lock()
	s.entries[sched.ID] = entryID
	s.mu.Unlock()
	return nil
}

// validate checks that expr is parseable by robfig/cron without adding it
// permanently to any runner.
func validate(expr string) error {
	tmp := cron.New()
	id, err := tmp.AddFunc(expr, func() {})
	if err != nil {
		return err
	}
	tmp.Remove(id)
	return nil
}

// Add validates, persists, and registers a new schedule. Returns the new DB id.
func (s *Scheduler) Add(ctx context.Context, sched Schedule) (int64, error) {
	if err := validate(sched.Expr); err != nil {
		return 0, fmt.Errorf("invalid schedule expression %q: %w", sched.Expr, err)
	}
	if err := s.validateScheduleScope(sched); err != nil {
		return 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	sched.CreatedAt = now
	sched.UpdatedAt = now

	id, err := s.db.Insert(ctx, "gateway_schedules", sched)
	if err != nil {
		return 0, err
	}
	sched.ID = id
	if sched.Enabled {
		if err := s.register(sched); err != nil {
			slog.Warn("scheduler: persisted but could not register schedule",
				"id", id, "error", err)
		}
	}
	return id, nil
}

// Update validates, persists, and re-registers an existing schedule.
func (s *Scheduler) Update(ctx context.Context, id int64, sched Schedule) error {
	if err := validate(sched.Expr); err != nil {
		return fmt.Errorf("invalid schedule expression %q: %w", sched.Expr, err)
	}
	if err := s.validateScheduleScope(sched); err != nil {
		return err
	}

	var existing Schedule
	if err := s.db.Get(ctx, &existing,
		`SELECT id, name, description, expr, targets, selected_repos, scope_json, mode, profile, enabled, last_run_at, created_at, updated_at
		 FROM gateway_schedules WHERE id = ?`, id,
	); err != nil {
		return fmt.Errorf("loading schedule %d: %w", id, err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Exec(ctx,
		`UPDATE gateway_schedules
		    SET name = ?, description = ?, expr = ?, targets = ?, selected_repos = ?, scope_json = ?, mode = ?, profile = ?, enabled = ?, updated_at = ?
		  WHERE id = ?`,
		sched.Name, sched.Description, sched.Expr, sched.Targets, sched.SelectedRepos, sched.ScopeJSON, sched.Mode, sched.Profile, sched.Enabled, now, id,
	); err != nil {
		return err
	}

	s.mu.Lock()
	if entryID, ok := s.entries[id]; ok {
		s.cron.Remove(entryID)
		delete(s.entries, id)
	}
	s.mu.Unlock()

	sched.ID = id
	sched.CreatedAt = existing.CreatedAt
	sched.UpdatedAt = now
	sched.LastRunAt = existing.LastRunAt
	if sched.Enabled {
		if err := s.register(sched); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes a schedule from cron and the DB.
func (s *Scheduler) Delete(ctx context.Context, id int64) error {
	s.mu.Lock()
	if entryID, ok := s.entries[id]; ok {
		s.cron.Remove(entryID)
		delete(s.entries, id)
	}
	s.mu.Unlock()
	return s.db.Exec(ctx, "DELETE FROM gateway_schedules WHERE id = ?", id)
}

// List returns all schedules ordered by id.
func (s *Scheduler) List(ctx context.Context) ([]Schedule, error) {
	var out []Schedule
	err := s.db.Select(ctx, &out,
		`SELECT id, name, description, expr, targets, selected_repos, scope_json, mode, profile, enabled, last_run_at, created_at, updated_at
		 FROM gateway_schedules ORDER BY id`)
	return out, err
}

// TriggerNow fires the agent immediately regardless of schedule, recording
// last_run_at for the given schedule id.
func (s *Scheduler) TriggerNow(ctx context.Context, id int64) error {
	var sched Schedule
	if err := s.db.Get(ctx, &sched,
		`SELECT id, name, description, expr, targets, selected_repos, scope_json, mode, profile, enabled, last_run_at, created_at, updated_at
		 FROM gateway_schedules WHERE id = ?`, id,
	); err != nil {
		return fmt.Errorf("loading schedule %d: %w", id, err)
	}
	return s.runSchedule(ctx, sched, "schedule.triggered")
}

func (s *Scheduler) runSchedule(ctx context.Context, sched Schedule, eventType string) error {
	if err := s.validateScheduleScope(sched); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Exec(ctx,
		"UPDATE gateway_schedules SET last_run_at = ? WHERE id = ?", now, sched.ID,
	); err != nil {
		return err
	}
	s.triggerFn(sched)
	payload := map[string]any{"id": sched.ID, "name": sched.Name}
	if eventType == "schedule.triggered" {
		payload["manual"] = true
	}
	s.broadcast(SSEEvent{Type: eventType, Payload: payload})
	return nil
}

func (s *Scheduler) validateScheduleScope(sched Schedule) error {
	_, err := parseScheduleScope(sched)
	return err
}

func parseScheduleTargetsJSON(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var targets []string
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil, fmt.Errorf("invalid schedule targets JSON: %w", err)
	}
	if err := validateScanTargets(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func parseScheduleSelectedReposJSON(raw string) ([]agent.SelectedRepo, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var repos []agent.SelectedRepo
	if err := json.Unmarshal([]byte(raw), &repos); err != nil {
		return nil, fmt.Errorf("invalid selected_repos JSON: %w", err)
	}
	if err := validateSelectedRepos(repos); err != nil {
		return nil, err
	}
	return repos, nil
}
