package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/robfig/cron/v3"
)

// Scheduler loads gateway_schedules from SQLite and registers them with
// robfig/cron. When a schedule fires it calls triggerFn (waking the
// orchestrator) and records last_run_at.
type Scheduler struct {
	db        database.DB
	cron      *cron.Cron
	triggerFn func()
	broadcast func(SSEEvent)

	mu      sync.Mutex
	entries map[int64]cron.EntryID // schedule DB id → cron entry id
}

func newScheduler(db database.DB, triggerFn func(), broadcast func(SSEEvent)) *Scheduler {
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
		`SELECT id, name, description, expr, targets, mode, enabled, last_run_at, created_at, updated_at
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
	entryID, err := s.cron.AddFunc(sched.Expr, func() {
		slog.Info("schedule fired", "name", sched.Name, "id", sched.ID)
		now := time.Now().UTC().Format(time.RFC3339)
		_ = s.db.Exec(context.Background(),
			"UPDATE gateway_schedules SET last_run_at = ? WHERE id = ?", now, sched.ID)
		s.triggerFn()
		s.broadcast(SSEEvent{
			Type:    "schedule.fired",
			Payload: map[string]any{"id": sched.ID, "name": sched.Name},
		})
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
		`SELECT id, name, description, expr, targets, mode, enabled, last_run_at, created_at, updated_at
		 FROM gateway_schedules ORDER BY id`)
	return out, err
}

// TriggerNow fires the agent immediately regardless of schedule, recording
// last_run_at for the given schedule id.
func (s *Scheduler) TriggerNow(ctx context.Context, id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Exec(ctx,
		"UPDATE gateway_schedules SET last_run_at = ? WHERE id = ?", now, id,
	); err != nil {
		return err
	}
	s.triggerFn()
	s.broadcast(SSEEvent{
		Type:    "schedule.triggered",
		Payload: map[string]any{"id": id},
	})
	return nil
}
