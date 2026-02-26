package gateway

import (
	"context"
	"log/slog"
	"time"
)

const (
	heartbeatCheckInterval = 30 * time.Second
	// stuckThreshold is how long a sweep can run with no orchestrator activity
	// before we declare it stuck. 15 minutes is conservative — large repo scans
	// can legitimately take a while, but a truly hung goroutine will miss this easily.
	stuckThreshold = 15 * time.Minute
	// deadThreshold is how long after gateway start we wait before calling an
	// orchestrator that has never emitted any event "dead".
	deadThreshold = 10 * time.Minute
)

// HeartbeatMonitor subscribes to orchestrator lifecycle events (already funneled
// through the Gateway's callback wiring) and periodically computes the agent's
// health status. It broadcasts an "agent.health" SSE event whenever the status
// changes, and exposes computeStatus() for the REST handler.
type HeartbeatMonitor struct {
	gw         *Gateway
	lastStatus string // tracks previous status to suppress no-change broadcasts
}

func newHeartbeatMonitor(gw *Gateway) *HeartbeatMonitor {
	return &HeartbeatMonitor{gw: gw}
}

// run is the background goroutine. It checks health every heartbeatCheckInterval
// and broadcasts an SSE event when the computed status changes.
func (h *HeartbeatMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(heartbeatCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.evaluate()
		}
	}
}

// evaluate computes current health and broadcasts on change.
func (h *HeartbeatMonitor) evaluate() {
	hs := h.computeStatus()
	if hs.Status != h.lastStatus {
		h.lastStatus = hs.Status
		h.gw.broadcaster.send(SSEEvent{Type: "agent.health", Payload: hs})
		slog.Info("gateway: agent health changed", "status", hs.Status, "message", hs.Message)
	}
}

// computeStatus derives a HeartbeatStatus from the gateway's tracked activity fields.
// It is safe to call from any goroutine.
func (h *HeartbeatMonitor) computeStatus() HeartbeatStatus {
	h.gw.mu.RLock()
	lastAt := h.gw.lastActivityAt
	sweepRunning := h.gw.sweepRunning
	startedAt := h.gw.startedAt
	h.gw.mu.RUnlock()

	now := time.Now()

	// No orchestrator event has ever been received.
	if lastAt.IsZero() {
		if now.Sub(startedAt) > deadThreshold {
			return HeartbeatStatus{
				Status:       "dead",
				SweepRunning: false,
				Message:      "Orchestrator has not emitted any events since gateway start.",
			}
		}
		return HeartbeatStatus{
			Status:       "idle",
			SweepRunning: false,
			Message:      "Waiting for first orchestrator activity.",
		}
	}

	lastAtStr := lastAt.UTC().Format(time.RFC3339)

	if !sweepRunning {
		return HeartbeatStatus{
			Status:         "idle",
			LastActivityAt: lastAtStr,
			SweepRunning:   false,
			Message:        "No sweep running — waiting for trigger or cron schedule.",
		}
	}

	// Sweep is running. Check for stuck condition.
	sinceActivity := now.Sub(lastAt)
	if sinceActivity > stuckThreshold {
		return HeartbeatStatus{
			Status:         "stuck",
			LastActivityAt: lastAtStr,
			SweepRunning:   true,
			StuckForSecs:   int64(sinceActivity.Seconds()),
			Message:        "Sweep is running but no orchestrator activity detected. May be hung on a slow network call.",
		}
	}

	return HeartbeatStatus{
		Status:         "alive",
		LastActivityAt: lastAtStr,
		SweepRunning:   true,
		Message:        "Sweep in progress.",
	}
}
