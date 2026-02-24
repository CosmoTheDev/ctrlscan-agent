package gateway

import (
	"encoding/json"
	"log/slog"
	"sync"
)

// Broadcaster fans SSEEvent values out to all active GET /events subscribers.
// Slow clients are skipped (non-blocking channel send with per-client buffer).
type Broadcaster struct {
	mu   sync.RWMutex
	subs map[chan []byte]struct{}
}

func newBroadcaster() *Broadcaster {
	return &Broadcaster{subs: make(map[chan []byte]struct{})}
}

// subscribe returns a channel that receives ready-to-write SSE data frames.
// The caller must call unsubscribe when the HTTP connection closes.
func (b *Broadcaster) subscribe() chan []byte {
	ch := make(chan []byte, 32)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broadcaster) unsubscribe(ch chan []byte) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

// send serialises evt as JSON and fans the SSE frame to all active subscribers.
func (b *Broadcaster) send(evt SSEEvent) {
	raw, err := json.Marshal(evt)
	if err != nil {
		slog.Warn("gateway: failed to marshal SSE event", "type", evt.Type, "error", err)
		return
	}
	// SSE wire format: "data: <json>\n\n"
	frame := []byte("data: ")
	frame = append(frame, raw...)
	frame = append(frame, '\n', '\n')

	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs {
		select {
		case ch <- frame:
		default:
			// slow subscriber — skip this frame
		}
	}
}
