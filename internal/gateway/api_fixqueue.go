package gateway

import (
	"net/http"
	"time"
)

// fixQueueRow maps a row from the fix_queue table.
type fixQueueRow struct {
	ID             int64   `db:"id"           json:"id"`
	ScanJobID      int64   `db:"scan_job_id"  json:"scan_job_id"`
	FindingType    string  `db:"finding_type" json:"finding_type"`
	FindingID      int64   `db:"finding_id"   json:"finding_id"`
	AIProvider     string  `db:"ai_provider"  json:"ai_provider,omitempty"`
	AIModel        string  `db:"ai_model"     json:"ai_model,omitempty"`
	AIEndpoint     string  `db:"ai_endpoint"  json:"ai_endpoint,omitempty"`
	ApplyHintsJSON string  `db:"apply_hints_json" json:"apply_hints_json,omitempty"`
	PRTitle        string  `db:"pr_title"     json:"pr_title"`
	PRBody         string  `db:"pr_body"      json:"pr_body"`
	Status         string  `db:"status"       json:"status"`
	PRURL          string  `db:"pr_url"       json:"pr_url,omitempty"`
	GeneratedAt    string  `db:"generated_at" json:"generated_at"`
	ApprovedAt     *string `db:"approved_at"  json:"approved_at,omitempty"`
}

func (gw *Gateway) handleListFixQueue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}

	var rows []fixQueueRow
	if err := gw.db.Select(ctx, &rows,
		`SELECT id, scan_job_id, finding_type, finding_id, ai_provider, ai_model, ai_endpoint, apply_hints_json, pr_title, pr_body,
		        status, pr_url, generated_at, approved_at
		 FROM fix_queue WHERE status = ? ORDER BY id DESC LIMIT 100`,
		status,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if rows == nil {
		rows = []fixQueueRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (gw *Gateway) handleFixApprove(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := gw.db.Exec(r.Context(),
		"UPDATE fix_queue SET status = 'approved', approved_at = ? WHERE id = ?", now, id,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{
		Type:    "fix.approved",
		Payload: map[string]any{"id": id},
	})
	gw.triggerPRProcessing() // wake PR worker to pick this up (not a full scan sweep)
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (gw *Gateway) handleFixApproveAndRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := gw.db.Exec(r.Context(),
		"UPDATE fix_queue SET status = 'approved', approved_at = ? WHERE id = ?", now, id,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "fix.approved", Payload: map[string]any{"id": id}})
	gw.triggerPRProcessing()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "approved_and_pr_processing"})
}

func (gw *Gateway) handleFixReject(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.db.Exec(r.Context(),
		"UPDATE fix_queue SET status = 'rejected' WHERE id = ?", id,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	gw.broadcaster.send(SSEEvent{
		Type:    "fix.rejected",
		Payload: map[string]any{"id": id},
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

