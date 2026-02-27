package gateway

import (
	"encoding/json"
	"net/http"
)

// scheduleRequest is the body for POST/PUT /api/schedules.
type scheduleRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Expr          string `json:"expr"`
	ScopeJSON     string `json:"scope_json"`
	Targets       string `json:"targets"`
	SelectedRepos string `json:"selected_repos"`
	Mode          string `json:"mode"`
	Enabled       bool   `json:"enabled"`
}

func (gw *Gateway) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	schedules, err := gw.scheduler.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	if schedules == nil {
		schedules = []Schedule{}
	}
	writeJSON(w, http.StatusOK, schedules)
}

func (gw *Gateway) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Expr == "" {
		writeError(w, http.StatusBadRequest, "name and expr are required")
		return
	}
	if req.Targets == "" {
		req.Targets = "[]"
	}
	if req.SelectedRepos == "" {
		req.SelectedRepos = "[]"
	}
	sched := Schedule{
		Name:          req.Name,
		Description:   req.Description,
		ScopeJSON:     req.ScopeJSON,
		Expr:          req.Expr,
		Targets:       req.Targets,
		SelectedRepos: req.SelectedRepos,
		Mode:          req.Mode,
		Enabled:       req.Enabled,
	}
	if err := hydrateScheduleScopeFields(&sched); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := gw.scheduler.Add(r.Context(), sched)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sched.ID = id
	gw.broadcaster.send(SSEEvent{Type: "schedule.created", Payload: map[string]any{"id": id}})
	writeJSON(w, http.StatusCreated, sched)
}

func (gw *Gateway) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req scheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.Expr == "" {
		writeError(w, http.StatusBadRequest, "name and expr are required")
		return
	}
	if req.Targets == "" {
		req.Targets = "[]"
	}
	if req.SelectedRepos == "" {
		req.SelectedRepos = "[]"
	}
	sched := Schedule{
		Name:          req.Name,
		Description:   req.Description,
		ScopeJSON:     req.ScopeJSON,
		Expr:          req.Expr,
		Targets:       req.Targets,
		SelectedRepos: req.SelectedRepos,
		Mode:          req.Mode,
		Enabled:       req.Enabled,
	}
	if err := hydrateScheduleScopeFields(&sched); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.scheduler.Update(r.Context(), id, sched); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "schedule.updated", Payload: map[string]any{"id": id}})
	sched.ID = id
	writeJSON(w, http.StatusOK, sched)
}

func (gw *Gateway) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.scheduler.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "schedule.deleted", Payload: map[string]any{"id": id}})
	w.WriteHeader(http.StatusNoContent)
}

func (gw *Gateway) handleTriggerSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := gw.scheduler.TriggerNow(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "triggered"})
}

func hydrateScheduleScopeFields(s *Schedule) error {
	scope, err := parseScheduleScope(*s)
	if err != nil {
		return err
	}
	return applyScopeToScheduleFields(s, scope)
}
