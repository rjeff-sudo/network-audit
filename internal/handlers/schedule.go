package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/rjeff-sudo/sme-shield/internal/scheduler"
)

// ScheduleHandler handles all schedule CRUD endpoints.
type ScheduleHandler struct {
	sched *scheduler.Scheduler
}

// NewScheduleHandler constructs a ScheduleHandler.
func NewScheduleHandler(s *scheduler.Scheduler) *ScheduleHandler {
	return &ScheduleHandler{sched: s}
}

// List handles GET /api/schedules
func (h *ScheduleHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	schedules, err := h.sched.List()
	if err != nil {
		jsonError(w, "could not load schedules", http.StatusInternalServerError)
		return
	}
	jsonOK(w, schedules)
}

// Create handles POST /api/schedules
func (h *ScheduleHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		IP          string `json:"ip"`
		Label       string `json:"label"`
		IntervalHrs int    `json:"interval_hrs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.IP == "" {
		jsonError(w, "ip is required", http.StatusBadRequest)
		return
	}
	if body.IntervalHrs < 1 {
		jsonError(w, "interval_hrs must be at least 1", http.StatusBadRequest)
		return
	}

	sc, err := h.sched.Create(body.IP, body.Label, body.IntervalHrs)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	b, _ := json.Marshal(sc)
	w.Write(b)
}

// Route handles /api/schedules/{id} — dispatches by method.
func (h *ScheduleHandler) Route(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api/schedules/42 or /api/schedules/42/run
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/schedules/"), "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid schedule id", http.StatusBadRequest)
		return
	}

	// /api/schedules/{id}/run — fire immediately
	if len(parts) > 1 && parts[1] == "run" {
		if r.Method != http.MethodPost {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := h.sched.RunNow(id); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"status": "scan started"})
		return
	}

	// /api/schedules/{id}/toggle — enable or disable
	if len(parts) > 1 && parts[1] == "toggle" {
		if r.Method != http.MethodPost {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if err := h.sched.Toggle(id, body.Enabled); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"status": "updated"})
		return
	}

	// /api/schedules/{id} DELETE
	if r.Method == http.MethodDelete {
		if err := h.sched.Delete(id); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]string{"status": "deleted"})
		return
	}

	jsonError(w, "not found", http.StatusNotFound)
}