package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rjeff-sudo/sme-shield/internal/audit"
	"github.com/rjeff-sudo/sme-shield/internal/hub"
	"github.com/rjeff-sudo/sme-shield/internal/models"
)

type ScanHandler struct {
	engine *audit.Engine
	hub    *hub.Hub
}

func NewScanHandler(engine *audit.Engine, hub *hub.Hub) *ScanHandler {
	return &ScanHandler{engine: engine, hub: hub}
}

type scanRequest struct {
	IP string `json:"ip"`
}

func (h *ScanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ip := strings.TrimSpace(req.IP)
	if ip == "" {
		jsonError(w, "ip is required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": "Audit started — follow progress via WebSocket",
		"ip":      ip,
	})

	go func() {
		onProgress := func(percent int, message string) {
			h.hub.SendProgress(percent, message)
		}

		onPortFound := func(port models.Port) {
			h.hub.SendPortFound(ip, port)
		}

		result, err := h.engine.Run(ip, onProgress, onPortFound)
		if err != nil {
			h.hub.SendError("Audit failed: " + err.Error())
			return
		}

		h.hub.SendComplete(result)
	}()
}
