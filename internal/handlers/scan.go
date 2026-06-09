// Package handlers contains all HTTP handler functions for SME-Shield.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rjeff-sudo/sme-shield/internal/audit"
	"github.com/rjeff-sudo/sme-shield/internal/hub"
	"github.com/rjeff-sudo/sme-shield/internal/models"
)

// ScanHandler holds dependencies for the scan endpoint.
type ScanHandler struct {
	engine *audit.Engine
	hub    *hub.Hub
}

// NewScanHandler constructs a ScanHandler.
func NewScanHandler(engine *audit.Engine, hub *hub.Hub) *ScanHandler {
	return &ScanHandler{engine: engine, hub: hub}
}

// scanRequest is the JSON body expected from the browser.
type scanRequest struct {
	IP string `json:"ip"`
}

// ServeHTTP handles POST /api/scan
// It launches the audit in a goroutine so the HTTP response returns immediately
// with a 202 Accepted. All progress is streamed via WebSocket.
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

	// Acknowledge immediately — results stream over WebSocket.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": "Audit started — follow progress via WebSocket",
		"ip":      ip,
	})

	// Run the audit in the background.
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
