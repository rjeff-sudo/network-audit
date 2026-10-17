// Package handlers contains all HTTP handler functions for Sentry.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rjeff-sudo/sme-shield/internal/audit"
	"github.com/rjeff-sudo/sme-shield/internal/auth"
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

// SubnetScanRequest is the JSON body for subnet scanning.
type SubnetScanRequest struct {
	Subnet string `json:"subnet"`
}

// SubnetScan handles POST /api/scan/subnet
// It discovers all devices on the subnet and audits each one sequentially.
func (h *ScanHandler) SubnetScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SubnetScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	subnet := strings.TrimSpace(req.Subnet)
	if subnet == "" {
		jsonError(w, "subnet is required", http.StatusBadRequest)
		return
	}

	// Try to acquire the scan lock.
	scanCtx, ok := h.hub.StartScan()
	if !ok {
		h.hub.SendBusy()
		jsonError(w, "another audit is already running", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": "Subnet audit started — follow progress via WebSocket",
		"subnet":  subnet,
	})

	go func() {
		defer h.hub.FinishScan()

		onProgress := func(percent int, message string) {
			h.hub.SendProgress(percent, message)
		}

		onDeviceComplete := func(result models.ScanResult) {
			h.hub.SendComplete(result)
		}

		_, err := h.engine.RunSubnet(scanCtx, auth.UserIDFromContext(r.Context()), subnet, onProgress, onDeviceComplete)
		if err != nil {
			if scanCtx.Err() != nil {
				h.hub.SendProgress(0, "Subnet scan cancelled")
			} else {
				h.hub.SendError("Subnet scan failed: " + err.Error())
			}
			return
		}
	}()
}

// Cancel handles POST /api/scan/cancel
// It aborts the currently running audit if one is in progress.
func (h *ScanHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cancelled := h.hub.CancelScan()
	if !cancelled {
		jsonError(w, "no scan is currently running", http.StatusConflict)
		return
	}

	jsonOK(w, map[string]string{"status": "cancelled", "message": "Scan abort requested"})
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

	// Try to acquire the scan lock — reject if another scan is running.
	scanCtx, ok := h.hub.StartScan()
	if !ok {
		h.hub.SendBusy()
		jsonError(w, "another audit is already running", http.StatusConflict)
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
		defer h.hub.FinishScan()

		onProgress := func(percent int, message string) {
			h.hub.SendProgress(percent, message)
		}

		onPortFound := func(port models.Port) {
			h.hub.SendPortFound(ip, port)
		}

		result, err := h.engine.RunAs(scanCtx, auth.UserIDFromContext(r.Context()), ip, onProgress, onPortFound)
		if err != nil {
			if scanCtx.Err() != nil {
				h.hub.SendProgress(0, "Scan cancelled")
			} else {
				h.hub.SendError("Audit failed: " + err.Error())
			}
			return
		}

		h.hub.SendComplete(result)
	}()
}
