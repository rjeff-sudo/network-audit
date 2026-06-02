package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/hub"
	"github.com/rjeff-sudo/sme-shield/internal/models"
	"github.com/rjeff-sudo/sme-shield/internal/network"
)

// DiscoveryHandler holds dependencies for the network discovery endpoints.
type DiscoveryHandler struct {
	cfg models.Config
	hub *hub.Hub
}

// NewDiscoveryHandler constructs a DiscoveryHandler.
func NewDiscoveryHandler(cfg models.Config, hub *hub.Hub) *DiscoveryHandler {
	return &DiscoveryHandler{cfg: cfg, hub: hub}
}

// Subnet handles GET /api/subnet
// Returns the detected local subnet CIDR so the UI can show it to the user.
func (h *DiscoveryHandler) Subnet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cidr, err := network.GetLocalSubnet()
	if err != nil {
		jsonError(w, "could not detect subnet: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"subnet": cidr})
}

// Discover handles POST /api/discover
// Sweeps the local subnet and streams discovered devices over WebSocket,
// returning a 202 immediately so the browser doesn't hang.
func (h *DiscoveryHandler) Discover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Optional: accept a specific CIDR in the request body.
	// If not provided, auto-detect.
	var body struct {
		Subnet string `json:"subnet"`
	}
	json.NewDecoder(r.Body).Decode(&body) // ignore decode errors — body is optional

	cidr := body.Subnet
	if cidr == "" {
		var err error
		cidr, err = network.GetLocalSubnet()
		if err != nil {
			jsonError(w, "could not detect subnet: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "accepted",
		"subnet": cidr,
	})

	go func() {
		h.hub.SendProgress(0, "Starting network discovery on "+cidr)

		timeout := time.Duration(h.cfg.Discovery.TimeoutMs) * time.Millisecond
		devices, err := network.DiscoverDevices(
			cidr,
			h.cfg.Discovery.ProbePorts,
			h.cfg.Discovery.WorkerCount,
			timeout,
		)
		if err != nil {
			h.hub.SendError("Discovery failed: " + err.Error())
			return
		}

		h.hub.Broadcast(models.WSMessage{
			Type:    models.WSTypeDevices,
			Payload: devices,
		})

		h.hub.SendProgress(100, "Discovery complete — found "+countStr(len(devices))+" device(s)")
	}()
}

func countStr(n int) string {
	if n == 0 {
		return "no"
	}
	b, _ := json.Marshal(n)
	return string(b)
}