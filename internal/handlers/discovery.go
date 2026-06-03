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
func (h *DiscoveryHandler) Discover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Subnet string `json:"subnet"`
	}
	json.NewDecoder(r.Body).Decode(&body)

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

		h.hub.SendProgress(100, "Discovery complete — found "+portCountStr(len(devices))+" device(s)")
	}()
}