package hub

import (
	"context"
	"encoding/json"
	"log"
	"sync"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

type Hub struct {
	mu            sync.RWMutex
	clients       map[*Client]struct{}
	allowedOrigin string // "*" = allow all, "" = same-origin, or a specific origin URL

	// Scan concurrency guard — only one audit may run at a time.
	scanMu      sync.Mutex
	scanning    bool
	scanCancel  context.CancelFunc // non-nil while a scan is running
}

func New(allowedOrigin string) *Hub {
	return &Hub{
		clients:       make(map[*Client]struct{}),
		allowedOrigin: allowedOrigin,
	}
}

// StartScan tries to acquire the scan lock. Returns a cancellable context
// and true if the scan can proceed, or (nil, false) if another scan is running.
func (h *Hub) StartScan() (context.Context, bool) {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	if h.scanning {
		return nil, false
	}
	h.scanning = true
	ctx, cancel := context.WithCancel(context.Background())
	h.scanCancel = cancel
	return ctx, true
}

// FinishScan releases the scan lock so the next audit can proceed.
func (h *Hub) FinishScan() {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	h.scanning = false
	h.scanCancel = nil
}

// CancelScan aborts the currently running scan, if any.
func (h *Hub) CancelScan() bool {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	if !h.scanning || h.scanCancel == nil {
		return false
	}
	h.scanCancel()
	return true
}

// IsScanning reports whether an audit is currently in progress.
func (h *Hub) IsScanning() bool {
	h.scanMu.Lock()
	defer h.scanMu.Unlock()
	return h.scanning
}

func (h *Hub) Register(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
	log.Printf("[hub] client connected — total: %d", len(h.clients))
}

func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
		log.Printf("[hub] client disconnected — total: %d", len(h.clients))
	}
}

func (h *Hub) Broadcast(msg models.WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[hub] marshal error: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			log.Printf("[hub] dropping slow client")
			go h.Unregister(c)
		}
	}
}

func (h *Hub) SendProgress(percent int, message string) {
	h.Broadcast(models.WSMessage{
		Type: models.WSTypeProgress,
		Payload: models.WSPayloadProgress{
			Percent: percent,
			Message: message,
		},
	})
}

func (h *Hub) SendPortFound(ip string, port models.Port) {
	h.Broadcast(models.WSMessage{
		Type: models.WSTypePortFound,
		Payload: models.WSPayloadPortFound{
			IP:       ip,
			Port:     port.Number,
			Service:  port.Service,
			Product:  port.ServiceInfo.Product,
			Version:  port.ServiceInfo.Version,
			CVECount: len(port.Vulnerabilities),
		},
	})
}

func (h *Hub) SendComplete(result models.ScanResult) {
	h.Broadcast(models.WSMessage{
		Type:    models.WSTypeComplete,
		Payload: models.WSPayloadComplete{Result: result},
	})
}

func (h *Hub) SendError(message string) {
	h.Broadcast(models.WSMessage{
		Type:    models.WSTypeError,
		Payload: models.WSPayloadError{Message: message},
	})
}

func (h *Hub) SendBusy() {
	h.Broadcast(models.WSMessage{
		Type: models.WSTypeBusy,
		Payload: map[string]string{
			"message": "Another audit is already running. Please wait for it to finish.",
		},
	})
}

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
