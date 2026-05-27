package hub

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[*Client]struct{}
}

func New() *Hub {
	return &Hub{
		clients: make(map[*Client]struct{}),
	}
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

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}
