package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// HistoryHandler serves past scan results from the database.
type HistoryHandler struct {
	db *sql.DB
}

// NewHistoryHandler constructs a HistoryHandler.
func NewHistoryHandler(db *sql.DB) *HistoryHandler {
	return &HistoryHandler{db: db}
}

// scanRow is a flat database row returned to the UI.
type scanRow struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	RiskScore int       `json:"risk_score"`
	ScanTime  time.Time `json:"scan_time"`
	PortCount int       `json:"port_count"`
	CVECount  int       `json:"cve_count"`
}

// List handles GET /api/history
func (h *HistoryHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	rows, err := h.db.Query(`
		SELECT
			s.id,
			s.ip,
			COALESCE(s.hostname, '') AS hostname,
			s.risk_score,
			s.scan_time,
			COUNT(r.id) AS port_count,
			COALESCE(SUM(r.cve_count), 0) AS cve_count
		FROM scans s
		LEFT JOIN scan_results r ON r.scan_id = s.id
		GROUP BY s.id
		ORDER BY s.scan_time DESC
		LIMIT ?`, limit)
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []scanRow
	for rows.Next() {
		var s scanRow
		var scanTimeStr string
		err := rows.Scan(
			&s.ID, &s.IP, &s.Hostname,
			&s.RiskScore, &scanTimeStr,
			&s.PortCount, &s.CVECount,
		)
		if err != nil {
			continue
		}
		s.ScanTime, _ = time.Parse(time.RFC3339Nano, scanTimeStr)
		scans = append(scans, s)
	}

	if scans == nil {
		scans = []scanRow{}
	}

	jsonOK(w, scans)
}

// Get handles GET /api/history/{id}
func (h *HistoryHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Path[len("/api/history/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	var s scanRow
	var scanTimeStr string
	err = h.db.QueryRow(`
		SELECT id, ip, COALESCE(hostname,''), risk_score, scan_time
		FROM scans WHERE id = ?`, id).
		Scan(&s.ID, &s.IP, &s.Hostname, &s.RiskScore, &scanTimeStr)
	if err == sql.ErrNoRows {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	s.ScanTime, _ = time.Parse(time.RFC3339Nano, scanTimeStr)

	portRows, err := h.db.Query(`
		SELECT port, service, product, version, cve_count
		FROM scan_results WHERE scan_id = ?
		ORDER BY port ASC`, id)
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer portRows.Close()

	type portDetail struct {
		Port     int    `json:"port"`
		Service  string `json:"service"`
		Product  string `json:"product"`
		Version  string `json:"version"`
		CVECount int    `json:"cve_count"`
	}

	var ports []portDetail
	for portRows.Next() {
		var p portDetail
		if err := portRows.Scan(&p.Port, &p.Service, &p.Product, &p.Version, &p.CVECount); err != nil {
			continue
		}
		ports = append(ports, p)
	}

	if ports == nil {
		ports = []portDetail{}
	}

	jsonOK(w, map[string]interface{}{
		"scan":  s,
		"ports": ports,
	})
}

// Delete handles DELETE /api/history/{id}
func (h *HistoryHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Path[len("/api/history/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	res, err := h.db.Exec(`DELETE FROM scans WHERE id = ?`, id)
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	h.db.Exec(`DELETE FROM scan_results WHERE scan_id = ?`, id)
	jsonOK(w, map[string]string{"status": "deleted"})
}

// portCountStr is a small helper used by the discovery handler.
func portCountStr(n int) string {
	if n == 0 {
		return "no"
	}
	return fmt.Sprintf("%d", n)
}