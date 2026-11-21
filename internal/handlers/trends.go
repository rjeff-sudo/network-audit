package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
)

// TrendHandler serves score history data for the vulnerability trend tracker.
type TrendHandler struct {
	db *sql.DB
}

// NewTrendHandler constructs a TrendHandler.
func NewTrendHandler(db *sql.DB) *TrendHandler {
	return &TrendHandler{db: db}
}

// trendPoint is a single data point in the trend chart.
type trendPoint struct {
	ScanID    int64  `json:"scan_id"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	RiskScore int    `json:"risk_score"`
	ScanTime  string `json:"scan_time"`
	CVECount  int    `json:"cve_count"`
}

// HandleTrends handles GET /api/trends?ip=optional
// Returns all scan scores for a specific IP, or all devices if ip is empty.
func (h *TrendHandler) HandleTrends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.URL.Query().Get("ip")

	userID := auth.UserIDFromContext(r.Context())

	var rows *sql.Rows
	var err error

	// Use a LEFT JOIN aggregation instead of a correlated subquery to avoid
	// an N+1 pattern (one extra query per scan row).
	if ip != "" {
		rows, err = h.db.Query(`
			SELECT s.id, s.ip, COALESCE(s.hostname, ''), s.risk_score, s.scan_time,
				COALESCE(SUM(r.cve_count), 0) AS cve_count
			FROM scans s
			LEFT JOIN scan_results r ON r.scan_id = s.id
			WHERE s.ip = ? AND s.user_id = ?
			GROUP BY s.id
			ORDER BY s.scan_time ASC`, ip, userID)
	} else {
		// Return latest scan per device for the overview chart.
		rows, err = h.db.Query(`
			SELECT s.id, s.ip, COALESCE(s.hostname, ''), s.risk_score, s.scan_time,
				COALESCE(SUM(r.cve_count), 0) AS cve_count
			FROM scans s
			LEFT JOIN scan_results r ON r.scan_id = s.id
			WHERE s.user_id = ? AND s.id IN (
				SELECT MAX(id) FROM scans WHERE user_id = ? GROUP BY ip
			)
			GROUP BY s.id
			ORDER BY s.scan_time ASC`, userID, userID)
	}

	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var points []trendPoint
	for rows.Next() {
		var p trendPoint
		var scanTimeStr string
		if err := rows.Scan(&p.ScanID, &p.IP, &p.Hostname, &p.RiskScore, &scanTimeStr, &p.CVECount); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, scanTimeStr)
		p.ScanTime = t.Format(time.RFC3339)
		points = append(points, p)
	}

	if points == nil {
		points = []trendPoint{}
	}

	jsonOK(w, map[string]interface{}{
		"points": points,
	})
}

// HandleDeviceTrends handles GET /api/trends/devices
// Returns a summary of all devices with their latest score and scan count.
func (h *TrendHandler) HandleDeviceTrends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := auth.UserIDFromContext(r.Context())

	// Avoid correlated subqueries (one per device) by joining against the
	// latest-scan-per-ip set once.
	rows, err := h.db.Query(`
		SELECT
			s.ip,
			COALESCE(MAX(s.hostname), '') AS hostname,
			latest.risk_score                AS latest_score,
			latest.scan_time                 AS latest_scan,
			COUNT(s.id)                      AS scan_count
		FROM scans s
		JOIN (
			SELECT ip, risk_score, scan_time
			FROM scans
			WHERE user_id = ?
			AND id IN (SELECT MAX(id) FROM scans WHERE user_id = ? GROUP BY ip)
		) AS latest ON latest.ip = s.ip
		WHERE s.user_id = ?
		GROUP BY s.ip
		ORDER BY latest_score ASC`, userID, userID, userID)
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type deviceSummary struct {
		IP          string `json:"ip"`
		Hostname    string `json:"hostname"`
		LatestScore int    `json:"latest_score"`
		LatestScan  string `json:"latest_scan"`
		ScanCount   int    `json:"scan_count"`
	}

	var devices []deviceSummary
	for rows.Next() {
		var d deviceSummary
		var scanTimeStr string
		if err := rows.Scan(&d.IP, &d.Hostname, &d.LatestScore, &scanTimeStr, &d.ScanCount); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, scanTimeStr)
		d.LatestScan = t.Format(time.RFC3339)
		devices = append(devices, d)
	}

	if devices == nil {
		devices = []deviceSummary{}
	}

	jsonOK(w, map[string]interface{}{
		"devices": devices,
	})
}
