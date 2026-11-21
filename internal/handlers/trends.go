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

// HandleTrendsSummary handles GET /api/trends/summary
// Returns the full scan history for every device in one payload, structured
// for the multi-line trend chart. Each device entry carries its own ordered
// array of data points (scan_time, risk_score, cve_count, port_count) plus
// a pre-computed delta so the UI can show improvement/deterioration instantly.
func (h *TrendHandler) HandleTrendsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := auth.UserIDFromContext(r.Context())

	// Single query: every scan for this user, with aggregated port/CVE counts.
	rows, err := h.db.Query(`
		SELECT
			s.id,
			s.ip,
			COALESCE(s.hostname, '')         AS hostname,
			s.risk_score,
			s.scan_time,
			COALESCE(SUM(r.cve_count), 0)   AS cve_count,
			COUNT(r.id)                      AS port_count
		FROM scans s
		LEFT JOIN scan_results r ON r.scan_id = s.id
		WHERE s.user_id = ?
		GROUP BY s.id
		ORDER BY s.ip ASC, s.scan_time ASC`, userID)
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type point struct {
		ScanID    int64  `json:"scan_id"`
		ScanTime  string `json:"scan_time"`
		RiskScore int    `json:"risk_score"`
		CVECount  int    `json:"cve_count"`
		PortCount int    `json:"port_count"`
	}
	type deviceHistory struct {
		IP       string  `json:"ip"`
		Hostname string  `json:"hostname"`
		Points   []point `json:"points"`
		// Delta: latest risk_score minus previous risk_score.
		// Positive = improved (score went up), negative = deteriorated.
		Delta       int `json:"delta"`
		LatestScore int `json:"latest_score"`
		LatestCVE   int `json:"latest_cve"`
		ScanCount   int `json:"scan_count"`
	}

	// Group by IP preserving insertion order.
	order := []string{}
	byIP := map[string]*deviceHistory{}

	for rows.Next() {
		var scanID int64
		var ip, hostname, scanTimeStr string
		var riskScore, cveCount, portCount int
		if err := rows.Scan(&scanID, &ip, &hostname, &riskScore, &scanTimeStr, &cveCount, &portCount); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, scanTimeStr)

		dh, exists := byIP[ip]
		if !exists {
			dh = &deviceHistory{IP: ip, Hostname: hostname}
			byIP[ip] = dh
			order = append(order, ip)
		}
		if hostname != "" {
			dh.Hostname = hostname // keep most recent non-empty hostname
		}
		dh.Points = append(dh.Points, point{
			ScanID:    scanID,
			ScanTime:  t.Format(time.RFC3339),
			RiskScore: riskScore,
			CVECount:  cveCount,
			PortCount: portCount,
		})
	}

	// Compute deltas and summaries.
	result := make([]deviceHistory, 0, len(order))
	for _, ip := range order {
		dh := byIP[ip]
		dh.ScanCount = len(dh.Points)
		if dh.ScanCount > 0 {
			last := dh.Points[dh.ScanCount-1]
			dh.LatestScore = last.RiskScore
			dh.LatestCVE = last.CVECount
			if dh.ScanCount >= 2 {
				prev := dh.Points[dh.ScanCount-2]
				dh.Delta = last.RiskScore - prev.RiskScore
			}
		}
		result = append(result, *dh)
	}

	jsonOK(w, map[string]interface{}{
		"devices": result,
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
