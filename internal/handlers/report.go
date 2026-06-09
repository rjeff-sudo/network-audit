package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rjeff-sudo/sme-shield/platform/report"
)

// ReportHandler generates downloadable PDF reports for a completed scan.
type ReportHandler struct {
	db *sql.DB
}

// NewReportHandler constructs a ReportHandler.
func NewReportHandler(db *sql.DB) *ReportHandler {
	return &ReportHandler{db: db}
}

// Download handles GET /api/report/{id}
func (h *ReportHandler) Download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Path[len("/api/report/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	data, err := h.buildReportData(id)
	if err == sql.ErrNoRows {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, "could not load scan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pdfBytes, err := report.Generate(data)
	if err != nil {
		jsonError(w, "PDF generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("sme-shield-report-%s-%s.pdf",
		data.IP,
		data.ScanTime.Format("2006-01-02"),
	)

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Length", strconv.Itoa(len(pdfBytes)))
	w.Write(pdfBytes)
}

// buildReportData queries the database and assembles a report.Data struct.
func (h *ReportHandler) buildReportData(id int64) (report.Data, error) {
	var data report.Data
	var scanTimeStr string

	err := h.db.QueryRow(`
		SELECT id, ip, COALESCE(hostname,''), risk_score, scan_time
		FROM scans WHERE id = ?`, id).
		Scan(&data.ScanID, &data.IP, &data.Hostname, &data.RiskScore, &scanTimeStr)
	if err != nil {
		return data, err
	}

	data.ScanTime = parseScanTime(scanTimeStr)

	rows, err := h.db.Query(`
		SELECT port, service, product, version, cve_count
		FROM scan_results WHERE scan_id = ?
		ORDER BY port ASC`, id)
	if err != nil {
		return data, err
	}
	defer rows.Close()

	for rows.Next() {
		var p report.PortRow
		if err := rows.Scan(&p.Port, &p.Service, &p.Product, &p.Version, &p.CVECount); err != nil {
			continue
		}
		data.Ports = append(data.Ports, p)
	}

	return data, nil
}

// parseScanTime tries every format SQLite might have stored the time in.
// Falls back to time.Now() so the PDF always shows a real date.
func parseScanTime(s string) time.Time {
	formats := []string{
		time.RFC3339Nano,                // 2006-01-02T15:04:05.999999999Z07:00
		time.RFC3339,                    // 2006-01-02T15:04:05Z07:00
		"2006-01-02T15:04:05.999999999", // without timezone
		"2006-01-02T15:04:05",           // short ISO
		"2006-01-02 15:04:05.999999999", // SQLite default with space
		"2006-01-02 15:04:05",           // SQLite default short
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil && t.Year() > 1 {
			return t
		}
	}
	// Last resort — the DB value is unreadable, use current time
	return time.Now()
}

// ── Shared response helpers ───────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprint(w, `{"error":"marshal failed"}`)
		return
	}
	w.Write(b)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": message})
	w.Write(b)
}
