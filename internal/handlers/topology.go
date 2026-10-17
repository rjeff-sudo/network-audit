package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
)

// TopologyHandler serves network topology data for the visual map.
type TopologyHandler struct {
	db *sql.DB
}

// NewTopologyHandler constructs a TopologyHandler.
func NewTopologyHandler(db *sql.DB) *TopologyHandler {
	return &TopologyHandler{db: db}
}

// topologyDevice represents a device node in the topology map.
type topologyDevice struct {
	IP         string   `json:"ip"`
	Hostname   string   `json:"hostname"`
	RiskScore  int      `json:"risk_score"`
	ScanTime   string   `json:"scan_time"`
	Services   []string `json:"services"`
	DeviceType string   `json:"device_type"` // "server", "workstation", "printer", "router", "iot", "unknown"
	OSHint     string   `json:"os_hint"`     // "linux", "windows", "macos", "unknown"
	OpenPorts  int      `json:"open_ports"`
	CVECount   int      `json:"cve_count"`
}

// HandleTopo handles GET /api/topology
// Returns the latest scan data for every unique IP ever scanned.
func (h *TopologyHandler) HandleTopo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := auth.UserIDFromContext(r.Context())

	rows, err := h.db.Query(`
		SELECT
			s.ip,
			COALESCE(s.hostname, '') AS hostname,
			s.risk_score,
			s.scan_time,
			COUNT(r.id) AS open_ports,
			COALESCE(SUM(r.cve_count), 0) AS cve_count
		FROM scans s
		LEFT JOIN scan_results r ON r.scan_id = s.id
		WHERE s.user_id = ? AND s.id IN (
			SELECT MAX(id) FROM scans WHERE user_id = ? GROUP BY ip
		)
		GROUP BY s.id
		ORDER BY s.risk_score ASC`, userID, userID)
	if err != nil {
		jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var devices []topologyDevice
	for rows.Next() {
		var d topologyDevice
		var scanTimeStr string
		if err := rows.Scan(&d.IP, &d.Hostname, &d.RiskScore, &scanTimeStr, &d.OpenPorts, &d.CVECount); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, scanTimeStr)
		d.ScanTime = t.Format(time.RFC3339)

		// Get services for this device's latest scan
		scanID := h.getLatestScanID(d.IP, userID)
		if scanID > 0 {
			d.Services = h.getServices(scanID)
			d.DeviceType = h.fingerprintDeviceType(scanID)
			d.OSHint = h.fingerprintOS(scanID)
		}

		devices = append(devices, d)
	}

	if devices == nil {
		devices = []topologyDevice{}
	}

	jsonOK(w, map[string]interface{}{
		"devices": devices,
		"gateway": getGatewayIP(),
	})
}

func (h *TopologyHandler) getLatestScanID(ip string, userID int64) int64 {
	var id int64
	h.db.QueryRow(`SELECT MAX(id) FROM scans WHERE ip = ? AND user_id = ?`, ip, userID).Scan(&id)
	return id
}

func (h *TopologyHandler) getServices(scanID int64) []string {
	rows, err := h.db.Query(`
		SELECT DISTINCT service FROM scan_results
		WHERE scan_id = ? AND service != '' ORDER BY service`, scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var services []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err == nil {
			services = append(services, s)
		}
	}
	return services
}

// fingerprintDeviceType infers the device type from open port patterns.
func (h *TopologyHandler) fingerprintDeviceType(scanID int64) string {
	rows, err := h.db.Query(`SELECT port FROM scan_results WHERE scan_id = ?`, scanID)
	if err != nil {
		return "unknown"
	}
	defer rows.Close()

	ports := map[int]bool{}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err == nil {
			ports[p] = true
		}
	}

	// Printer: IPP (631), raw printing (9100)
	if ports[631] || ports[9100] {
		return "printer"
	}
	// Router/network device: SNMP (161), UPnP (1900), management (8080 with SSH)
	if ports[161] || ports[1900] {
		return "router"
	}
	// Windows server/workstation: RDP (3389), SMB (445), WinRM (5985/5986)
	if ports[3389] || (ports[445] && ports[135]) || ports[5985] || ports[5986] {
		return "workstation"
	}
	// Server: web (80/443) + database (3306/5432/27017/6379)
	if (ports[80] || ports[443]) && (ports[3306] || ports[5432] || ports[27017] || ports[6379]) {
		return "server"
	}
	// Web server: 80 or 443
	if ports[80] || ports[443] {
		return "server"
	}
	// Database server: just database ports
	if ports[3306] || ports[5432] || ports[27017] || ports[6379] || ports[1433] {
		return "server"
	}
	// Linux/Unix workstation: SSH only
	if ports[22] && !ports[80] && !ports[443] {
		return "workstation"
	}

	return "unknown"
}

// fingerprintOS infers the OS from banner products stored in scan_results.
func (h *TopologyHandler) fingerprintOS(scanID int64) string {
	rows, err := h.db.Query(`
		SELECT DISTINCT product FROM scan_results
		WHERE scan_id = ? AND product != ''`, scanID)
	if err != nil {
		return "unknown"
	}
	defer rows.Close()

	for rows.Next() {
		var product string
		if err := rows.Scan(&product); err != nil {
			continue
		}
		p := product
		// Windows indicators
		if containsAny(p, "Microsoft", "IIS", "Windows", "SMB", "RDP", "WinRM") {
			return "windows"
		}
		// macOS indicators
		if containsAny(p, "macOS", "Darwin", "Apple") {
			return "macos"
		}
		// Linux indicators (most common)
		if containsAny(p, "OpenSSH", "nginx", "Apache", "Ubuntu", "Debian", "CentOS",
			"Red Hat", "kernel", "Linux", "lighttpd", "ProFTPD", "vsftpd", "Postfix", "Dovecot") {
			return "linux"
		}
		// Network设备
		if containsAny(p, "Cisco", "MikroTik", "Ubiquiti", "TP-Link", "D-Link") {
			return "network"
		}
		// Printer
		if containsAny(p, "HP", "Canon", "Epson", "Brother", "CUPS", "Printer") {
			return "printer"
		}
	}
	return "unknown"
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if equalFold(s[i:i+len(sub)], sub) {
					return true
				}
			}
		}
	}
	return false
}

// equalFold is a simple case-insensitive contains check.
func equalFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c1, c2 := s[i], t[i]
		if c1 == c2 {
			continue
		}
		if c1 >= 'A' && c1 <= 'Z' {
			c1 += 32
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 += 32
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}

// getGatewayIP returns the gateway/router IP (first scan IP as heuristic).
func getGatewayIP() string {
	// In a real implementation this would use net.Interfaces to get the default gateway.
	// For now, return empty — the frontend handles this gracefully.
	return ""
}


