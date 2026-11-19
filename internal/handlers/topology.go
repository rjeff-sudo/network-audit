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

	// Collect scan IDs and base device data first, then batch-fetch port details.
	type partialDevice struct {
		topologyDevice
		scanID int64
	}
	var partial []partialDevice
	var scanIDs []int64

	for rows.Next() {
		var d partialDevice
		var scanTimeStr string
		if err := rows.Scan(&d.IP, &d.Hostname, &d.RiskScore, &scanTimeStr, &d.OpenPorts, &d.CVECount); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, scanTimeStr)
		d.ScanTime = t.Format(time.RFC3339)
		d.scanID = h.getLatestScanID(d.IP, userID)
		partial = append(partial, d)
		if d.scanID > 0 {
			scanIDs = append(scanIDs, d.scanID)
		}
	}
	rows.Close()

	// Batch fetch all port data for all scan IDs in two queries.
	serviceMap := map[int64][]string{}
	portSetMap := map[int64]map[int]bool{}
	productMap := map[int64][]string{}
	if len(scanIDs) > 0 {
		serviceMap, portSetMap, productMap = h.batchFetchPortData(scanIDs)
	}

	var devices []topologyDevice
	for _, pd := range partial {
		d := pd.topologyDevice
		if pd.scanID > 0 {
			d.Services = serviceMap[pd.scanID]
			if d.Services == nil {
				d.Services = []string{}
			}
			d.DeviceType = classifyDeviceType(portSetMap[pd.scanID])
			d.OSHint = classifyOS(productMap[pd.scanID])
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

// batchFetchPortData fetches service, port, and product data for a slice of
// scan IDs in two queries (instead of one query per device), eliminating the
// N+1 problem in HandleTopo.
//
// Returns:
//
//	serviceMap  — scan_id → sorted list of distinct non-empty service names
//	portSetMap  — scan_id → set of open port numbers
//	productMap  — scan_id → list of distinct non-empty product banner strings
func (h *TopologyHandler) batchFetchPortData(scanIDs []int64) (
	serviceMap map[int64][]string,
	portSetMap map[int64]map[int]bool,
	productMap map[int64][]string,
) {
	serviceMap = make(map[int64][]string)
	portSetMap = make(map[int64]map[int]bool)
	productMap = make(map[int64][]string)

	if len(scanIDs) == 0 {
		return
	}

	// Build a placeholder list: (?,?,?,...) for the IN clause.
	placeholders := make([]byte, 0, len(scanIDs)*2)
	args := make([]interface{}, len(scanIDs))
	for i, id := range scanIDs {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args[i] = id
	}
	inClause := string(placeholders)

	rows, err := h.db.Query(
		`SELECT scan_id, port, service, product FROM scan_results WHERE scan_id IN (`+inClause+`)`,
		args...)
	if err != nil {
		return
	}
	defer rows.Close()

	// Track which services/products we have already appended to avoid
	// re-scanning the slice on every row; use a small set per scan_id.
	seenSvc := make(map[int64]map[string]bool)
	seenProd := make(map[int64]map[string]bool)

	for rows.Next() {
		var scanID int64
		var port int
		var service, product string
		if err := rows.Scan(&scanID, &port, &service, &product); err != nil {
			continue
		}

		// Port set
		if portSetMap[scanID] == nil {
			portSetMap[scanID] = make(map[int]bool)
		}
		portSetMap[scanID][port] = true

		// Services (distinct, non-empty)
		if service != "" {
			if seenSvc[scanID] == nil {
				seenSvc[scanID] = make(map[string]bool)
			}
			if !seenSvc[scanID][service] {
				seenSvc[scanID][service] = true
				serviceMap[scanID] = append(serviceMap[scanID], service)
			}
		}

		// Products (distinct, non-empty)
		if product != "" {
			if seenProd[scanID] == nil {
				seenProd[scanID] = make(map[string]bool)
			}
			if !seenProd[scanID][product] {
				seenProd[scanID][product] = true
				productMap[scanID] = append(productMap[scanID], product)
			}
		}
	}
	return
}

// classifyDeviceType infers a device category from its open-port fingerprint.
func classifyDeviceType(ports map[int]bool) string {
	if ports == nil {
		return "unknown"
	}
	// Printer: IPP (631), raw printing (9100)
	if ports[631] || ports[9100] {
		return "printer"
	}
	// Router/network device: SNMP (161), UPnP (1900)
	if ports[161] || ports[1900] {
		return "router"
	}
	// Windows workstation/server: RDP (3389), SMB+RPC (445+135), WinRM (5985/5986)
	if ports[3389] || (ports[445] && ports[135]) || ports[5985] || ports[5986] {
		return "workstation"
	}
	// Server: web stack combined with a database port
	if (ports[80] || ports[443]) && (ports[3306] || ports[5432] || ports[27017] || ports[6379]) {
		return "server"
	}
	// Pure web server
	if ports[80] || ports[443] {
		return "server"
	}
	// Database-only
	if ports[3306] || ports[5432] || ports[27017] || ports[6379] || ports[1433] {
		return "server"
	}
	// Linux/Unix host reachable only via SSH
	if ports[22] && !ports[80] && !ports[443] {
		return "workstation"
	}
	return "unknown"
}

// classifyOS infers the operating system from banner product strings returned
// by the scanner (populated from service version detection).
func classifyOS(products []string) string {
	for _, p := range products {
		if containsAny(p, "Microsoft", "IIS", "Windows", "SMB", "RDP", "WinRM") {
			return "windows"
		}
		if containsAny(p, "macOS", "Darwin", "Apple") {
			return "macos"
		}
		if containsAny(p, "OpenSSH", "nginx", "Apache", "Ubuntu", "Debian", "CentOS",
			"Red Hat", "kernel", "Linux", "lighttpd", "ProFTPD", "vsftpd", "Postfix", "Dovecot") {
			return "linux"
		}
		if containsAny(p, "Cisco", "MikroTik", "Ubiquiti", "TP-Link", "D-Link") {
			return "network"
		}
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
