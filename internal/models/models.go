// Package models defines every shared data type in SME-Shield.
// No business logic lives here — only structs, enums, and constants.
package models

import "time"

// ── Configuration ─────────────────────────────────────────────────────────────

// Config mirrors the structure of config.yaml.
type Config struct {
	Server struct {
		Port   int    `yaml:"port"`
		UIDir  string `yaml:"ui_dir"`
		DBPath string `yaml:"db_path"`
	} `yaml:"server"`

	Scanner struct {
		WorkerCount     int   `yaml:"worker_count"`
		TimeoutMs       int   `yaml:"timeout_ms"`
		BannerTimeoutMs int   `yaml:"banner_timeout_ms"`
		Ports           []int `yaml:"ports"`
	} `yaml:"scanner"`

	Discovery struct {
		WorkerCount int   `yaml:"worker_count"`
		TimeoutMs   int   `yaml:"timeout_ms"`
		ProbePorts  []int `yaml:"probe_ports"`
	} `yaml:"discovery"`

	NVD struct {
		APIKey         string `yaml:"api_key"`
		BaseURL        string `yaml:"base_url"`
		CacheTTLHours  int    `yaml:"cache_ttl_hours"`
		RequestDelayMs int    `yaml:"request_delay_ms"`
	} `yaml:"nvd"`

	Auth struct {
		SessionSecret   string `yaml:"session_secret"`
		SessionTTLHours int    `yaml:"session_ttl_hours"`
	} `yaml:"auth"`
}

// ── Network discovery ─────────────────────────────────────────────────────────

// Device represents an active host found during subnet discovery.
type Device struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Active   bool   `json:"active"`
}

// ── Scan / audit results ──────────────────────────────────────────────────────

// ServiceInfo holds the parsed product name and version extracted from a banner.
type ServiceInfo struct {
	Product string `json:"product"`
	Version string `json:"version"`
	Raw     string `json:"raw,omitempty"` // original banner text for debugging
}

// CVE is a single vulnerability entry sourced from the NVD.
type CVE struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	Score       float64 `json:"score"`    // CVSS base score 0.0–10.0
	Description string  `json:"description"`
	Fix         string  `json:"fix"` // human-readable remediation advice
}

// Port holds everything discovered about a single open TCP port.
type Port struct {
	Number          int         `json:"number"`
	Protocol        string      `json:"protocol"` // always "tcp" for now
	Service         string      `json:"service"`  // friendly name e.g. "SSH"
	ServiceInfo     ServiceInfo `json:"service_info"`
	Vulnerabilities []CVE       `json:"vulnerabilities"`
}

// Summary gives a quick human-readable breakdown attached to a ScanResult.
type Summary struct {
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Label    string `json:"label"` // "Secure" | "Moderate Risk" | "High Risk" | "Critical"
}

// ScanResult is the complete audit output for a single target IP address.
type ScanResult struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	ScanTime  time.Time `json:"scan_time"`
	OpenPorts []Port    `json:"open_ports"`
	RiskScore int       `json:"risk_score"` // 0 (worst) – 100 (best)
	Summary   Summary   `json:"summary"`
}

// ── NVD API ───────────────────────────────────────────────────────────────────

// NVDResponse maps the NVD API 2.0 JSON envelope.
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CvssMetricV30 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CvssMetricV2 []struct {
					CvssData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// ── WebSocket message types ───────────────────────────────────────────────────

// WSMessage is the envelope for every message sent to the browser over WS.
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// Defined Type constants — the browser switches on these.
const (
	WSTypeProgress  = "SCAN_PROGRESS" // audit is running
	WSTypePortFound = "PORT_FOUND"    // a port has been analysed
	WSTypeComplete  = "SCAN_COMPLETE" // audit finished
	WSTypeError     = "SCAN_ERROR"    // audit failed
	WSTypeDevices   = "DEVICES_FOUND" // discovery results
)

// WSPayloadProgress is sent periodically while a scan runs.
type WSPayloadProgress struct {
	Percent int    `json:"percent"`
	Message string `json:"message"`
}

// WSPayloadPortFound is sent each time an open port is fully analysed.
type WSPayloadPortFound struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	CVECount int    `json:"cve_count"`
}

// WSPayloadComplete is sent when the full audit is done.
type WSPayloadComplete struct {
	Result ScanResult `json:"result"`
}

// WSPayloadError is sent when the audit fails.
type WSPayloadError struct {
	Message string `json:"message"`
}
