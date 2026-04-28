package models

import "time"

// ScanResult represents the final output of a single IP scan
type ScanResult struct {
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	ScanTime    time.Time `json:"scan_time"`
	OpenPorts   []Port    `json:"open_ports"`
	RiskScore   int       `json:"risk_score"`
}

// Port represents details of a discovered open port
type Port struct {
	Number      int      `json:"number"`
	Protocol    string   `json:"protocol"` // TCP/UDP
	Service     string   `json:"service"`  // e.g., SSH, HTTP
	Version     string   `json:"version"`  // e.g., OpenSSH 8.2
	Vulnerabilities []CVE `json:"vulnerabilities"`
}

// CVE represents a specific security vulnerability from NVD
type CVE struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"` // Critical, High, etc.
	Score       float64 `json:"score"`
	Description string  `json:"description"`
	Fix         string  `json:"fix"`
}