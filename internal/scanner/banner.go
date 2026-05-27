package scanner

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

var wellKnownPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	135:   "RPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

var httpProbe = "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: SME-Shield/1.0\r\n\r\n"

var httpPorts = map[int]bool{80: true, 443: true, 8080: true, 8443: true}

func GrabBanner(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if httpPorts[port] {
		conn.Write([]byte(httpProbe))
	}

	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return string(buf[:n])
}

func ParseBanner(raw string, port int) models.ServiceInfo {
	clean := regexp.MustCompile(`[^\x20-\x7E\r\n]+`).ReplaceAllString(raw, " ")
	clean = strings.TrimSpace(clean)

	fallback := wellKnownPorts[port]
	if fallback == "" {
		fallback = fmt.Sprintf("Port-%d", port)
	}

	if clean == "" {
		return models.ServiceInfo{Product: fallback, Version: "Unknown"}
	}

	if m := regexp.MustCompile(`SSH-[\d.]+-([A-Za-z0-9_.-]+)`).FindStringSubmatch(clean); len(m) >= 2 {
		parts := strings.SplitN(m[1], "_", 2)
		product := parts[0]
		version := "Unknown"
		if len(parts) == 2 {
			version = parts[1]
		}
		return models.ServiceInfo{Product: product, Version: version, Raw: clean}
	}

	if m := regexp.MustCompile(`(?i)Server:\s*([A-Za-z0-9._-]+)/([0-9][0-9A-Za-z._-]*)`).FindStringSubmatch(clean); len(m) >= 3 {
		return models.ServiceInfo{Product: m[1], Version: m[2], Raw: clean}
	}

	if m := regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]+)/([0-9][0-9A-Za-z._-]*)`).FindStringSubmatch(clean); len(m) >= 3 {
		return models.ServiceInfo{Product: m[1], Version: m[2], Raw: clean}
	}

	if m := regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]+)\s+([0-9][0-9A-Za-z._-]*)`).FindStringSubmatch(clean); len(m) >= 3 {
		return models.ServiceInfo{Product: m[1], Version: m[2], Raw: clean}
	}

	return models.ServiceInfo{Product: fallback, Version: "Unknown", Raw: clean}
}

func ServiceName(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return fmt.Sprintf("Port-%d", port)
}
