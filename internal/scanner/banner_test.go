package scanner

import (
	"testing"
)

// ── SSH banner parsing ───────────────────────────────────────────────────────

func TestParseBanner_SSH(t *testing.T) {
	raw := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
	info := ParseBanner(raw, 22)
	if info.Product != "OpenSSH" {
		t.Errorf("Product = %q, want %q", info.Product, "OpenSSH")
	}
	if info.Version != "8.9p1" {
		t.Errorf("Version = %q, want %q", info.Version, "8.9p1")
	}
}

func TestParseBanner_SSHSimple(t *testing.T) {
	raw := "SSH-2.0-OpenSSH_7.4"
	info := ParseBanner(raw, 22)
	if info.Product != "OpenSSH" {
		t.Errorf("Product = %q, want %q", info.Product, "OpenSSH")
	}
	if info.Version != "7.4" {
		t.Errorf("Version = %q, want %q", info.Version, "7.4")
	}
}

// ── HTTP Server header ───────────────────────────────────────────────────────

func TestParseBanner_HTTPServerHeader(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n"
	info := ParseBanner(raw, 80)
	if info.Product != "nginx" {
		t.Errorf("Product = %q, want %q", info.Product, "nginx")
	}
	if info.Version != "1.18.0" {
		t.Errorf("Version = %q, want %q", info.Version, "1.18.0")
	}
}

func TestParseBanner_HTTPServerApache(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n\r\n"
	info := ParseBanner(raw, 80)
	if info.Product != "Apache" {
		t.Errorf("Product = %q, want %q", info.Product, "Apache")
	}
	if info.Version != "2.4.52" {
		t.Errorf("Version = %q, want %q", info.Version, "2.4.52")
	}
}

// ── Generic product/version pattern ──────────────────────────────────────────

func TestParseBanner_GenericVersion(t *testing.T) {
	raw := "ProFTPD 1.3.5a Server"
	info := ParseBanner(raw, 21)
	if info.Product != "ProFTPD" {
		t.Errorf("Product = %q, want %q", info.Product, "ProFTPD")
	}
	if info.Version != "1.3.5a" {
		t.Errorf("Version = %q, want %q", info.Version, "1.3.5a")
	}
}

// ── MySQL banner ─────────────────────────────────────────────────────────────

func TestParseBanner_MySQL(t *testing.T) {
	raw := "5.7.39-0ubuntu0.18.04.1"
	info := ParseBanner(raw, 3306)
	// MySQL banners are just version numbers — the generic regex should pick up 5.7.39
	if info.Version != "5.7.39" {
		t.Errorf("expected version 5.7.39, got %q", info.Version)
	}
}

// ── Empty / no banner ────────────────────────────────────────────────────────

func TestParseBanner_Empty(t *testing.T) {
	info := ParseBanner("", 80)
	if info.Product == "" {
		t.Error("expected fallback product name, got empty")
	}
	if info.Version != "Unknown" {
		t.Errorf("Version = %q, want %q for empty banner", info.Version, "Unknown")
	}
}

// ── Unknown port fallback ────────────────────────────────────────────────────

func TestParseBanner_UnknownPort(t *testing.T) {
	info := ParseBanner("", 9999)
	if info.Product != "Port-9999" {
		t.Errorf("Product = %q, want %q for unknown port", info.Product, "Port-9999")
	}
}

// ── Raw field preserved ──────────────────────────────────────────────────────

func TestParseBanner_RawPreserved(t *testing.T) {
	raw := "SSH-2.0-OpenSSH_8.9p1"
	info := ParseBanner(raw, 22)
	if info.Raw != raw {
		t.Errorf("Raw = %q, want %q", info.Raw, raw)
	}
}

// ── ServiceName ──────────────────────────────────────────────────────────────

func TestServiceName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{6379, "Redis"},
		{27017, "MongoDB"},
		{12345, "Port-12345"},
	}
	for _, tt := range tests {
		got := ServiceName(tt.port)
		if got != tt.want {
			t.Errorf("ServiceName(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}
