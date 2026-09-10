package audit

import (
	"strings"
	"testing"
)

// ── Known CVE remediation ────────────────────────────────────────────────────

func TestRemediation_KnownCVE(t *testing.T) {
	tests := []struct {
		cveID   string
		product string
		contain string // the fix should contain this substring
	}{
		{"CVE-2024-6387", "OpenSSH", "9.8p1"},
		{"CVE-2023-38408", "OpenSSH", "SSH agent"},
		{"CVE-2021-41773", "Apache", "2.4.51"},
		{"CVE-2017-0144", "SMB", "EternalBlue"},
		{"CVE-2019-0708", "RDP", "BlueKeep"},
		{"CVE-2015-3306", "FTP", "ProFTPD"},
		{"CVE-2011-4862", "Telnet", "plaintext"},
	}
	for _, tt := range tests {
		fix := Remediation(tt.cveID, tt.product)
		if fix == "" {
			t.Errorf("Remediation(%q, %q) returned empty string", tt.cveID, tt.product)
		}
		if !strings.Contains(fix, tt.contain) {
			t.Errorf("Remediation(%q, %q) = %q, should contain %q", tt.cveID, tt.product, fix, tt.contain)
		}
	}
}

// ── Product fallbacks ────────────────────────────────────────────────────────

func TestRemediation_ProductFallback(t *testing.T) {
	tests := []struct {
		cveID   string
		product string
		contain string
	}{
		{"CVE-9999-0001", "nginx", "latest stable"},
		{"CVE-9999-0002", "Apache", "2.4.58"},
		{"CVE-9999-0003", "MySQL", "127.0.0.1"},
		{"CVE-9999-0004", "Redis", "requirepass"},
		{"CVE-9999-0005", "MongoDB", "--auth"},
		{"CVE-9999-0006", "OpenSSH", "SSH keys"},
	}
	for _, tt := range tests {
		fix := Remediation(tt.cveID, tt.product)
		if fix == "" {
			t.Errorf("Remediation(%q, %q) returned empty string", tt.cveID, tt.product)
		}
		if !strings.Contains(fix, tt.contain) {
			t.Errorf("Remediation(%q, %q) = %q, should contain %q", tt.cveID, tt.product, fix, tt.contain)
		}
	}
}

// ── Default fallback for unknown products ────────────────────────────────────

func TestRemediation_DefaultFallback(t *testing.T) {
	fix := Remediation("CVE-9999-9999", "SomeWeirdSoftware")
	if fix == "" {
		t.Fatal("expected non-empty fallback remediation")
	}
	if !strings.Contains(fix, "SomeWeirdSoftware") {
		t.Errorf("default fallback should mention the product name, got: %q", fix)
	}
	if !strings.Contains(fix, "latest") {
		t.Errorf("default fallback should mention updating, got: %q", fix)
	}
}

// ── No empty returns ─────────────────────────────────────────────────────────

func TestRemediation_NeverEmpty(t *testing.T) {
	// Every combination of (unknown CVE, any product) should return something
	products := []string{"", "unknown", "CustomApp", "MyTool 3.2"}
	for _, p := range products {
		fix := Remediation("CVE-0000-0000", p)
		if fix == "" {
			t.Errorf("Remediation returned empty for product %q", p)
		}
	}
}
