package audit

import (
	"testing"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

// ── CalculateScore ───────────────────────────────────────────────────────────

func TestCalculateScore_NoCVEs(t *testing.T) {
	score := CalculateScore(nil)
	if score != 100 {
		t.Errorf("expected 100 for no CVEs, got %d", score)
	}
}

func TestCalculateScore_SingleCritical(t *testing.T) {
	cves := []models.CVE{
		{ID: "CVE-2024-6387", Score: 9.8, Severity: "CRITICAL"},
	}
	score := CalculateScore(cves)
	if score <= 0 || score >= 100 {
		t.Errorf("expected a score between 0-99 for 1 critical CVE, got %d", score)
	}
	// A single critical should knock off a meaningful amount
	if score > 80 {
		t.Errorf("expected score < 80 for critical CVE, got %d", score)
	}
}

func TestCalculateScore_MultipleCVEsReduceScore(t *testing.T) {
	one := []models.CVE{
		{ID: "CVE-2024-0001", Score: 9.0, Severity: "CRITICAL"},
	}
	many := []models.CVE{
		{ID: "CVE-2024-0001", Score: 9.0, Severity: "CRITICAL"},
		{ID: "CVE-2024-0002", Score: 9.0, Severity: "CRITICAL"},
		{ID: "CVE-2024-0003", Score: 9.0, Severity: "CRITICAL"},
	}
	s1 := CalculateScore(one)
	s2 := CalculateScore(many)
	if s2 >= s1 {
		t.Errorf("more CVEs should reduce score: 1 CVE=%d, 3 CVEs=%d", s1, s2)
	}
}

func TestCalculateScore_AllLowImpact(t *testing.T) {
	cves := []models.CVE{
		{ID: "CVE-2024-0001", Score: 2.0, Severity: "LOW"},
		{ID: "CVE-2024-0002", Score: 3.0, Severity: "LOW"},
	}
	score := CalculateScore(cves)
	// A few low CVEs should still leave a decent score
	if score < 70 {
		t.Errorf("expected score >= 70 for 2 low CVEs, got %d", score)
	}
}

func TestCalculateScore_SevereCVEs(t *testing.T) {
	// Simulate a heavily compromised host
	cves := []models.CVE{
		{ID: "CVE-1", Score: 9.8, Severity: "CRITICAL"},
		{ID: "CVE-2", Score: 9.5, Severity: "CRITICAL"},
		{ID: "CVE-3", Score: 8.5, Severity: "HIGH"},
		{ID: "CVE-4", Score: 7.5, Severity: "HIGH"},
		{ID: "CVE-5", Score: 7.0, Severity: "HIGH"},
	}
	score := CalculateScore(cves)
	if score > 50 {
		t.Errorf("expected score <= 50 for 5 severe CVEs, got %d", score)
	}
}

// ── SeverityLabel ────────────────────────────────────────────────────────────

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.5, "CRITICAL"},
		{9.0, "CRITICAL"},
		{7.5, "HIGH"},
		{7.0, "HIGH"},
		{5.0, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.0, "LOW"},
		{0.0, "LOW"},
	}
	for _, tt := range tests {
		got := SeverityLabel(tt.score)
		if got != tt.want {
			t.Errorf("SeverityLabel(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ── BuildSummary ─────────────────────────────────────────────────────────────

func TestBuildSummary_NoCVEs(t *testing.T) {
	s := BuildSummary(nil)
	if s.Critical != 0 || s.High != 0 || s.Medium != 0 || s.Low != 0 {
		t.Errorf("expected all zero counts, got %+v", s)
	}
	if s.Label != "Secure" {
		t.Errorf("expected label 'Secure', got %q", s.Label)
	}
}

func TestBuildSummary_Labels(t *testing.T) {
	tests := []struct {
		cves    []models.CVE
		wantLbl string
	}{
	{
		cves: []models.CVE{
			{ID: "1", Score: 9.8, Severity: "CRITICAL"},
			{ID: "2", Score: 9.5, Severity: "CRITICAL"},
			{ID: "3", Score: 8.5, Severity: "HIGH"},
			{ID: "4", Score: 7.5, Severity: "HIGH"},
			{ID: "5", Score: 5.0, Severity: "MEDIUM"},
		},
		wantLbl: "High Risk",
	},
	{
		cves: []models.CVE{
			{ID: "1", Score: 9.8, Severity: "CRITICAL"},
			{ID: "2", Score: 9.5, Severity: "CRITICAL"},
			{ID: "3", Score: 8.5, Severity: "HIGH"},
			{ID: "4", Score: 7.5, Severity: "HIGH"},
			{ID: "5", Score: 4.0, Severity: "MEDIUM"},
			{ID: "6", Score: 4.0, Severity: "MEDIUM"},
			{ID: "7", Score: 4.0, Severity: "MEDIUM"},
			{ID: "8", Score: 4.0, Severity: "MEDIUM"},
			{ID: "9", Score: 4.0, Severity: "MEDIUM"},
			{ID: "10", Score: 4.0, Severity: "MEDIUM"},
			{ID: "11", Score: 4.0, Severity: "MEDIUM"},
			{ID: "12", Score: 4.0, Severity: "MEDIUM"},
			{ID: "13", Score: 4.0, Severity: "MEDIUM"},
			{ID: "14", Score: 4.0, Severity: "MEDIUM"},
			{ID: "15", Score: 4.0, Severity: "MEDIUM"},
			{ID: "16", Score: 4.0, Severity: "MEDIUM"},
			{ID: "17", Score: 4.0, Severity: "MEDIUM"},
		},
		wantLbl: "Critical",
	},
	}
	for _, tt := range tests {
		s := BuildSummary(tt.cves)
		if s.Label != tt.wantLbl {
			t.Errorf("BuildSummary label = %q, want %q (cves: %d)", s.Label, tt.wantLbl, len(tt.cves))
		}
	}
}

func TestBuildSummary_Counts(t *testing.T) {
	cves := []models.CVE{
		{ID: "1", Severity: "CRITICAL"},
		{ID: "2", Severity: "CRITICAL"},
		{ID: "3", Severity: "HIGH"},
		{ID: "4", Severity: "MEDIUM"},
		{ID: "5", Severity: "LOW"},
		{ID: "6", Severity: "LOW"},
	}
	s := BuildSummary(cves)
	if s.Critical != 2 {
		t.Errorf("Critical = %d, want 2", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("High = %d, want 1", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("Medium = %d, want 1", s.Medium)
	}
	if s.Low != 2 {
		t.Errorf("Low = %d, want 2", s.Low)
	}
}
