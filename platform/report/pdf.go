// Package report generates PDF security audit reports for SME-Shield.
package report

import (
	"bytes"
	"fmt"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// Data holds everything needed to render a PDF report.
type Data struct {
	ScanID    int64
	IP        string
	Hostname  string
	RiskScore int
	ScanTime  time.Time
	Ports     []PortRow
}

// PortRow is a single port entry in the report table.
type PortRow struct {
	Port     int
	Service  string
	Product  string
	Version  string
	CVECount int
}

// colour palette — keep the report on-brand with the UI
const (
	colDark   = "#0F172A" // slate-900  — headers
	colAccent = "#3B82F6" // blue-500   — section titles
	colGreen  = "#22C55E" // green-500  — Secure
	colAmber  = "#F59E0B" // amber-500  — Moderate
	colOrange = "#F97316" // orange-500 — High Risk
	colRed    = "#EF4444" // red-500    — Critical
	colLight  = "#F8FAFC" // slate-50   — table alt row
	colBorder = "#CBD5E1" // slate-300  — table borders
)

// Generate builds a PDF from data and returns the raw bytes.
func Generate(data Data) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(16, 16, 16)
	pdf.SetAutoPageBreak(true, 20)
	pdf.AddPage()

	drawHeader(pdf, data)
	drawSummaryBox(pdf, data)
	drawPortTable(pdf, data.Ports)
	drawFooter(pdf)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("pdf output: %w", err)
	}
	return buf.Bytes(), nil
}

// ── Section renderers ─────────────────────────────────────────────────────────

func drawHeader(pdf *gofpdf.Fpdf, data Data) {
	// Dark banner background
	setFillHex(pdf, colDark)
	pdf.Rect(0, 0, 210, 36, "F")

	// Logo text
	pdf.SetFont("Helvetica", "B", 20)
	setTextHex(pdf, "#FFFFFF")
	pdf.SetXY(16, 8)
	pdf.CellFormat(80, 10, "SME-Shield", "", 0, "L", false, 0, "")

	// Subtitle
	pdf.SetFont("Helvetica", "", 9)
	setTextHex(pdf, "#94A3B8") // slate-400
	pdf.SetXY(16, 20)
	pdf.CellFormat(80, 6, "Network Security Audit Report", "", 0, "L", false, 0, "")

	// Report date — right aligned
	pdf.SetFont("Helvetica", "", 9)
	setTextHex(pdf, "#94A3B8")
	pdf.SetXY(110, 14)
	pdf.CellFormat(84, 6,
		"Generated: "+data.ScanTime.Format("02 Jan 2006, 15:04 MST"),
		"", 0, "R", false, 0, "")

	pdf.SetY(44)
}

func drawSummaryBox(pdf *gofpdf.Fpdf, data Data) {
	// Section title
	pdf.SetFont("Helvetica", "B", 11)
	setTextHex(pdf, colAccent)
	pdf.CellFormat(0, 7, "Audit Summary", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	// Two-column layout: target info (left) | risk score (right)
	startY := pdf.GetY()

	// Left column — target details
	col1 := [][]string{
		{"Target IP", data.IP},
		{"Hostname", emptyOr(data.Hostname, "—")},
		{"Open Ports", fmt.Sprintf("%d", len(data.Ports))},
		{"Scan Time", data.ScanTime.Format("02 Jan 2006, 15:04:05")},
		{"Report ID", fmt.Sprintf("SCN-%04d", data.ScanID)},
	}

	pdf.SetFont("Helvetica", "", 9)
	for _, row := range col1 {
		setTextHex(pdf, "#64748B") // label — slate-500
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(32, 7, row[0]+":", "", 0, "L", false, 0, "")
		setTextHex(pdf, colDark)
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(60, 7, row[1], "", 1, "L", false, 0, "")
	}

	// Right column — risk score circle (drawn as a filled rect for simplicity)
	scoreColor := scoreHex(data.RiskScore)
	scoreLabel := scoreText(data.RiskScore)

	setFillHex(pdf, scoreColor)
	pdf.RoundedRect(130, startY, 64, 46, 4, "1234", "F")

	pdf.SetFont("Helvetica", "B", 28)
	setTextHex(pdf, "#FFFFFF")
	pdf.SetXY(130, startY+6)
	pdf.CellFormat(64, 14, fmt.Sprintf("%d", data.RiskScore), "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetXY(130, startY+22)
	pdf.CellFormat(64, 8, "SECURITY SCORE", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(130, startY+31)
	pdf.CellFormat(64, 8, scoreLabel, "", 1, "C", false, 0, "")

	pdf.SetY(startY + 52)
	drawHRule(pdf)
}

func drawPortTable(pdf *gofpdf.Fpdf, ports []PortRow) {
	pdf.Ln(3)
	pdf.SetFont("Helvetica", "B", 11)
	setTextHex(pdf, colAccent)
	pdf.CellFormat(0, 7, "Open Ports & Services", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	if len(ports) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		setTextHex(pdf, "#64748B")
		pdf.CellFormat(0, 8, "No open ports were found on the target host.", "", 1, "L", false, 0, "")
		return
	}

	// Table header
	colWidths := []float64{18, 30, 42, 42, 22, 24}
	headers := []string{"Port", "Service", "Product", "Version", "CVEs", "Risk"}

	setFillHex(pdf, colDark)
	setTextHex(pdf, "#FFFFFF")
	pdf.SetFont("Helvetica", "B", 9)

	for i, h := range headers {
		pdf.CellFormat(colWidths[i], 8, h, "0", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Table rows
	pdf.SetFont("Helvetica", "", 8)
	for i, p := range ports {
		// Alternate row shading
		if i%2 == 0 {
			setFillHex(pdf, colLight)
		} else {
			setFillHex(pdf, "#FFFFFF")
		}

		risk := portRiskLabel(p.CVECount)
		riskColor := portRiskColor(p.CVECount)

		setTextHex(pdf, colDark)
		pdf.CellFormat(colWidths[0], 7, fmt.Sprintf("%d", p.Port), "0", 0, "C", true, 0, "")
		pdf.CellFormat(colWidths[1], 7, p.Service, "0", 0, "L", true, 0, "")
		pdf.CellFormat(colWidths[2], 7, truncate(p.Product, 22), "0", 0, "L", true, 0, "")
		pdf.CellFormat(colWidths[3], 7, truncate(p.Version, 22), "0", 0, "L", true, 0, "")
		pdf.CellFormat(colWidths[4], 7, fmt.Sprintf("%d", p.CVECount), "0", 0, "C", true, 0, "")

		// Risk badge cell
		setFillHex(pdf, riskColor)
		setTextHex(pdf, "#FFFFFF")
		pdf.CellFormat(colWidths[5], 7, risk, "0", 1, "C", true, 0, "")
	}

	// Bottom border line under the table
	pdf.Ln(1)
	drawHRule(pdf)
}

func drawFooter(pdf *gofpdf.Fpdf) {
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "I", 8)
	setTextHex(pdf, "#94A3B8")
	pdf.MultiCell(0, 5,
		"This report was generated automatically by SME-Shield. "+
			"CVE data sourced from the NIST National Vulnerability Database (nvd.nist.gov). "+
			"Remediation advice is provided as guidance only — consult a qualified security "+
			"professional before making changes to production systems.",
		"", "L", false)

	pdf.Ln(3)
	setTextHex(pdf, "#CBD5E1")
	pdf.CellFormat(0, 5,
		fmt.Sprintf("SME-Shield  •  Report generated %s", time.Now().Format("02 Jan 2006")),
		"", 0, "C", false, 0, "")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func drawHRule(pdf *gofpdf.Fpdf) {
	setDrawHex(pdf, colBorder)
	pdf.SetLineWidth(0.3)
	y := pdf.GetY()
	pdf.Line(16, y, 194, y)
	pdf.Ln(3)
}

// setFillHex parses a "#RRGGBB" hex string and calls SetFillColor.
func setFillHex(pdf *gofpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetFillColor(r, g, b)
}

// setTextHex parses a "#RRGGBB" hex string and calls SetTextColor.
func setTextHex(pdf *gofpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetTextColor(r, g, b)
}

// setDrawHex parses a "#RRGGBB" hex string and calls SetDrawColor.
func setDrawHex(pdf *gofpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetDrawColor(r, g, b)
}

func hexToRGB(hex string) (int, int, int) {
	hex = trimHash(hex)
	if len(hex) != 6 {
		return 0, 0, 0
	}
	var r, g, b int
	fmt.Sscanf(hex[0:2], "%x", &r)
	fmt.Sscanf(hex[2:4], "%x", &g)
	fmt.Sscanf(hex[4:6], "%x", &b)
	return r, g, b
}

func trimHash(s string) string {
	if len(s) > 0 && s[0] == '#' {
		return s[1:]
	}
	return s
}

func scoreHex(score int) string {
	switch {
	case score >= 80:
		return colGreen
	case score >= 60:
		return colAmber
	case score >= 30:
		return colOrange
	default:
		return colRed
	}
}

func scoreText(score int) string {
	switch {
	case score >= 80:
		return "Secure"
	case score >= 60:
		return "Moderate Risk"
	case score >= 30:
		return "High Risk"
	default:
		return "Critical"
	}
}

func portRiskLabel(cveCount int) string {
	switch {
	case cveCount == 0:
		return "Clean"
	case cveCount <= 2:
		return "Low"
	case cveCount <= 5:
		return "Medium"
	default:
		return "High"
	}
}

func portRiskColor(cveCount int) string {
	switch {
	case cveCount == 0:
		return colGreen
	case cveCount <= 2:
		return colAmber
	case cveCount <= 5:
		return colOrange
	default:
		return colRed
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func emptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}