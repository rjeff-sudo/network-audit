// Package report generates PDF security audit reports for SME-Shield.
package report

import (
	"bytes"
	"fmt"
	"strings"
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

// Colour palette - professional, minimal
const (
	colDark    = "#1E293B"
	colAccent  = "#2563EB"
	colGreen   = "#15803D"
	colAmber   = "#B45309"
	colOrange  = "#C2410C"
	colRed     = "#B91C1C"
	colLight   = "#F8FAFC"
	colBorder  = "#E2E8F0"
	colMuted   = "#64748B"
	colBgBlue  = "#EFF6FF"
	colBgGreen = "#F0FDF4"
)

var eat = time.FixedZone("EAT", 3*3600)

// Generate builds a PDF from data and returns the raw bytes.
func Generate(data Data) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(16, 16, 16)
	pdf.SetAutoPageBreak(true, 24)
	pdf.AddPage()

	drawHeader(pdf, data)
	drawExecutiveSummary(pdf, data)
	drawWhatThisMeans(pdf, data)
	drawPortTable(pdf, data.Ports)
	drawRecommendations(pdf, data)
	drawFooter(pdf, data)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("pdf output: %w", err)
	}
	return buf.Bytes(), nil
}

// ── Sections ──────────────────────────────────────────────────────────────────

func drawHeader(pdf *gofpdf.Fpdf, data Data) {
	setFillHex(pdf, colDark)
	pdf.Rect(0, 0, 210, 36, "F")

	pdf.SetFont("Helvetica", "B", 20)
	setTextHex(pdf, "#FFFFFF")
	pdf.SetXY(16, 7)
	pdf.CellFormat(90, 10, "SME-Shield", "", 0, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	setTextHex(pdf, "#94A3B8")
	pdf.SetXY(16, 20)
	pdf.CellFormat(90, 6, "Network Security Audit Report", "", 0, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	setTextHex(pdf, "#94A3B8")
	pdf.SetXY(110, 11)
	pdf.CellFormat(84, 6, "Report ID: SCN-"+fmt.Sprintf("%04d", data.ScanID), "", 1, "R", false, 0, "")
	pdf.SetXY(110, 19)
	pdf.CellFormat(84, 6, "Generated: "+data.ScanTime.In(eat).Format("02 Jan 2006, 15:04 MST"), "", 1, "R", false, 0, "")

	pdf.SetY(44)
}

func drawExecutiveSummary(pdf *gofpdf.Fpdf, data Data) {
	sectionTitle(pdf, "Executive Summary")

	startY := pdf.GetY()

	details := [][]string{
		{"Device Scanned", data.IP},
		{"Device Name", emptyOr(data.Hostname, "Not identified")},
		{"Open Services", fmt.Sprintf("%d found", len(data.Ports))},
		{"Scan Date", data.ScanTime.In(eat).Format("Monday, 02 January 2006")},
		{"Scan Time", data.ScanTime.In(eat).Format("15:04:05 MST")},
	}

	for _, row := range details {
		pdf.SetFont("Helvetica", "B", 9)
		setTextHex(pdf, colMuted)
		pdf.CellFormat(38, 7, row[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		setTextHex(pdf, colDark)
		pdf.CellFormat(70, 7, row[1], "", 1, "L", false, 0, "")
	}

	// Score box - right side
	scoreCol := scoreHex(data.RiskScore)
	setFillHex(pdf, scoreCol)
	pdf.RoundedRect(126, startY, 68, 50, 4, "1234", "F")

	pdf.SetFont("Helvetica", "B", 38)
	setTextHex(pdf, "#FFFFFF")
	pdf.SetXY(126, startY+3)
	pdf.CellFormat(68, 18, fmt.Sprintf("%d", data.RiskScore), "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetXY(126, startY+22)
	pdf.CellFormat(68, 7, "out of 100", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetXY(126, startY+31)
	pdf.CellFormat(68, 7, strings.ToUpper(scoreLabel(data.RiskScore)), "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 7)
	pdf.SetXY(126, startY+40)
	pdf.CellFormat(68, 7, "Higher score = safer device", "", 1, "C", false, 0, "")

	pdf.SetY(startY + 56)
	hRule(pdf)
}

func drawWhatThisMeans(pdf *gofpdf.Fpdf, data Data) {
	sectionTitle(pdf, "What Does This Mean For Your Business?")

	pdf.SetFont("Helvetica", "", 10)
	setTextHex(pdf, colDark)
	pdf.MultiCell(0, 6, plainEnglishScore(data.RiskScore, len(data.Ports)), "", "L", false)
	pdf.Ln(4)

	// Score guide
	setFillHex(pdf, "#F1F5F9")
	boxY := pdf.GetY()
	pdf.RoundedRect(16, boxY, 178, 26, 3, "1234", "F")
	pdf.SetXY(20, boxY+3)
	pdf.SetFont("Helvetica", "B", 9)
	setTextHex(pdf, colDark)
	pdf.CellFormat(0, 6, "How is the Security Score calculated?", "", 1, "L", false, 0, "")
	pdf.SetX(20)
	pdf.SetFont("Helvetica", "", 8)
	setTextHex(pdf, colMuted)
	pdf.MultiCell(170, 5,
		"SME-Shield checks each open service against the NIST National Vulnerability Database (NVD) - "+
			"a global register of known security weaknesses. Critical weaknesses reduce your score more than minor ones. "+
			"A score of 80 or above means your device is in good shape.",
		"", "L", false)

	pdf.Ln(6)

	pdf.SetFont("Helvetica", "B", 9)
	setTextHex(pdf, colDark)
	pdf.CellFormat(0, 7, "Score Guide:", "", 1, "L", false, 0, "")

	bands := [][]string{
		{"80-100", "Secure", "Device is well-maintained. Keep applying updates regularly.", colGreen},
		{"60-79", "Moderate Risk", "Some issues found. Apply updates within the next 2 weeks.", colAmber},
		{"30-59", "High Risk", "Multiple vulnerabilities present. Address within 48 hours.", colOrange},
		{"0-29", "Critical", "Serious exposure detected. Take immediate action today.", colRed},
	}

	for _, b := range bands {
		setFillHex(pdf, b[3])
		pdf.Rect(16, pdf.GetY()+2, 3, 5, "F")
		pdf.SetX(22)
		pdf.SetFont("Helvetica", "B", 9)
		setTextHex(pdf, colDark)
		pdf.CellFormat(18, 7, b[0], "", 0, "L", false, 0, "")
		setFillHex(pdf, b[3])
		setTextHex(pdf, "#FFFFFF")
		pdf.CellFormat(24, 6, " "+b[1]+" ", "", 0, "C", true, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		setTextHex(pdf, colMuted)
		pdf.CellFormat(0, 7, "  "+b[2], "", 1, "L", false, 0, "")
	}

	pdf.Ln(3)
	hRule(pdf)
}

func drawPortTable(pdf *gofpdf.Fpdf, ports []PortRow) {
	sectionTitle(pdf, "Open Services Detected")

	pdf.SetFont("Helvetica", "", 9)
	setTextHex(pdf, colMuted)
	pdf.MultiCell(0, 5,
		"Every service listed below is a program running on the device that accepts network connections. "+
			"Each one is a potential entry point for attackers. Services with known weaknesses are flagged.",
		"", "L", false)
	pdf.Ln(2)

	if len(ports) == 0 {
		setFillHex(pdf, colBgGreen)
		pdf.RoundedRect(16, pdf.GetY(), 178, 12, 3, "1234", "F")
		pdf.SetFont("Helvetica", "B", 9)
		setTextHex(pdf, colGreen)
		pdf.CellFormat(0, 12, "   No open services found - this device has a minimal attack surface.", "", 1, "L", false, 0, "")
		return
	}

	colW := []float64{16, 26, 36, 30, 16, 64}
	headers := []string{"Port", "Service", "Software", "Version", "Issues", "Plain-English Risk"}

	setFillHex(pdf, colDark)
	setTextHex(pdf, "#FFFFFF")
	pdf.SetFont("Helvetica", "B", 8)
	for i, h := range headers {
		pdf.CellFormat(colW[i], 8, h, "0", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 8)
	for i, p := range ports {
		if i%2 == 0 {
			setFillHex(pdf, colLight)
		} else {
			setFillHex(pdf, "#FFFFFF")
		}

		setTextHex(pdf, colDark)
		pdf.CellFormat(colW[0], 7, fmt.Sprintf("%d", p.Port), "0", 0, "C", true, 0, "")
		pdf.CellFormat(colW[1], 7, p.Service, "0", 0, "L", true, 0, "")
		pdf.CellFormat(colW[2], 7, truncate(p.Product, 20), "0", 0, "L", true, 0, "")
		pdf.CellFormat(colW[3], 7, truncate(p.Version, 16), "0", 0, "L", true, 0, "")

		setFillHex(pdf, portRiskHex(p.CVECount))
		setTextHex(pdf, "#FFFFFF")
		pdf.CellFormat(colW[4], 7, fmt.Sprintf("%d", p.CVECount), "0", 0, "C", true, 0, "")

		if i%2 == 0 {
			setFillHex(pdf, colLight)
		} else {
			setFillHex(pdf, "#FFFFFF")
		}
		setTextHex(pdf, colMuted)
		pdf.CellFormat(colW[5], 7, truncate(portRiskPlainText(p), 46), "0", 1, "L", true, 0, "")
	}

	pdf.Ln(2)
	hRule(pdf)
}

func drawRecommendations(pdf *gofpdf.Fpdf, data Data) {
	var risky []PortRow
	for _, p := range data.Ports {
		if p.CVECount > 0 {
			risky = append(risky, p)
		}
	}

	sectionTitle(pdf, "Recommended Actions")

	if len(risky) == 0 {
		pdf.SetFont("Helvetica", "", 10)
		setTextHex(pdf, colDark)
		pdf.MultiCell(0, 6,
			"No immediate actions required. To stay secure:\n"+
				"  1. Apply all operating system and software updates monthly.\n"+
				"  2. Run SME-Shield once a month to check for new vulnerabilities.\n"+
				"  3. Disable any services you no longer use.",
			"", "L", false)
		return
	}

	pdf.SetFont("Helvetica", "", 9)
	setTextHex(pdf, colMuted)
	pdf.MultiCell(0, 5,
		"The services below have known security weaknesses. Actions are listed by priority - start from number 1.",
		"", "L", false)
	pdf.Ln(3)

	for i, p := range risky {
		badgeCol := portRiskHex(p.CVECount)
		setFillHex(pdf, badgeCol)
		pdf.Circle(21, pdf.GetY()+4, 4, "F")
		setTextHex(pdf, "#FFFFFF")
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetXY(17, pdf.GetY())
		pdf.CellFormat(9, 8, fmt.Sprintf("%d", i+1), "", 0, "C", false, 0, "")

		pdf.SetFont("Helvetica", "B", 10)
		setTextHex(pdf, colDark)
		pdf.CellFormat(0, 8,
			fmt.Sprintf("Fix %s (Port %d) - %d known issue(s)", p.Service, p.Port, p.CVECount),
			"", 1, "L", false, 0, "")

		pdf.SetX(26)
		pdf.SetFont("Helvetica", "", 9)
		setTextHex(pdf, colMuted)
		pdf.MultiCell(168, 5, actionAdvice(p), "", "L", false)
		pdf.Ln(3)
	}

	// Tip box
	pdf.Ln(1)
	setFillHex(pdf, colBgBlue)
	boxY := pdf.GetY()
	pdf.RoundedRect(16, boxY, 178, 30, 3, "1234", "F")
	pdf.SetXY(20, boxY+3)
	pdf.SetFont("Helvetica", "B", 9)
	setTextHex(pdf, colAccent)
	pdf.CellFormat(0, 6, "General Security Advice for Your Business", "", 1, "L", false, 0, "")
	pdf.SetX(20)
	pdf.SetFont("Helvetica", "", 8)
	setTextHex(pdf, colDark)
	pdf.MultiCell(170, 5,
		"1. Keep all software updated - most attacks exploit known weaknesses that updates already fix.\n"+
			"2. If a service is not being used, turn it off - fewer open ports means fewer ways in.\n"+
			"3. Change default passwords on all routers, printers, and servers.\n"+
			"4. Run this audit monthly and share the report with your IT support person.",
		"", "L", false)
}

func drawFooter(pdf *gofpdf.Fpdf, data Data) {
	pdf.Ln(8)
	hRule(pdf)
	pdf.SetFont("Helvetica", "I", 7)
	setTextHex(pdf, "#94A3B8")
	pdf.MultiCell(0, 4,
		"This report was generated automatically by SME-Shield. Vulnerability data is sourced from the NIST National "+
			"Vulnerability Database (nvd.nist.gov). This report is intended as guidance for non-technical business owners "+
			"and does not constitute a full penetration test. Consult a qualified cybersecurity professional before making "+
			"changes to production systems. SME-Shield is not liable for actions taken based on this report.",
		"", "C", false)
	pdf.Ln(2)
	setTextHex(pdf, "#CBD5E1")
	pdf.CellFormat(0, 5,
		fmt.Sprintf("SME-Shield  |  Report SCN-%04d  |  %s",
			data.ScanID,
			data.ScanTime.In(eat).Format("02 Jan 2006")),
		"", 0, "C", false, 0, "")
}

// ── Plain-English generators ──────────────────────────────────────────────────

func plainEnglishScore(score, portCount int) string {
	switch {
	case score >= 80:
		return fmt.Sprintf(
			"Good news - this device scored %d out of 100, which means it is in a healthy security state. "+
				"No critical vulnerabilities were found among the %d service(s) running on it. "+
				"Continue applying software updates regularly and re-run this audit monthly to maintain this status.",
			score, portCount)
	case score >= 60:
		return fmt.Sprintf(
			"This device scored %d out of 100, indicating a moderate level of risk. "+
				"Some of the %d service(s) running on this device have known security weaknesses. "+
				"These are not emergencies, but they should be addressed within the next 1 to 2 weeks "+
				"by applying the software updates listed in the Recommended Actions section below.",
			score, portCount)
	case score >= 30:
		return fmt.Sprintf(
			"This device scored %d out of 100, which is a HIGH RISK rating. "+
				"Several serious vulnerabilities were found across the %d service(s) running on this device. "+
				"An attacker on the same network could potentially access or damage this device. "+
				"Please follow the recommendations below within 48 hours and contact your IT support.",
			score, portCount)
	default:
		return fmt.Sprintf(
			"URGENT: This device scored %d out of 100, which is a CRITICAL rating. "+
				"This device has serious, well-known security weaknesses that are actively exploited by attackers worldwide. "+
				"It should be disconnected from the network or patched immediately. "+
				"Do not store sensitive business data on this device until the issues below are resolved. "+
				"Contact your IT support provider today.",
			score)
	}
}

func portRiskPlainText(p PortRow) string {
	if p.CVECount == 0 {
		return "No known issues - keep software updated"
	}
	switch {
	case p.CVECount <= 2:
		return fmt.Sprintf("%d minor issue(s) - update %s when possible", p.CVECount, p.Product)
	case p.CVECount <= 5:
		return fmt.Sprintf("%d issues found - update %s within 2 weeks", p.CVECount, p.Product)
	default:
		return fmt.Sprintf("%d issues - update %s immediately", p.CVECount, p.Product)
	}
}

func actionAdvice(p PortRow) string {
	base := fmt.Sprintf(
		"The %s service (running as %s %s) has %d known security issue(s). ",
		p.Service, p.Product, p.Version, p.CVECount,
	)
	switch strings.ToLower(p.Service) {
	case "ssh":
		return base + "Update OpenSSH to the latest version. Disable password login and use SSH keys only. " +
			"If remote access is not needed, disable this service entirely."
	case "http", "http-alt":
		return base + "Update your web server software (" + p.Product + ") to the latest stable version. " +
			"If this device does not serve web pages, disable the web server."
	case "https", "https-alt":
		return base + "Update your web server (" + p.Product + ") and renew your SSL certificate if it is older than 1 year."
	case "ftp":
		return base + "FTP sends passwords in plain text. Replace it with SFTP immediately. " +
			"If file transfer is not needed, disable this service."
	case "telnet":
		return base + "Telnet is extremely insecure - all data including passwords travel in plain text. " +
			"Disable Telnet immediately and use SSH instead."
	case "mysql", "postgresql", "mssql":
		return base + "Your database should never be directly accessible from the network. " +
			"Configure it to only accept local connections (127.0.0.1). Update to the latest version."
	case "rdp":
		return base + "Remote Desktop (RDP) is a common attack target. Restrict it to trusted IP addresses only " +
			"using your firewall, and ensure all Windows updates are applied."
	case "smb", "netbios":
		return base + "File sharing (SMB) vulnerabilities can allow attackers to take full control of a device. " +
			"Apply all Windows security updates immediately and disable SMBv1 if enabled."
	case "redis":
		return base + "Redis has no password protection by default. Set a strong password and configure it " +
			"to only accept local connections."
	case "vnc":
		return base + "Remote desktop (VNC) should never be exposed directly to the network. " +
			"Use a VPN or SSH tunnel to access it remotely and set a strong VNC password."
	default:
		return base + fmt.Sprintf("Update %s to the latest available version. If this service is not actively "+
			"needed, consider disabling it to reduce your attack surface.", p.Product)
	}
}

// ── Shared drawing helpers ────────────────────────────────────────────────────

func sectionTitle(pdf *gofpdf.Fpdf, title string) {
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "B", 11)
	setTextHex(pdf, colAccent)
	pdf.CellFormat(0, 8, title, "", 1, "L", false, 0, "")
	pdf.Ln(1)
}

func hRule(pdf *gofpdf.Fpdf) {
	setDrawHex(pdf, colBorder)
	pdf.SetLineWidth(0.3)
	y := pdf.GetY()
	pdf.Line(16, y, 194, y)
	pdf.Ln(4)
}

func setFillHex(pdf *gofpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetFillColor(r, g, b)
}

func setTextHex(pdf *gofpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetTextColor(r, g, b)
}

func setDrawHex(pdf *gofpdf.Fpdf, hex string) {
	r, g, b := hexToRGB(hex)
	pdf.SetDrawColor(r, g, b)
}

func hexToRGB(hex string) (int, int, int) {
	if len(hex) > 0 && hex[0] == '#' {
		hex = hex[1:]
	}
	if len(hex) != 6 {
		return 0, 0, 0
	}
	var r, g, b int
	fmt.Sscanf(hex[0:2], "%x", &r)
	fmt.Sscanf(hex[2:4], "%x", &g)
	fmt.Sscanf(hex[4:6], "%x", &b)
	return r, g, b
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

func scoreLabel(score int) string {
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

func portRiskHex(cveCount int) string {
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
	return s[:max-1] + "."
}

func emptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
