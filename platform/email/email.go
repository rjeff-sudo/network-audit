// Package email sends transactional emails via SMTP (Gmail-compatible).
package email

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

// Config holds SMTP settings from config.yaml.
type Config struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	FromAddress string `yaml:"from_address"`
	// Resend API key (loaded from RESEND_API_KEY env var if empty in config).
	ResendAPIKey string `yaml:"resend_api_key"`
}

// Client sends emails via SMTP.
type Client struct {
	cfg Config
}

// NewClient creates an email Client.
func NewClient(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// SendVerification sends a verification email with a one-time link.
func (c *Client) SendVerification(toEmail, token, baseURL string) error {
	if c.cfg.Host == "" || c.cfg.Username == "" {
		log.Printf("[email] SMTP not configured — skipping verification email to %s", toEmail)
		return nil
	}

	link := fmt.Sprintf("%s/api/verify-email?token=%s", baseURL, token)
	subject := "Verify your email address for Sentry"
	boundary := fmt.Sprintf("=_boundary_%d", time.Now().UnixNano())

	// Plain-text body
	textBody := fmt.Sprintf(
		"Hi,\r\n\r\n"+
			"Please verify your email address for your Sentry account.\r\n\r\n"+
			"Click the link below to verify:\r\n\r\n"+
			"%s\r\n\r\n"+
			"This link will expire in 24 hours.\r\n\r\n"+
			"If you did not create an Sentry account, you can safely ignore this email.\r\n\r\n"+
			"— The Sentry Team\r\n", link)

	// HTML body (helps with spam scoring — legitimate emails usually have both)
	htmlBody := fmt.Sprintf(
		"<html><body style=\"font-family:sans-serif;font-size:14px;color:#333\">\r\n"+
			"<p>Hi,</p>\r\n"+
			"<p>Please verify your email address for your Sentry account.</p>\r\n"+
			"<p><a href=\"%s\" style=\"display:inline-block;padding:10px 24px;background:#200f0a;color:#a2f6f5;border-radius:999px;text-decoration:none\">Verify Email</a></p>\r\n"+
			"<p style=\"font-size:12px;color:#999\">This link expires in 24 hours. If you did not create an account, ignore this email.</p>\r\n"+
			"</body></html>\r\n", link)

	msg := fmt.Sprintf(
		"From: Sentry <%s>\r\n"+
			"To: %s\r\n"+
			"Reply-To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: multipart/alternative; boundary=\"%s\"\r\n"+
			"X-Mailer: Sentry\r\n"+
			"List-Unsubscribe: <mailto:%s?subject=unsubscribe>\r\n"+
			"Precedence: bulk\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n"+
			"%s\r\n"+
			"--%s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n"+
			"%s\r\n"+
			"--%s--\r\n",
		c.cfg.FromAddress, toEmail, c.cfg.FromAddress,
		subject, boundary,
		c.cfg.FromAddress,
		boundary, textBody,
		boundary, htmlBody,
		boundary)

	addr := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)
	auth := smtp.PlainAuth("", c.cfg.Username, c.cfg.Password, c.cfg.Host)

	// Gmail requires TLS on port 587 (STARTTLS) or 465 (implicit TLS).
	// We use crypto/tls to establish a TLS connection directly.
	if c.cfg.Port == 465 {
		return c.sendTLS(addr, auth, toEmail, msg)
	}
	return smtp.SendMail(addr, auth, c.cfg.FromAddress, []string{toEmail}, []byte(msg))
}

// sendTLS connects with explicit TLS (port 465).
func (c *Client) sendTLS(addr string, auth smtp.Auth, to, msg string) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: c.cfg.Host,
	})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err = client.Mail(c.cfg.FromAddress); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err = w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err = w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}

	return client.Quit()
}

// SendReport emails a PDF audit report to the given address.
func (c *Client) SendReport(toEmail string, pdf []byte, ip string, scanTime time.Time) error {
	if c.cfg.ResendAPIKey != "" {
		return c.sendReportResend(toEmail, pdf, ip, scanTime)
	}
	return c.sendReportSMTP(toEmail, pdf, ip, scanTime)
}

// sendReportSMTP emails a PDF audit report to the given address via SMTP.
func (c *Client) sendReportSMTP(toEmail string, pdf []byte, ip string, scanTime time.Time) error {
	if c.cfg.Host == "" || c.cfg.Username == "" {
		log.Printf("[email] SMTP not configured - skipping report email to %s", toEmail)
		return nil
	}

	subject := fmt.Sprintf("Sentry Security Report - %s", ip)
	boundary := fmt.Sprintf("=_boundary_%d", time.Now().UnixNano())

	textBody := fmt.Sprintf(
		"Hi,\r\n\r\n"+
			"Your Sentry network security audit report for %s is attached.\r\n\r\n"+
			"Report generated: %s\r\n\r\n"+
			"- The Sentry Team\r\n", ip, scanTime.UTC().Format("02 Jan 2006, 15:04 MST"))

	htmlBody := fmt.Sprintf(
		"<html><body style=\"font-family:sans-serif;font-size:14px;color:#333\">\r\n"+
			"<p>Hi,</p>\r\n"+
			"<p>Your Sentry network security audit report for <strong>%s</strong> is attached.</p>\r\n"+
			"<p>Report generated: %s</p>\r\n"+
			"<p style=\"font-size:12px;color:#999\">- The Sentry Team</p>\r\n"+
			"</body></html>\r\n", ip, scanTime.UTC().Format("02 Jan 2006, 15:04 MST"))

	// Encode the PDF as base64 with RFC 2045 line wrapping.
	pdfB64 := base64.StdEncoding.EncodeToString(pdf)
	var wrapped bytes.Buffer
	for i := 0; i < len(pdfB64); i += 76 {
		end := i + 76
		if end > len(pdfB64) {
			end = len(pdfB64)
		}
		wrapped.WriteString(pdfB64[i:end])
		wrapped.WriteString("\r\n")
	}

	msg := fmt.Sprintf(
		"From: Sentry <%s>\r\n"+
			"To: %s\r\n"+
			"Reply-To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: multipart/mixed; boundary=\"%s\"\r\n"+
			"X-Mailer: Sentry\r\n"+
			"Precedence: bulk\r\n"+
			"\r\n"+
			"--%s\r\n"+
			"Content-Type: multipart/alternative; boundary=\"%s.inner\"\r\n"+
			"\r\n"+
			"--%s.inner\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n%s\r\n"+
			"--%s.inner\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"Content-Transfer-Encoding: 7bit\r\n"+
			"\r\n%s\r\n"+
			"--%s.inner--\r\n"+
			"Content-Type: application/pdf; name=\"Sentry-report-%s.pdf\"\r\n"+
			"Content-Disposition: attachment; filename=\"Sentry-report-%s.pdf\"\r\n"+
			"Content-Transfer-Encoding: base64\r\n"+
			"\r\n%s--%s--\r\n",
		c.cfg.FromAddress, toEmail, c.cfg.FromAddress,
		subject, boundary,
		boundary,
		textBody,
		boundary,
		htmlBody,
		boundary,
		"Sentry-report-"+ip+".pdf", "Sentry-report-"+ip+".pdf",
		wrapped.String(), boundary)

	addr := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)
	auth := smtp.PlainAuth("", c.cfg.Username, c.cfg.Password, c.cfg.Host)

	if c.cfg.Port == 465 {
		return c.sendTLS(addr, auth, toEmail, msg)
	}
	return smtp.SendMail(addr, auth, c.cfg.FromAddress, []string{toEmail}, []byte(msg))
}

// sendReportResend sends the audit PDF via the Resend API.
//
// Resend supports attachments via the "attachment" property in the email payload.
// However, the simplest approach for now is to embed a download link in the email
// body, since Resend's free tier attachment handling may require a paid plan.
// We'll include a link to the report download endpoint instead.
func (c *Client) sendReportResend(toEmail string, pdf []byte, ip string, scanTime time.Time) error {
	// For now, embed a link to the report download API endpoint.
	// The frontend can fetch /api/report/{id} if needed; we just include a placeholder link.
	reportLink := fmt.Sprintf("http://localhost:8080/api/report/%s", ip) // TODO: use real report ID

	htmlBody := fmt.Sprintf(
		"<html><body style=\"font-family:sans-serif;font-size:14px;color:#333\">\r\n"+
			"<p>Hi,</p>\r\n"+
			"<p>Your Sentry network security audit report is ready.</p>\r\n"+
			"<p>Download the report: <a href=\"%s\">Sentry Security Report PDF</a></p>\r\n"+
			"<p style=\"font-size:12px;color:#999\">- The Sentry Team</p>\r\n"+
			"</body></html>\r\n", reportLink)

	apiKey := c.cfg.ResendAPIKey
	if apiKey == "" {
		// fallback to env var
		envKey := os.Getenv("RESEND_API_KEY")
		if envKey != "" {
			apiKey = envKey
		}
	}
	if apiKey == "" {
		log.Printf("[email] Resend API key not set - skipping report email to %s", toEmail)
		return nil
	}

	url := "https://api.resend.com/api/emails"

	reqBody := fmt.Sprintf(`{"from":"Sentry <%s>","to":"%s","subject":"Sentry Security Report","html":"%s"}`, c.cfg.FromAddress, toEmail, htmlBody)

	body := []byte(reqBody)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("resend returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var result struct {
		ID      string `json:"id"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[email] Resend report send OK but could not parse response for %s", toEmail)
	} else {
		log.Printf("[email] Resend report sent to %s, ID=%s", result.Address, result.ID)
	}

	return nil
}

// IsConfigured returns true if SMTP settings are present OR Resend API key is set.
func (c *Client) IsConfigured() bool {
	return c.cfg.Host != "" && c.cfg.Username != "" && c.cfg.FromAddress != "" ||
		c.cfg.ResendAPIKey != ""
}
