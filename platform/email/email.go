// Package email sends transactional emails via SMTP (Gmail-compatible).
package email

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
	"time"
)

// Config holds SMTP settings from config.yaml.
type Config struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	FromAddress string `yaml:"from_address"`
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

// IsConfigured returns true if SMTP settings are present.
func (c *Client) IsConfigured() bool {
	return c.cfg.Host != "" && c.cfg.Username != "" && c.cfg.FromAddress != ""
}
