// Package email sends transactional emails via SMTP (Gmail-compatible).
package email

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
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
	subject := "Verify your email — SME-Shield"
	body := fmt.Sprintf(
		"Hi,\n\nPlease verify your email address by clicking the link below:\n\n"+
			"%s\n\nThis link will expire in 24 hours.\n\n"+
			"If you did not create an account, you can ignore this email.\n\n"+
			"— SME-Shield", link)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		c.cfg.FromAddress, toEmail, subject, body)

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
