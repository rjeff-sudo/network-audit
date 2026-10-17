package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
	"github.com/rjeff-sudo/sme-shield/platform/email"
)

// SettingsHandler handles user settings endpoints.
type SettingsHandler struct {
	auth      *auth.Auth
	emailCli  *email.Client
	serverURL string
}

// NewSettingsHandler constructs a SettingsHandler.
func NewSettingsHandler(a *auth.Auth, emailCli *email.Client, serverURL string) *SettingsHandler {
	return &SettingsHandler{auth: a, emailCli: emailCli, serverURL: serverURL}
}

// ChangePassword handles POST /api/settings/password
func (h *SettingsHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if body.CurrentPassword == "" || body.NewPassword == "" {
		jsonError(w, "current_password and new_password are required", http.StatusBadRequest)
		return
	}

	username := auth.UserFromContext(r.Context())
	if err := h.auth.ChangePassword(username, body.CurrentPassword, body.NewPassword); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]string{"status": "password changed"})
}

// EmailStatus handles GET /api/settings/email-status and POST to save email
func (h *SettingsHandler) EmailStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		username := auth.UserFromContext(r.Context())
		email := h.auth.GetEmail(username)
		verified := h.auth.IsEmailVerified(username)
		smtpConfigured := h.emailCli != nil && h.emailCli.IsConfigured()

		jsonOK(w, map[string]interface{}{
			"email":           email,
			"verified":        verified,
			"smtp_configured": smtpConfigured,
		})

	case http.MethodPost:
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if body.Email == "" {
			jsonError(w, "email is required", http.StatusBadRequest)
			return
		}
		username := auth.UserFromContext(r.Context())
		if err := h.auth.SetEmail(username, body.Email); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send verification email if SMTP is configured
		if h.emailCli != nil && h.emailCli.IsConfigured() {
			token, err := h.auth.SendVerification(username)
			if err != nil {
				log.Printf("[settings] send verification error: %v", err)
			} else {
				if err := h.emailCli.SendVerification(body.Email, token, h.serverURL); err != nil {
					log.Printf("[settings] email send error: %v", err)
				}
			}
		}

		jsonOK(w, map[string]string{"status": "email saved"})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ResendVerification handles POST /api/settings/resend-verification
func (h *SettingsHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := auth.UserFromContext(r.Context())
	email := h.auth.GetEmail(username)
	if email == "" {
		jsonError(w, "no email address set", http.StatusBadRequest)
		return
	}
	if h.auth.IsEmailVerified(username) {
		jsonOK(w, map[string]string{"status": "already verified"})
		return
	}
	if h.emailCli == nil || !h.emailCli.IsConfigured() {
		jsonError(w, "SMTP is not configured — cannot send email", http.StatusBadRequest)
		return
	}

	token, err := h.auth.SendVerification(username)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.emailCli.SendVerification(email, token, h.serverURL); err != nil {
		log.Printf("[settings] resend verification error: %v", err)
		jsonError(w, "failed to send email", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"status": "verification email sent"})
}
