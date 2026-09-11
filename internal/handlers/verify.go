package handlers

import (
	"net/http"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
)

// VerifyHandler handles email verification links.
type VerifyHandler struct {
	auth *auth.Auth
}

// NewVerifyHandler constructs a VerifyHandler.
func NewVerifyHandler(a *auth.Auth) *VerifyHandler {
	return &VerifyHandler{auth: a}
}

// VerifyEmail handles GET /api/verify-email?token=xxx
func (h *VerifyHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, "/login?error=missing_token", http.StatusFound)
		return
	}

	if err := h.auth.VerifyEmail(token); err != nil {
		http.Redirect(w, r, "/login?error=invalid_token", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/index.html?verified=1", http.StatusFound)
}
