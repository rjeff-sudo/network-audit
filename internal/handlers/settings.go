package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
)

// SettingsHandler handles user settings endpoints.
type SettingsHandler struct {
	auth *auth.Auth
}

// NewSettingsHandler constructs a SettingsHandler.
func NewSettingsHandler(a *auth.Auth) *SettingsHandler {
	return &SettingsHandler{auth: a}
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

	username := h.auth.GetUsername()
	if err := h.auth.ChangePassword(username, body.CurrentPassword, body.NewPassword); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]string{"status": "password changed"})
}
