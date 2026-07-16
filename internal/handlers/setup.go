package handlers

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
)

// SetupHandler handles the first-run account creation flow.
type SetupHandler struct {
	auth *auth.Auth
}

// NewSetupHandler constructs a SetupHandler.
func NewSetupHandler(a *auth.Auth) *SetupHandler {
	return &SetupHandler{auth: a}
}

// ServeHTTP routes GET /setup (show page) and POST /api/setup (create user).
func (h *SetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If setup already done, redirect to login
	if h.auth.IsSetupDone() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// Read and serve setup.html directly to avoid Go's 301 redirect on .html
	data, err := os.ReadFile("./ui/setup.html")
	if err != nil {
		http.Error(w, "setup page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// Create handles POST /api/setup — creates the admin user.
func (h *SetupHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Block if setup already done
	if h.auth.IsSetupDone() {
		jsonError(w, "setup already completed", http.StatusForbidden)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.auth.CreateUser(body.Username, body.Password); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonOK(w, map[string]string{"status": "ok"})
}