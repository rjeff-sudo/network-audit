package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
)

// LoginHandler handles GET /login (show form) and POST /login (submit form).
type LoginHandler struct {
	auth *auth.Auth
}

// NewLoginHandler constructs a LoginHandler.
func NewLoginHandler(a *auth.Auth) *LoginHandler {
	return &LoginHandler{auth: a}
}

// ServeHTTP routes GET and POST for /login.
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.showForm(w, r)
	case http.MethodPost:
		h.handleSubmit(w, r)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// showForm serves the login page HTML.
func (h *LoginHandler) showForm(w http.ResponseWriter, r *http.Request) {
	// If already logged in, go straight to the dashboard.
	if h.auth.IsAuthenticated(r) {
		http.Redirect(w, r, "/index.html", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./ui/login.html")
}

// handleSubmit processes the login form POST.
// Accepts both application/x-www-form-urlencoded (HTML form)
// and application/json (fetch from JS).
func (h *LoginHandler) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var username, password string

	ct := r.Header.Get("Content-Type")
	if ct == "application/json" || ct == "application/json; charset=utf-8" {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		username = body.Username
		password = body.Password
	} else {
		// Standard HTML form POST
		if err := r.ParseForm(); err != nil {
			jsonError(w, "could not parse form", http.StatusBadRequest)
			return
		}
		username = r.FormValue("username")
		password = r.FormValue("password")
	}

	if !h.auth.CheckCredentials(username, password) {
		// Wrong credentials — redirect back with error flag
		http.Redirect(w, r, "/login?error=1", http.StatusFound)
		return
	}

	// Correct — set session cookie and go to dashboard
	h.auth.SetSession(w)
	http.Redirect(w, r, "/index.html", http.StatusFound)
}

// Logout handles GET /logout — clears the session and redirects to login.
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.auth.ClearSession(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}