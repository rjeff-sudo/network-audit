package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/rjeff-sudo/sme-shield/internal/auth"
	"github.com/rjeff-sudo/sme-shield/platform/email"
)

// RegisterHandler handles open self-registration (GET /register, POST /api/register).
// Accounts are created unverified; the owner must click the verification
// email link before they can log in.
type RegisterHandler struct {
	auth      *auth.Auth
	emailCli  *email.Client
	serverURL string
}

// NewRegisterHandler constructs a RegisterHandler.
func NewRegisterHandler(a *auth.Auth, emailCli *email.Client, serverURL string) *RegisterHandler {
	return &RegisterHandler{auth: a, emailCli: emailCli, serverURL: serverURL}
}

// ServeHTTP routes GET /register (show page) and POST /api/register (create account).
func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// First-run setup must happen before anyone can register.
	if !h.auth.IsSetupDone() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	data, err := os.ReadFile("./ui/register.html")
	if err != nil {
		http.Error(w, "register page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// Create handles POST /api/register — creates an unverified account and
// emails the verification link.
func (h *RegisterHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Email verification is the registration gate — without SMTP configured,
	// nobody could ever verify, so registration is unavailable.
	if h.emailCli == nil || !h.emailCli.IsConfigured() {
		jsonError(w, "registration is unavailable — the email verification system is not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.auth.Register(body.Username, body.Password, body.Email)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.emailCli.SendVerification(body.Email, token, h.serverURL); err != nil {
		log.Printf("[register] verification email to %s: %v", body.Email, err)
		jsonError(w, "account created but the verification email failed to send — please try registering again", http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{
		"status":  "ok",
		"message": "Account created — check your email and click the verification link before signing in.",
	})
}
