// Package auth handles session-based authentication for SME-Shield.
// Passwords are hashed with bcrypt and stored in SQLite.
// Sessions use HMAC-SHA256 signed cookies — no external dependencies.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName  = "sme_session"
	bcryptCost  = 12 // work factor — higher = slower = harder to brute force
)

// Config holds auth settings from config.yaml.
type Config struct {
	SessionSecret   string `yaml:"session_secret"`
	SessionTTLHours int    `yaml:"session_ttl_hours"`
}

// Auth handles all authentication logic.
type Auth struct {
	cfg Config
	db  *sql.DB
}

// New creates an Auth instance.
func New(cfg Config, db *sql.DB) *Auth {
	return &Auth{cfg: cfg, db: db}
}

// ── Setup ─────────────────────────────────────────────────────────────────────

// IsSetupDone returns true if at least one user exists in the database.
func (a *Auth) IsSetupDone() bool {
	var count int
	a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count > 0
}

// CreateUser hashes the password with bcrypt and inserts a new user.
// Returns an error if the username already exists.
func (a *Auth) CreateUser(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = a.db.Exec(
		`INSERT INTO users (username, password_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?)`,
		username, string(hash), now, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("username already exists")
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// ── Login ─────────────────────────────────────────────────────────────────────

// CheckCredentials returns true if username exists and password matches the hash.
func (a *Auth) CheckCredentials(username, password string) bool {
	var hash string
	err := a.db.QueryRow(
		`SELECT password_hash FROM users WHERE username = ?`, username).
		Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ── Password change ───────────────────────────────────────────────────────────

// ChangePassword verifies the current password then updates the hash.
func (a *Auth) ChangePassword(username, currentPassword, newPassword string) error {
	if !a.CheckCredentials(username, currentPassword) {
		return fmt.Errorf("current password is incorrect")
	}
	if len(newPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = a.db.Exec(
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`,
		string(hash), now, username,
	)
	return err
}

// GetUsername returns the username of the first (and only) user.
func (a *Auth) GetUsername() string {
	var username string
	a.db.QueryRow(`SELECT username FROM users LIMIT 1`).Scan(&username)
	return username
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// SetSession writes a signed session cookie to the response.
func (a *Auth) SetSession(w http.ResponseWriter) {
	nonce := randomHex(16)
	ts    := fmt.Sprintf("%d", time.Now().Unix())
	raw   := nonce + ":" + ts
	sig   := a.sign(raw)
	value := raw + ":" + sig

	ttl := a.cfg.SessionTTLHours
	if ttl == 0 {
		ttl = 168
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   ttl * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSession removes the session cookie.
func (a *Auth) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// IsAuthenticated returns true if the request has a valid unexpired session.
func (a *Auth) IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return a.validateToken(cookie.Value)
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Middleware protects all routes, redirecting unauthenticated requests.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Always public — setup, login, logout, landing, static assets
		if path == "/setup" || path == "/api/setup" ||
			path == "/login" || path == "/logout" ||
			path == "/landing.html" || isPublicAsset(path) {
			next.ServeHTTP(w, r)
			return
		}

		// If setup not done, force setup page
		if !a.IsSetupDone() {
			if strings.HasPrefix(path, "/api/") || path == "/ws" {
				jsonUnauthorized(w)
				return
			}
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		// Check session
		if a.IsAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Not authenticated
		if strings.HasPrefix(path, "/api/") || path == "/ws" {
			jsonUnauthorized(w)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (a *Auth) sign(data string) string {
	mac := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *Auth) validateToken(value string) bool {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 {
		return false
	}
	raw         := parts[0] + ":" + parts[1]
	expectedSig := a.sign(raw)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return false
	}
	var ts int64
	fmt.Sscanf(parts[1], "%d", &ts)
	ttl := a.cfg.SessionTTLHours
	if ttl == 0 {
		ttl = 168
	}
	expiry := time.Unix(ts, 0).Add(time.Duration(ttl) * time.Hour)
	return time.Now().Before(expiry)
}

func isPublicAsset(path string) bool {
	for _, ext := range []string{".css", ".js", ".ico", ".png", ".jpg", ".svg", ".woff", ".woff2"} {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func jsonUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthorized"}`))
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}