// Package auth handles session-based authentication for SME-Shield.
// It uses a signed cookie (HMAC-SHA256) — no external dependencies needed.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const cookieName = "sme_session"

// Config holds the auth credentials loaded from config.yaml.
type Config struct {
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	SessionSecret  string `yaml:"session_secret"`
	SessionTTLHours int   `yaml:"session_ttl_hours"`
}

// Auth handles login checks and session management.
type Auth struct {
	cfg Config
}

// New creates an Auth instance.
func New(cfg Config) *Auth {
	return &Auth{cfg: cfg}
}

// CheckCredentials returns true if the username and password are correct.
func (a *Auth) CheckCredentials(username, password string) bool {
	return username == a.cfg.Username && password == a.cfg.Password
}

// SetSession writes a signed session cookie to the response.
func (a *Auth) SetSession(w http.ResponseWriter) {
	// token = random_nonce:timestamp:hmac
	nonce := randomHex(16)
	ts    := fmt.Sprintf("%d", time.Now().Unix())
	raw   := nonce + ":" + ts
	sig   := a.sign(raw)
	value := raw + ":" + sig

	ttl := a.cfg.SessionTTLHours
	if ttl == 0 {
		ttl = 24
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   ttl * 3600,
		HttpOnly: true,  // not accessible from JS — XSS protection
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

// IsAuthenticated returns true if the request has a valid session cookie.
func (a *Auth) IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return a.validateToken(cookie.Value)
}

// Middleware wraps a handler and redirects to /login if not authenticated.
// API routes return 401 JSON instead of redirecting.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow the login page and its POST handler
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Always allow static assets (CSS, JS, fonts)
		if isPublicAsset(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if a.IsAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}

		// API routes — return 401 JSON
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/ws") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		// All other routes — redirect to login
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
	raw := parts[0] + ":" + parts[1]
	expectedSig := a.sign(raw)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return false
	}

	// Check expiry
	var ts int64
	fmt.Sscanf(parts[1], "%d", &ts)
	ttl := a.cfg.SessionTTLHours
	if ttl == 0 {
		ttl = 24
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
	// Landing page is public
	if path == "/landing.html" {
		return true
	}
	return false
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}