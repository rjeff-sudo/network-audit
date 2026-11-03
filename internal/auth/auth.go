// Package auth handles session-based authentication for Sentry.
// Passwords are hashed with bcrypt and stored in SQLite.
// Sessions use HMAC-SHA256 signed cookies that carry the username -
// no external dependencies.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName = "sentry_session"
	bcryptCost = 12 // work factor - higher = slower = harder to brute force
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

// ── Users ─────────────────────────────────────────────────────────────────────

// IsValidUsername enforces the username charset (it is embedded in the
// signed session token, so ':' and whitespace are not allowed).
func IsValidUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, c := range u {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// IsValidEmail performs a lightweight sanity check on an email address.
func IsValidEmail(e string) bool {
	at := strings.Index(e, "@")
	return at > 0 && at < len(e)-1 && !strings.Contains(e, " ") && strings.Contains(e[strings.Index(e, "@"):], ".")
}

// ValidatePassword enforces the password policy shared by setup,
// registration and password change: at least 8 characters with a letter,
// a number and a symbol/special character.
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	var hasLetter, hasDigit, hasSymbol bool
	for _, c := range password {
		switch {
		case unicode.IsLetter(c):
			hasLetter = true
		case unicode.IsDigit(c):
			hasDigit = true
		case c != ' ':
			hasSymbol = true
		}
	}
	if !hasLetter {
		return fmt.Errorf("password must contain at least one letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSymbol {
		return fmt.Errorf("password must contain at least one special character or symbol")
	}
	return nil
}

// CreateUser creates a verified account. Used for the first-run setup flow
// (the person configuring the server is trusted without email verification).
func (a *Auth) CreateUser(username, password, email string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}
	if !IsValidUsername(username) {
		return fmt.Errorf("username must be 3-32 characters (letters, digits, _ . -)")
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = a.db.Exec(
		`INSERT INTO users (username, password_hash, email, email_verified, created_at, updated_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		username, string(hash), email, now, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("username already exists")
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// Register records a pending registration and returns the email verification
// token. No username or email is written to the users table until the owner
// clicks the verification link, so unverified attempts never occupy a username
// or store an email address.
func (a *Auth) Register(username, password, email string) (string, error) {
	if !IsValidUsername(username) {
		return "", fmt.Errorf("username must be 3-32 characters (letters, digits, _ . -)")
	}
	if !IsValidEmail(email) {
		return "", fmt.Errorf("please enter a valid email address")
	}
	if err := ValidatePassword(password); err != nil {
		return "", err
	}

	// Reject a username that is already taken, whether by a verified account
	// or by a pending (unverified) registration.
	if a.usernameTaken(username) {
		return "", fmt.Errorf("that username is already taken")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	token, err := a.insertPendingRegistration(username, string(hash), email)
	if err != nil {
		return "", fmt.Errorf("register user: %w", err)
	}
	return token, nil
}

// IsSetupDone returns true if at least one user exists in the database.
func (a *Auth) IsSetupDone() bool {
	var count int
	a.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count > 0
}

// ── Login ─────────────────────────────────────────────────────────────────────

// CheckCredentials returns true if the username exists, the password matches,
// and the account's email has been verified.
func (a *Auth) CheckCredentials(username, password string) bool {
	var hash string
	var verified int
	err := a.db.QueryRow(
		`SELECT password_hash, email_verified FROM users WHERE username = ?`, username).
		Scan(&hash, &verified)
	if err != nil {
		return false
	}
	if verified != 1 {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// AccountExists returns true if the username is registered (verified or not).
func (a *Auth) AccountExists(username string) bool {
	var n int
	a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&n)
	return n > 0
}

// IsEmailVerifiedFor reports whether a specific account's email is verified.
func (a *Auth) IsEmailVerifiedFor(username string) bool {
	var verified int
	a.db.QueryRow(`SELECT email_verified FROM users WHERE username = ?`, username).Scan(&verified)
	return verified == 1
}

// EmailForID returns the verified email address for a database user id, or empty.
func (a *Auth) EmailForID(userID int64) string {
	var email string
	a.db.QueryRow(`SELECT COALESCE(email, '') FROM users WHERE id = ? AND email_verified = 1`, userID).Scan(&email)
	return email
}

// IsEmailVerifiedForID reports whether the user with the given database id has a
// verified email.
func (a *Auth) IsEmailVerifiedForID(userID int64) bool {
	var verified int
	a.db.QueryRow(`SELECT email_verified FROM users WHERE id = ?`, userID).Scan(&verified)
	return verified == 1
}

// ── Password change ───────────────────────────────────────────────────────────

// ChangePassword verifies the current password then updates the hash.
func (a *Auth) ChangePassword(username, currentPassword, newPassword string) error {
	if !a.CheckCredentials(username, currentPassword) {
		return fmt.Errorf("current password is incorrect")
	}
	if err := ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("new %s", err.Error())
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

// ── Email verification ────────────────────────────────────────────────────────

// insertPendingRegistration stores a registration attempt that has not yet
// been verified. No users-table row is created at this point.
func (a *Auth) insertPendingRegistration(username, passwordHash, email string) (string, error) {
	token := randomHex(32)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	_, err := a.db.Exec(
		`INSERT INTO pending_registrations
		 (email, username, password_hash, verification_token, token_expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		email, username, passwordHash, token, expires,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return "", fmt.Errorf("that username is already taken")
		}
		return "", fmt.Errorf("store pending registration: %w", err)
	}
	return token, nil
}

// completePendingRegistration promotes a pending registration to a real user
// row and removes the pending row. It returns errNoPendingRegistration when the
// token is not found in pending_registrations.
func (a *Auth) completePendingRegistration(token string) error {
	var email, username, passwordHash, expiresStr string
	err := a.db.QueryRow(
		`SELECT email, username, password_hash, token_expires_at
		 FROM pending_registrations
		 WHERE verification_token = ?`,
		token).Scan(&email, &username, &passwordHash, &expiresStr)
	if err == sql.ErrNoRows {
		return errNoPendingRegistration
	}
	if err != nil {
		return fmt.Errorf("lookup pending registration: %w", err)
	}

	expires, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil || time.Now().After(expires) {
		// Token expired - remove the pending row so the username becomes free.
		a.db.Exec(`DELETE FROM pending_registrations WHERE verification_token = ?`, token)
		return fmt.Errorf("verification token has expired")
	}

	// Create the real (verified) user row.
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = a.db.Exec(
		`INSERT INTO users (username, password_hash, email, email_verified, created_at, updated_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		username, passwordHash, email, now, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("that username is already taken")
		}
		return fmt.Errorf("create verified user: %w", err)
	}

	// Remove the pending row - single-use token.
	_, err = a.db.Exec(`DELETE FROM pending_registrations WHERE verification_token = ?`, token)
	return err
}

// verifyLegacyToken handles verification tokens stored on the users table
// (pre-migration or setup-created accounts, or email-change tokens). It returns
// the verified username on success so the caller can promote a pending email.
func (a *Auth) verifyLegacyToken(token string) (string, error) {
	var expiresStr, username string
	err := a.db.QueryRow(
		`SELECT token_expires_at, username FROM users
		 WHERE verification_token = ? AND verification_token != ''`,
		token).Scan(&expiresStr, &username)
	if err == sql.ErrNoRows {
		return "", errNoPendingRegistration
	}
	if err != nil {
		return "", fmt.Errorf("lookup verification token: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, expiresStr)
	if err != nil || time.Now().After(expires) {
		// Token expired - clear it and any stale pending email so the user
		// can retry the change without the old pending email hanging around.
		a.db.Exec(`UPDATE users SET verification_token = '', token_expires_at = '', pending_email = '' WHERE username = ?`, username)
		return "", fmt.Errorf("verification token has expired")
	}
	_, err = a.db.Exec(
		`UPDATE users SET email_verified = 1, verification_token = '', token_expires_at = ''
		 WHERE verification_token = ?`, token)
	if err != nil {
		return "", err
	}
	return username, nil
}

// errNoPendingRegistration is returned by lookups when a token is not present
// in pending_registrations. It is internal; callers translate it to a user error.
var errNoPendingRegistration = fmt.Errorf("no pending registration for token")

// usernameTaken reports whether the username is already used by a verified
// account or by a pending (unverified) registration.
func (a *Auth) usernameTaken(username string) bool {
	var n int
	a.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&n)
	if n > 0 {
		return true
	}
	a.db.QueryRow(`SELECT COUNT(*) FROM pending_registrations WHERE username = ?`, username).Scan(&n)
	return n > 0
}

// RemovePendingRegistrationByUsername deletes a pending registration row
// for the given username. Best-effort; used when the verification email fails
// to send so the username can be retried.
func (a *Auth) RemovePendingRegistrationByUsername(username string) {
	a.db.Exec(`DELETE FROM pending_registrations WHERE username = ?`, username)
}

// CleanupExpiredPendingRegistrations removes pending rows whose token has
// expired. Call it periodically (or at startup) to free the username/email
// those attempts had reserved.
func (a *Auth) CleanupExpiredPendingRegistrations() {
	before := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	res, err := a.db.Exec(`DELETE FROM pending_registrations WHERE token_expires_at < ?`, before)
	if err != nil {
		log.Printf("[auth] cleanup expired pending registrations: %v", err)
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Printf("[auth] cleaned up %d expired pending registrations", n)
	}
}

// GetEmail returns the email address of the given user.
func (a *Auth) GetEmail(username string) string {
	var email string
	a.db.QueryRow(`SELECT COALESCE(email, '') FROM users WHERE username = ?`, username).Scan(&email)
	return email
}

// IsEmailVerified returns true if the given user's email is verified.
func (a *Auth) IsEmailVerified(username string) bool {
	var verified int
	a.db.QueryRow(`SELECT email_verified FROM users WHERE username = ?`, username).Scan(&verified)
	return verified == 1
}

// SetEmail stores an email address for the given user (resets verification).
// It overwrites the current email immediately - use RequestEmailChange when you
// want the old email to stay in place until the new one is verified.
func (a *Auth) SetEmail(username, email string) error {
	_, err := a.db.Exec(
		`UPDATE users SET email = ?, email_verified = 0, verification_token = '', token_expires_at = '', pending_email = '' WHERE username = ?`,
		email, username)
	return err
}

// RequestEmailChange verifies the current password, stores the new email as
// pending_email, and returns a verification token for it. The real email column
// is not touched until the verification link is clicked, so a failed verification
// leaves the original email in place. The caller is responsible for sending the
// verification email using the returned token.
func (a *Auth) RequestEmailChange(username, newEmail, password string) (string, error) {
	if !a.CheckCredentials(username, password) {
		return "", fmt.Errorf("current password is incorrect")
	}
	if !IsValidEmail(newEmail) {
		return "", fmt.Errorf("please enter a valid email address")
	}

	// Normalise the "change to the same email" case: just re-send verification.
	current := a.GetEmail(username)
	if current == newEmail {
		token, err := a.SendVerification(username)
		if err != nil {
			return "", fmt.Errorf("could not create verification token: %w", err)
		}
		return token, nil
	}

	token, err := a.SendVerification(username)
	if err != nil {
		return "", fmt.Errorf("could not create verification token: %w", err)
	}

	// SendVerification already stored a 24h expiry on the users row. Keep it.
	_, err = a.db.Exec(
		`UPDATE users SET pending_email = ? WHERE username = ?`,
		newEmail, username)
	if err != nil {
		return "", fmt.Errorf("store pending email: %w", err)
	}
	return token, nil
}

// PendingEmail returns the pending (not-yet-verified) email for the user, or
// empty if none is set.
func (a *Auth) PendingEmail(username string) string {
	var pe string
	a.db.QueryRow(`SELECT COALESCE(pending_email, '') FROM users WHERE username = ?`, username).Scan(&pe)
	return pe
}

// ConfirmPendingEmail promotes pending_email into the real email column and
// clears pending_email. It is called after a successful verification when a
// pending email change is present.
func (a *Auth) ConfirmPendingEmail(username string) error {
	var pe string
	err := a.db.QueryRow(`SELECT pending_email FROM users WHERE username = ?`, username).Scan(&pe)
	if err != nil {
		return err
	}
	if pe == "" {
		return nil // nothing to promote
	}
	_, err = a.db.Exec(
		`UPDATE users SET email = ?, pending_email = '', email_verified = 1 WHERE username = ?`,
		pe, username)
	return err
}

// SendVerification generates a token for the given user, stores it, and
// returns it for the caller to email.
func (a *Auth) SendVerification(username string) (string, error) {
	email := a.GetEmail(username)
	if email == "" {
		return "", fmt.Errorf("no email address set for user")
	}
	token := randomHex(32)
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	_, err := a.db.Exec(
		`UPDATE users SET verification_token = ?, token_expires_at = ? WHERE username = ?`,
		token, expires, username)
	if err != nil {
		return "", err
	}
	return token, nil
}

// VerifyEmail completes a pending registration if the token is valid and
// unexpired. On success the real user row is created and marked verified; the
// pending row is then removed. When the verified account has a pending email
// change, that pending email is promoted into the real email column.
// Tokens from pending registrations work without a session, so a new registrant
// can click the link before ever signing in.
func (a *Auth) VerifyEmail(token string) error {
	if token == "" {
		return fmt.Errorf("verification token is empty")
	}

	// Try a pending registration first.
	if err := a.completePendingRegistration(token); err == nil {
		return nil
	} else if err != errNoPendingRegistration {
		return err
	}

	// Legacy / email-change path: token on an existing user row.
	if username, err := a.verifyLegacyToken(token); err != nil {
		return err
	} else if username != "" {
		a.ConfirmPendingEmail(username)
	}

	return nil
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// SetSession writes a signed session cookie bound to the given username.
func (a *Auth) SetSession(w http.ResponseWriter, username string) {
	nonce := randomHex(16)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	// Username contains no ':' (validated by IsValidUsername), so ':' is a safe separator.
	raw := nonce + ":" + ts + ":" + username
	sig := a.sign(raw)
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

// IsAuthenticated returns true if the request has a valid, unexpired session.
func (a *Auth) IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	_, ok := a.validateToken(cookie.Value)
	return ok
}

// sessionUser extracts the username from a valid session cookie.
func (a *Auth) sessionUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	return a.validateToken(cookie.Value)
}

// ── Current-user context ─────────────────────────────────────────────────────

type userCtxKey struct{}

type userCtx struct {
	Name string
	ID   int64
}

// UserFromContext returns the authenticated username stored on the request
// context ("" if the request is unauthenticated).
func UserFromContext(ctx context.Context) string {
	u, _ := ctx.Value(userCtxKey{}).(*userCtx)
	if u == nil {
		return ""
	}
	return u.Name
}

// UserIDFromContext returns the database ID of the authenticated user
// (0 if the request is unauthenticated).
func UserIDFromContext(ctx context.Context) int64 {
	u, _ := ctx.Value(userCtxKey{}).(*userCtx)
	if u == nil {
		return 0
	}
	return u.ID
}

// lookupUserID resolves a username to its database id.
func (a *Auth) lookupUserID(username string) int64 {
	var id int64
	a.db.QueryRow(`SELECT id FROM users WHERE username = ? AND email_verified = 1`, username).Scan(&id)
	return id
}

// withUser injects the session's username and id into the request context.
func (a *Auth) withUser(r *http.Request) context.Context {
	if username, ok := a.sessionUser(r); ok {
		return context.WithValue(r.Context(), userCtxKey{},
			&userCtx{Name: username, ID: a.lookupUserID(username)})
	}
	return r.Context()
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Middleware protects all routes, redirecting unauthenticated requests.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Always public - setup, registration, login, logout, email verify,
		// landing page, static assets
		if path == "/" || path == "/landing.html" ||
			path == "/setup" || path == "/api/setup" ||
			path == "/register" || path == "/api/register" ||
			path == "/login" || path == "/logout" ||
			path == "/api/verify-email" || isPublicAsset(path) {
			next.ServeHTTP(w, r.WithContext(a.withUser(r)))
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
		if username, ok := a.sessionUser(r); ok {
			ctx := context.WithValue(r.Context(), userCtxKey{},
				&userCtx{Name: username, ID: a.lookupUserID(username)})
			next.ServeHTTP(w, r.WithContext(ctx))
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

// validateToken checks the signature and expiry and returns the username.
func (a *Auth) validateToken(value string) (string, bool) {
	parts := strings.SplitN(value, ":", 4)
	if len(parts) != 4 {
		return "", false
	}
	raw := parts[0] + ":" + parts[1] + ":" + parts[2]
	expectedSig := a.sign(raw)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[3])) {
		return "", false
	}
	if !IsValidUsername(parts[2]) {
		return "", false
	}
	var ts int64
	fmt.Sscanf(parts[1], "%d", &ts)
	ttl := a.cfg.SessionTTLHours
	if ttl == 0 {
		ttl = 168
	}
	expiry := time.Unix(ts, 0).Add(time.Duration(ttl) * time.Hour)
	if time.Now().After(expiry) {
		return "", false
	}
	return parts[2], true
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
