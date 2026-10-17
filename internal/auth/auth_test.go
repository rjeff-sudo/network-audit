package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/mattn/go-sqlite3"
)

func testDB(t *testing.T) *Auth {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for _, m := range []string{
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			email_verified INTEGER NOT NULL DEFAULT 0,
			verification_token TEXT NOT NULL DEFAULT '',
			token_expires_at TEXT NOT NULL DEFAULT ''
		)`,
	} {
		if _, err := db.Exec(m); err != nil {
			t.Fatalf("migration: %v", err)
		}
	}
	return New(Config{SessionSecret: "test-secret", SessionTTLHours: 1}, db)
}

func TestRegisterGate(t *testing.T) {
	a := testDB(t)

	// Register creates an unverified account + token
	token, err := a.Register("newuser", "password123", "new@example.com")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if token == "" || !a.AccountExists("newuser") {
		t.Fatalf("expected account + token")
	}

	// Blocked until verified
	if a.CheckCredentials("newuser", "password123") {
		t.Fatal("unverified account must not be able to log in")
	}

	// Verify token → login works
	if err := a.VerifyEmail(token); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !a.CheckCredentials("newuser", "password123") {
		t.Fatal("verified account should log in")
	}

	// Token is single-use
	if err := a.VerifyEmail(token); err == nil {
		t.Fatal("reused verification token must fail")
	}
}

func TestRegisterValidation(t *testing.T) {
	a := testDB(t)

	cases := []struct{ user, pw, email string }{
		{"x", "password123", "a@b.com"},     // username too short
		{"has space", "password123", "a@b.com"}, // invalid charset
		{"bad:char", "password123", "a@b.com"},  // ':' would corrupt session token
		{"gooduser1", "short", "a@b.com"},   // password too short
		{"gooduser1", "password123", "nope"}, // bad email
	}
	for i, c := range cases {
		if _, err := a.Register(c.user, c.pw, c.email); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}

	// Duplicate username
	if _, err := a.Register("dup", "password123", "a@b.com"); err != nil {
		t.Fatalf("seed dup: %v", err)
	}
	if _, err := a.Register("dup", "password123", "a@b.com"); err == nil ||
		!strings.Contains(err.Error(), "already taken") {
		t.Errorf("expected duplicate-username error, got %v", err)
	}
}

func TestSetupUserIsPreverified(t *testing.T) {
	a := testDB(t)
	if err := a.CreateUser("admin", "password123", "admin@example.com"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !a.CheckCredentials("admin", "password123") {
		t.Fatal("first-run admin should log in without email verification")
	}
}

func TestSessionCarriesUsername(t *testing.T) {
	a := testDB(t)
	if err := a.CreateUser("user1", "password123", "u1@example.com"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Login-equivalent: set a session bound to user1 on a recorder.
	rec := httptest.NewRecorder()
	a.SetSession(rec, "user1")
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	if !a.IsAuthenticated(req) {
		t.Fatal("session should validate")
	}
	if got, ok := a.sessionUser(req); !ok || got != "user1" {
		t.Fatalf("session username = %q (ok=%v), want user1", got, ok)
	}

	// A tampered username section must be rejected.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered := strings.Replace(cookies[0].Value, "user1", "hacker99", 1)
	req2.AddCookie(&http.Cookie{Name: cookieName, Value: tampered})
	if a.IsAuthenticated(req2) {
		t.Fatal("tampered session must be rejected")
	}

	// A session for an unverified user must not resolve context (locked out).
	_, err := a.Register("pending99", "password123", "p1@example.com")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rec2 := httptest.NewRecorder()
	a.SetSession(rec2, "pending99")
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.AddCookie(rec2.Result().Cookies()[0])
	ctx := a.withUser(req3)
	if got := UserIDFromContext(ctx); got != 0 {
		t.Fatalf("unverified user must have no data access, got id %d", got)
	}
}

func TestBcryptCost(t *testing.T) {
	if bcryptCost < bcrypt.DefaultCost {
		t.Errorf("bcrypt cost %d below library default", bcryptCost)
	}
}
