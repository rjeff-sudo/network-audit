// Package db manages the SQLite connection and schema migrations.
package db

// migrations is an ordered list of SQL statements that bring the schema
// up to date. Each entry is applied exactly once, tracked by its index
// in the schema_migrations table. Never edit a past migration — only append.
var migrations = []string{
	// v1 — core tables
	`CREATE TABLE IF NOT EXISTS scans (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		ip         TEXT        NOT NULL,
		hostname   TEXT        NOT NULL DEFAULT '',
		risk_score INTEGER     NOT NULL DEFAULT 100,
		scan_time  TEXT        NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS scan_results (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		port      INTEGER NOT NULL,
		service   TEXT    NOT NULL DEFAULT '',
		product   TEXT    NOT NULL DEFAULT '',
		version   TEXT    NOT NULL DEFAULT '',
		cve_count INTEGER NOT NULL DEFAULT 0
	)`,

	// v2 — CVE cache so we don't hammer NVD on every scan
	`CREATE TABLE IF NOT EXISTS cve_cache (
		cache_key    TEXT PRIMARY KEY,
		response_json TEXT    NOT NULL,
		cached_at    TEXT    NOT NULL
	)`,

	// v3 — indexes for common query patterns
	`CREATE INDEX IF NOT EXISTS idx_scans_scan_time   ON scans(scan_time DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_results_scan_id   ON scan_results(scan_id)`,
	`CREATE INDEX IF NOT EXISTS idx_cache_cached_at   ON cve_cache(cached_at)`,

	// v4 — migration tracking table (created last so earlier migrations
	//       don't depend on it existing)
	`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`,

	// v5 — users table (replaces plaintext password in config.yaml)
	`CREATE TABLE IF NOT EXISTS users (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		username     TEXT    NOT NULL UNIQUE,
		password_hash TEXT   NOT NULL,
		created_at   TEXT    NOT NULL,
		updated_at   TEXT    NOT NULL
	)`,
 
	// v6 — index on username for fast login lookups
	`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,

	// v7 — scheduled scans table
	`CREATE TABLE IF NOT EXISTS schedules (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		ip           TEXT    NOT NULL,
		label        TEXT    NOT NULL DEFAULT '',
		interval_hrs INTEGER NOT NULL DEFAULT 24,
		enabled      INTEGER NOT NULL DEFAULT 1,
		last_run     TEXT,
		next_run     TEXT    NOT NULL,
		created_at   TEXT    NOT NULL
	)`,
 
	// v8 — index for fast next_run polling
	`CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run)`,

	// v9 — email verification columns on users table
	`ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE users ADD COLUMN verification_token TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE users ADD COLUMN token_expires_at TEXT NOT NULL DEFAULT ''`,

	// v10 — per-user data ownership: attribute existing scans/schedules to the first user
	`ALTER TABLE scans ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE schedules ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0`,
	`UPDATE scans SET user_id = COALESCE((SELECT id FROM users ORDER BY id LIMIT 1), 0) WHERE user_id = 0`,
	`UPDATE schedules SET user_id = COALESCE((SELECT id FROM users ORDER BY id LIMIT 1), 0) WHERE user_id = 0`,
	`CREATE INDEX IF NOT EXISTS idx_scans_user_id     ON scans(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_schedules_user_id ON schedules(user_id)`,
}
