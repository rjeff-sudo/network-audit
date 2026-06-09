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
}
