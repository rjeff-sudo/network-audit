package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Open opens (or creates) the SQLite database at path, configures connection
// settings, enables WAL mode for better concurrent read performance, and runs
// all pending schema migrations. It returns a ready-to-use *sql.DB.
func Open(path string) (*sql.DB, error) {
	// The ?_foreign_keys=on pragma enforces ON DELETE CASCADE.
	dsn := fmt.Sprintf("%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000", path)

	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite3 %q: %w", path, err)
	}

	// SQLite performs best with a single writer. Cap the pool accordingly.
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(0) // keep connection alive for the process lifetime

	// Confirm the connection is actually usable.
	if err := database.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite3: %w", err)
	}

	if err := runMigrations(database); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	log.Printf("[db] opened %q (WAL mode, %d migrations applied)", path, len(migrations))
	return database, nil
}

// runMigrations applies any migrations that have not yet been recorded in the
// schema_migrations table. Migrations run inside a single transaction so a
// partial failure leaves the schema in its previous clean state.
func runMigrations(db *sql.DB) error {
	// Bootstrap: ensure the tracking table exists before we query it.
	// This is the only SQL we run outside a migration entry.
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("bootstrap migrations table: %w", err)
	}

	// Find the highest version already applied.
	var applied int
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	if err := row.Scan(&applied); err != nil {
		return fmt.Errorf("query applied migrations: %w", err)
	}

	pending := migrations[applied:]
	if len(pending) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	defer tx.Rollback() // no-op if Commit() succeeds

	for i, stmt := range pending {
		version := applied + i + 1
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("migration v%d: %w", version, err)
		}
		_, err := tx.Exec(
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, time.Now().UTC().Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("record migration v%d: %w", version, err)
		}
		log.Printf("[db] migration v%d applied", version)
	}

	return tx.Commit()
}