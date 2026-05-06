package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

func InitDB(filepath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		return nil, err
	}

	// Create tables if they don't exist
	query := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT,
		risk_score INTEGER,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS cve_cache (
		product TEXT,
		version TEXT,
		data TEXT,
		last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (product, version)
	);`

	resultsTable := `
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        port INTEGER,
        service TEXT,
        version TEXT,
        vulnerabilities TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );`

	_, err = db.Exec(query)
	return db, err
}