// Package nvd handles communication with the NIST National Vulnerability
// Database API and caches results locally to stay within rate limits.
package nvd

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// cacheGet retrieves a cached NVD response for cacheKey.
// Returns ("", false) when the entry is missing or older than ttl.
func cacheGet(db *sql.DB, cacheKey string, ttl time.Duration) (string, bool) {
	if db == nil {
		return "", false
	}

	var responseJSON, cachedAtStr string
	err := db.QueryRow(
		`SELECT response_json, cached_at FROM cve_cache WHERE cache_key = ?`,
		cacheKey,
	).Scan(&responseJSON, &cachedAtStr)

	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		log.Printf("[nvd cache] read error: %v", err)
		return "", false
	}

	cachedAt, err := time.Parse(time.RFC3339, cachedAtStr)
	if err != nil {
		return "", false
	}

	// Treat the entry as stale if it is older than ttl.
	if time.Since(cachedAt) > ttl {
		return "", false
	}

	return responseJSON, true
}

// cacheSet stores a raw JSON response string under cacheKey.
// Errors are logged but never returned — a failed cache write is not fatal.
func cacheSet(db *sql.DB, cacheKey, responseJSON string) {
	if db == nil {
		return
	}

	_, err := db.Exec(
		`INSERT INTO cve_cache (cache_key, response_json, cached_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(cache_key) DO UPDATE
		   SET response_json = excluded.response_json,
		       cached_at     = excluded.cached_at`,
		cacheKey,
		responseJSON,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		log.Printf("[nvd cache] write error for %q: %v", cacheKey, err)
	}
}

// cacheKey builds a canonical string key for a product+version pair.
func buildCacheKey(product, version string) string {
	return fmt.Sprintf("%s::%s", product, version)
}

// PruneCache deletes cache entries older than ttl. Safe to call on a schedule.
func PruneCache(db *sql.DB, ttl time.Duration) (int64, error) {
	if db == nil {
		return 0, nil
	}

	cutoff := time.Now().UTC().Add(-ttl).Format(time.RFC3339)
	res, err := db.Exec(`DELETE FROM cve_cache WHERE cached_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune cache: %w", err)
	}

	n, _ := res.RowsAffected()
	return n, nil
}
