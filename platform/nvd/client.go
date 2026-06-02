package nvd

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

// Client queries the NVD API for CVEs and caches results in SQLite.
type Client struct {
	apiKey      string
	baseURL     string
	ttl         time.Duration
	delay       time.Duration
	db          *sql.DB
	httpClient  *http.Client
}

// NewClient constructs an NVD Client from the app config.
func NewClient(cfg models.Config, db *sql.DB) *Client {
	return &Client{
		apiKey:  cfg.NVD.APIKey,
		baseURL: cfg.NVD.BaseURL,
		ttl:     time.Duration(cfg.NVD.CacheTTLHours) * time.Hour,
		delay:   time.Duration(cfg.NVD.RequestDelayMs) * time.Millisecond,
		db:      db,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Lookup returns a list of CVEs for the given product and version.
// It checks the local cache first and only calls the NVD API on a cache miss
// or when the cached entry is older than the configured TTL.
func (c *Client) Lookup(product, version string) ([]models.CVE, error) {
	key := buildCacheKey(product, version)

	// ── Cache hit ─────────────────────────────────────────────────────────────
	if raw, ok := cacheGet(c.db, key, c.ttl); ok {
		return parseCVEs(raw), nil
	}

	// ── Live NVD request ──────────────────────────────────────────────────────
	// Respect rate limits: 5 req/30s without key, 50 req/30s with key.
	time.Sleep(c.delay)

	raw, err := c.fetchFromNVD(product, version)
	if err != nil {
		return nil, fmt.Errorf("NVD fetch %s %s: %w", product, version, err)
	}

	// Persist to cache so the next identical lookup is instant.
	cacheSet(c.db, key, raw)

	return parseCVEs(raw), nil
}

// fetchFromNVD builds and executes the NVD API request, returning the raw
// JSON response body as a string.
func (c *Client) fetchFromNVD(product, version string) (string, error) {
	// NVD keyword search: "product version"
	// The API also supports CPE names but keyword search is simpler and works
	// well for common software names like "nginx 1.18.0".
	keyword := fmt.Sprintf("%s %s", product, version)

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("keywordExactMatch", "")
	params.Set("resultsPerPage", "10") // top 10 CVEs is enough for SME context

	endpoint := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SME-Shield/1.0 (github.com/rjeff-sudo/sme-shield)")

	// API key dramatically increases rate limits — use it when configured.
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf("NVD rate limit hit — add an API key in config.yaml")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	log.Printf("[nvd] fetched %d bytes for %s %s", len(body), product, version)
	return string(body), nil
}

// parseCVEs deserialises a raw NVD JSON response into a slice of models.CVE.
// It tries CVSS v3.1 → v3.0 → v2.0 in that order for scoring.
func parseCVEs(raw string) []models.CVE {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	var nvdResp models.NVDResponse
	if err := json.Unmarshal([]byte(raw), &nvdResp); err != nil {
		log.Printf("[nvd] parse error: %v", err)
		return nil
	}

	var cves []models.CVE
	for _, v := range nvdResp.Vulnerabilities {
		cve := models.CVE{ID: v.CVE.ID}

		// Extract English description.
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				cve.Description = d.Value
				break
			}
		}

		// Extract CVSS score — prefer newest metric version.
		switch {
		case len(v.CVE.Metrics.CvssMetricV31) > 0:
			m := v.CVE.Metrics.CvssMetricV31[0].CvssData
			cve.Score = m.BaseScore
			cve.Severity = strings.ToUpper(m.BaseSeverity)

		case len(v.CVE.Metrics.CvssMetricV30) > 0:
			m := v.CVE.Metrics.CvssMetricV30[0].CvssData
			cve.Score = m.BaseScore
			cve.Severity = strings.ToUpper(m.BaseSeverity)

		case len(v.CVE.Metrics.CvssMetricV2) > 0:
			m := v.CVE.Metrics.CvssMetricV2[0]
			cve.Score = m.CvssData.BaseScore
			cve.Severity = strings.ToUpper(m.BaseSeverity)
		}

		// Derive severity label from score when the API doesn't include one.
		if cve.Severity == "" {
			switch {
			case cve.Score >= 9.0:
				cve.Severity = "CRITICAL"
			case cve.Score >= 7.0:
				cve.Severity = "HIGH"
			case cve.Score >= 4.0:
				cve.Severity = "MEDIUM"
			default:
				cve.Severity = "LOW"
			}
		}

		cves = append(cves, cve)
	}

	return cves
}