package nvd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rjeff-sudo/network-audit/internals/models"
)

const baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type Client struct {
	APIKey     string
	HTTPClient *http.Client
}

func NewClient() *Client {
	return &Client{
		APIKey: os.Getenv("NVD_API_KEY"),
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) FetchCVEs(product, version string) ([]models.CVE, error) {
	if version == "Unknown" || version == "" {
		return nil, nil
	}

	// keywordSearch works best for product + version combos
	url := fmt.Sprintf("%s?keywordSearch=%s %s", baseURL, product, version)
	
	req, _ := http.NewRequest("GET", url, nil)
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API status: %d", resp.StatusCode)
	}

	var nvdData models.NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdData); err != nil {
		return nil, fmt.Errorf("failed to decode NVD JSON: %v", err)
	}

	var results []models.CVE
	for _, item := range nvdData.Vulnerabilities {
		cve := item.CVE
		newCVE := models.CVE{
			ID:          cve.ID,
			Description: "No description available",
			Severity:    "UNKNOWN",
			Score:       0.0,
		}

		// Grab the first English description
		if len(cve.Descriptions) > 0 {
			newCVE.Description = cve.Descriptions[0].Value
		}

		// Grab CVSS 3.1 Metrics if they exist
		if len(cve.Metrics.CvssMetricV31) > 0 {
			metric := cve.Metrics.CvssMetricV31[0].CvssData
			newCVE.Score = metric.BaseScore
			newCVE.Severity = metric.Severity
		}

		results = append(results, newCVE)
	}

	return results, nil
}