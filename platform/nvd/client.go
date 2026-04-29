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
	if version == "Unknown" {
		return nil, nil 
	}

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
		return nil, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	return []models.CVE{}, nil
}