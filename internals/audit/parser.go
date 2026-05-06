package audit

import (
	"regexp"
	"strings"

	"github.com/rjeff-sudo/network-audit/internals/models" // Point to your central models
)

// ParseBanner attempts to extract product and version from a raw string
// Now returns models.ServiceInfo instead of a local struct
func ParseBanner(banner string) models.ServiceInfo {
	// 1. CLEANUP: Remove non-printable/binary characters
	cleanReg := regexp.MustCompile("[^ -~]+")
	banner = cleanReg.ReplaceAllString(banner, " ")

	banner = strings.TrimSpace(banner)
	if banner == "" {
		return models.ServiceInfo{Product: "Unknown", Version: "Unknown"}
	}

	// 2. EXTRACTION: Common pattern Product/Version or Product Version
	re := regexp.MustCompile(`(?i)([a-z0-9-]+)[/\s]([0-9]+\.[0-9]+[.0-9a-z-]*)`)
	matches := re.FindStringSubmatch(banner)

	if len(matches) >= 3 {
		return models.ServiceInfo{
			Product: matches[1],
			Version: matches[2],
		}
	}

	// 3. FALLBACK: Split by space and take the first readable chunk
	parts := strings.Fields(banner) 
	if len(parts) > 0 {
		return models.ServiceInfo{
			Product: parts[0],
			Version: "Unknown",
		}
	}

	return models.ServiceInfo{Product: "Unknown", Version: "Unknown"}
}