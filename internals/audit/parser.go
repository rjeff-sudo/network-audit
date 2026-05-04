package audit

import (
	"regexp"
	"strings"
)

// ServiceInfo holds the cleaned name and version of a service
type ServiceInfo struct {
	Product string
	Version string
}

// ParseBanner attempts to extract product and version from a raw string
func ParseBanner(banner string) ServiceInfo {
	// 1. CLEANUP: Remove non-printable/binary characters
	// This regex matches anything that is NOT a standard printable ASCII character
	// and replaces it with a space.
	cleanReg := regexp.MustCompile("[^ -~]+")
	banner = cleanReg.ReplaceAllString(banner, " ")

	banner = strings.TrimSpace(banner)
	if banner == "" {
		return ServiceInfo{Product: "Unknown", Version: "Unknown"}
	}

	// 2. EXTRACTION: Common pattern Product/Version or Product Version
	// Looks for a name followed by a slash or space and then numbers/dots
	re := regexp.MustCompile(`(?i)([a-z0-9-]+)[/\s]([0-9]+\.[0-9]+[.0-9a-z-]*)`)
	matches := re.FindStringSubmatch(banner)

	if len(matches) >= 3 {
		return ServiceInfo{
			Product: matches[1],
			Version: matches[2],
		}
	}

	// 3. FALLBACK: Split by space and take the first readable chunk
	parts := strings.Fields(banner) // Fields handles multiple spaces better than Split
	if len(parts) > 0 {
		return ServiceInfo{
			Product: parts[0],
			Version: "Unknown",
		}
	}

	return ServiceInfo{Product: "Unknown", Version: "Unknown"}
}