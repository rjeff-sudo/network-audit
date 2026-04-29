package audit

import (
	"regexp"
	"strings"
)

type ServiceInfo struct {
	Product string
	Version string
}

func ParseBanner(banner string) ServiceInfo {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return ServiceInfo{Product: "Unknown", Version: "Unknown"}
	}

	// Common pattern: Product/Version or Product Version (e.g., Apache/2.4.41)
	// This regex looks for a name followed by a slash or space and then numbers/dots
	re := regexp.MustCompile(`(?i)([a-z0-9-]+)[/\s]([0-9]+\.[0-9]+[.0-9a-z-]*)`)
	matches := re.FindStringSubmatch(banner)

	if len(matches) >= 3 {
		return ServiceInfo{
			Product: matches[1],
			Version: matches[2],
		}
	}

	// Fallback: If no version found, just return the first part of the banner
	parts := strings.Split(banner, " ")
	return ServiceInfo{
		Product: parts[0],
		Version: "Unknown",
	}
}