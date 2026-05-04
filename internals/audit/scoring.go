package audit

import "github.com/rjeff-sudo/network-audit/internals/models"

// CalculateRiskScore takes all found CVEs and returns a score from 0-100
// 100 is perfect, 0 is very insecure.
func CalculateRiskScore(cves []models.CVE) int {
	if len(cves) == 0 {
		return 100
	}

	var totalImpact float64
	for _, cve := range cves {
		// We weight Critical/High vulnerabilities more heavily
		if cve.Score >= 9.0 {
			totalImpact += 25
		} else if cve.Score >= 7.0 {
			totalImpact += 15
		} else {
			totalImpact += 5
		}
	}

	score := 100 - int(totalImpact)
	if score < 0 {
		return 0
	}
	return score
}