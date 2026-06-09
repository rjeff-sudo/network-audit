package audit

import (
	"math"

	"github.com/rjeff-sudo/sme-shield/internal/models"
)

func CalculateScore(cves []models.CVE) int {
	if len(cves) == 0 {
		return 100
	}

	var impact float64
	for _, c := range cves {
		switch {
		case c.Score >= 9.0:
			impact += 20
		case c.Score >= 7.0:
			impact += 10
		case c.Score >= 4.0:
			impact += 4
		default:
			impact += 1
		}
	}

	damped := math.Log1p(impact) * 14.5
	score := 100 - int(math.Round(damped))
	if score < 0 {
		return 0
	}
	return score
}

func SeverityLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func BuildSummary(cves []models.CVE) models.Summary {
	s := models.Summary{}
	for _, c := range cves {
		switch c.Severity {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		default:
			s.Low++
		}
	}

	score := CalculateScore(cves)
	switch {
	case score >= 80:
		s.Label = "Secure"
	case score >= 60:
		s.Label = "Moderate Risk"
	case score >= 30:
		s.Label = "High Risk"
	default:
		s.Label = "Critical"
	}
	return s
}
