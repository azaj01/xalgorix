package reporting

import (
	"math"
	"sort"
	"strings"
)

// RiskScore computes a weighted overall risk score (0-10) from a slice of
// vulnerabilities. The formula matches the original internal/web
// implementation: weighted average of the top-five CVSS scores plus a
// severity-count penalty (capped at +1.5). When CVSS is missing, a
// severity-band default is substituted.
func RiskScore(vulns []Vuln) float64 {
	if len(vulns) == 0 {
		return 0
	}
	scores := make([]float64, 0, len(vulns))
	for _, v := range vulns {
		cvss := v.CVSS
		if cvss <= 0 {
			switch strings.ToLower(v.Severity) {
			case "critical":
				cvss = 9.5
			case "high":
				cvss = 7.5
			case "medium":
				cvss = 5.0
			case "low":
				cvss = 2.5
			default:
				cvss = 1.0
			}
		}
		scores = append(scores, cvss)
	}
	sort.Float64s(scores)
	n := len(scores)
	top := 5
	if n < top {
		top = n
	}
	sum := 0.0
	for i := 0; i < top; i++ {
		sum += scores[n-1-i]
	}
	avg := sum / float64(top)
	crit, high := 0, 0
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	penalty := math.Min(float64(crit)*0.15+float64(high)*0.05, 1.5)
	return math.Min(avg+penalty, 10.0)
}

// RiskLabel maps a numeric score into a human-readable rating used on the
// cover page and the executive-summary risk band.
func RiskLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 1.0:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}
