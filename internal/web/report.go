package web

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// riskScore computes a weighted overall risk score (0-10) from vulnerabilities.
// Formula: weighted average of top-5 CVSS scores + severity count penalty.
func riskScore(vulns []VulnSummary) float64 {
	if len(vulns) == 0 {
		return 0
	}
	// Collect CVSS values, fallback to severity-based defaults
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
	// Take top-5 (or fewer) weighted average
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
	// Severity count penalty: more criticals/highs push score up
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

// riskLabel returns a human-readable risk rating from a score.
func riskLabel(score float64) string {
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

// methodologyPhaseNames maps phase number to name for report display.
var methodologyPhaseNames = map[int]string{
	1: "Deep Reconnaissance & Attack Surface Mapping",
	2: "Manual Vulnerability Discovery",
	3: "Directory & File Discovery",
	4: "CORS & Cookie Analysis",
	5: "Authentication & Session Testing",
	6: "Injection Testing",
	7: "SSRF Testing",
	8: "IDOR & Broken Access Control",
	9: "API & GraphQL Testing",
	10: "File Upload Testing",
	11: "Deserialization & RCE",
	12: "Race Conditions & Business Logic",
	13: "Subdomain Takeover",
	14: "Open Redirect Testing",
	15: "Email Security Testing",
	16: "Cloud & Infrastructure",
	17: "WebSocket Testing",
	18: "CMS-Specific Testing",
	19: "Broken Link Hijacking & Content Spoofing",
	20: "Exploit Verification",
	21: "Zero-Day & Novel Vulnerability Discovery",
	22: "Final Report",
}

// generateReport creates a professional PDF pentest report for a scan.
func (s *Server) generateReport(scan *ScanRecord) (string, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Colors - dark theme to match UI
	darkBg := [3]int{15, 23, 42}      // #0f172a - main background
	coral := [3]int{244, 63, 94}      // #F43F5E - primary accent (coral rose)
	teal := [3]int{45, 212, 191}      // #2DD4BF - secondary accent
	white := [3]int{240, 240, 242}    // #f0f0f2 - text
	gray := [3]int{148, 163, 184}     // muted text
	red := [3]int{220, 53, 69}        // critical
	orange := [3]int{220, 120, 50}    // high
	amber := [3]int{220, 170, 50}     // medium
	greenLow := [3]int{40, 167, 69}   // low
	cyan := [3]int{6, 182, 212}       // info
	sectionBg := [3]int{30, 41, 59}   // #1e293b

	// Helper: set text color
	setColor := func(c [3]int) {
		pdf.SetTextColor(c[0], c[1], c[2])
	}

	// Helper: draw a colored rect
	drawRect := func(x, y, w, h float64, c [3]int) {
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "F")
	}

	// Helper: severity color
	sevColor := func(sev string) [3]int {
		switch strings.ToLower(sev) {
		case "critical":
			return red
		case "high":
			return orange
		case "medium":
			return amber
		case "low":
			return greenLow
		default:
			return cyan
		}
	}

	// ─── COVER PAGE ────────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)

	// Top accent line
	drawRect(0, 0, 210, 3, coral)

	// Branding: company logo placeholder (if logo path provided)
	if scan.LogoPath != "" {
		// Try to load the logo; silently skip if file missing
		info := pdf.RegisterImage(scan.LogoPath, "")
		if info != nil {
			// Scale logo to max 40mm height, centered
			logoW := info.Width() * 40.0 / info.Height()
			pdf.ImageOptions(scan.LogoPath, (210-logoW)/2, 30, logoW, 40, false, fpdf.ImageOptions{}, 0, "")
			pdf.SetY(75)
		} else {
			pdf.SetY(80)
		}
	} else {
		pdf.SetY(80)
	}

	// Title
	pdf.SetFont("Helvetica", "B", 42)
	setColor(coral)
	pdf.CellFormat(190, 16, "XALGORIX", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 14)
	setColor(white)
	pdf.CellFormat(190, 10, "Penetration Test Report", "", 1, "C", false, 0, "")

	// Branding: company name
	if scan.CompanyName != "" {
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "", 12)
		setColor(teal)
		pdf.CellFormat(190, 8, fmt.Sprintf("Prepared for: %s", scan.CompanyName), "", 1, "C", false, 0, "")
	}

	// Divider
	pdf.SetY(120)
	drawRect(60, pdf.GetY(), 90, 0.5, coral)

	// Target info
	pdf.SetY(135)
	pdf.SetFont("Helvetica", "", 12)
	setColor(gray)
	pdf.CellFormat(190, 8, "Target", "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "B", 14)
	setColor(white)
	target := scan.Target
	if len(target) > 50 {
		pdf.SetFont("Helvetica", "B", 10)
	}
	pdf.MultiCell(170, 10, target, "", "C", false)

	// Date
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 11)
	setColor(gray)
	startTime, _ := time.Parse(time.RFC3339, scan.StartedAt)
	pdf.CellFormat(190, 7, fmt.Sprintf("Date: %s", startTime.Format("January 2, 2006")), "", 1, "C", false, 0, "")

	// Scan ID
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(190, 7, fmt.Sprintf("Scan ID: %s", scan.ID), "", 1, "C", false, 0, "")

	// Bottom accent
	drawRect(0, 294, 210, 3, coral)

	// Footer
	pdf.SetY(270)
	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.CellFormat(190, 5, "Generated by Xalgorix - Autonomous AI-Powered Pentesting Engine", "", 1, "C", false, 0, "")
	pdf.CellFormat(190, 5, "https://github.com/xalgord/xalgorix", "", 1, "C", false, 0, "")

	// ─── EXECUTIVE SUMMARY ─────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(coral)
	pdf.CellFormat(190, 12, "Executive Summary", "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
	pdf.Ln(8)

	// Summary stats cards
	type statCard struct {
		label string
		value string
		color [3]int
	}

	endTime, _ := time.Parse(time.RFC3339, scan.FinishedAt)
	duration := "N/A"
	if !startTime.IsZero() && !endTime.IsZero() {
		d := endTime.Sub(startTime)
		if d.Hours() >= 1 {
			duration = fmt.Sprintf("%dh %dm %ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
		} else if d.Minutes() >= 1 {
			duration = fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
		} else {
			duration = fmt.Sprintf("%ds", int(d.Seconds()))
		}
	}

	// Count severity
	critCount, highCount, medCount, lowCount, infoCount := 0, 0, 0, 0, 0
	for _, v := range scan.Vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	cards := []statCard{
		{"Total Vulnerabilities", fmt.Sprintf("%d", len(scan.Vulns)), coral},
		{"Critical", fmt.Sprintf("%d", critCount), red},
		{"High", fmt.Sprintf("%d", highCount), orange},
		{"Medium", fmt.Sprintf("%d", medCount), amber},
		{"Low", fmt.Sprintf("%d", lowCount), greenLow},
		{"Info", fmt.Sprintf("%d", infoCount), cyan},
	}

	// Draw stat cards in 2 rows of 3
	cardW := 55.0
	cardH := 28.0
	startX := 12.0
	y := pdf.GetY()
	for i, c := range cards {
		col := i % 3
		row := i / 3
		x := startX + float64(col)*(cardW+7)
		cy := y + float64(row)*(cardH+6)

		drawRect(x, cy, cardW, cardH, sectionBg)
		// Top accent on card
		drawRect(x, cy, cardW, 2, c.color)

		pdf.SetXY(x+4, cy+6)
		pdf.SetFont("Helvetica", "", 9)
		setColor(gray)
		pdf.CellFormat(cardW-8, 5, c.label, "", 1, "L", false, 0, "")

		pdf.SetXY(x+4, cy+14)
		pdf.SetFont("Helvetica", "B", 18)
		setColor(c.color)
		pdf.CellFormat(cardW-8, 10, c.value, "", 0, "L", false, 0, "")
	}

	pdf.SetY(y + 2*(cardH+6) + 10)

	// ── Overall Risk Score ──
	score := riskScore(scan.Vulns)
	label := riskLabel(score)
	var riskColor [3]int
	switch label {
	case "CRITICAL":
		riskColor = red
	case "HIGH":
		riskColor = orange
	case "MEDIUM":
		riskColor = amber
	case "LOW":
		riskColor = greenLow
	default:
		riskColor = cyan
	}

	riskY := pdf.GetY()
	drawRect(10, riskY, 190, 22, sectionBg)
	drawRect(10, riskY, 190, 2.5, riskColor)
	pdf.SetXY(14, riskY+5)
	pdf.SetFont("Helvetica", "B", 11)
	setColor(gray)
	pdf.CellFormat(60, 6, "OVERALL RISK SCORE", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 22)
	setColor(riskColor)
	pdf.CellFormat(25, 10, fmt.Sprintf("%.1f", score), "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(50, 10, label, "", 0, "L", false, 0, "")
	pdf.SetY(riskY + 26)

	// ── Executive Risk Narrative ──
	pdf.SetFont("Helvetica", "B", 11)
	setColor(white)
	pdf.CellFormat(190, 7, "Risk Assessment", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	narrative := fmt.Sprintf(
		"The automated penetration test of %s identified %d vulnerabilities "+
			"(%d critical, %d high, %d medium, %d low, %d informational). ",
		scan.Target, len(scan.Vulns), critCount, highCount, medCount, lowCount, infoCount,
	)
	if critCount > 0 || highCount > 0 {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). Immediate remediation is recommended for the %d critical "+
				"and %d high severity findings, as they may allow unauthorized access, data exfiltration, or service disruption. ",
			label, score, critCount, highCount,
		)
	} else if medCount > 0 {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). While no critical or high-severity issues were found, "+
				"the %d medium findings should be addressed in the next maintenance cycle to reduce attack surface. ",
			label, score, medCount,
		)
	} else {
		narrative += fmt.Sprintf(
			"The overall risk is assessed as %s (%.1f/10). The target demonstrates a strong security posture "+
				"with only low-severity or informational findings. Continuous monitoring is recommended. ",
			label, score,
		)
	}
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, narrative, "", "L", false)
	pdf.Ln(6)

	// Scan metadata
	pdf.SetFont("Helvetica", "B", 13)
	setColor(white)
	pdf.CellFormat(190, 8, "Scan Details", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	metaItems := [][2]string{
		{"Target", scan.Target},
		{"Status", strings.ToUpper(scan.Status)},
		{"Duration", duration},
		{"Iterations", fmt.Sprintf("%d", scan.Iterations)},
		{"Tool Calls", fmt.Sprintf("%d", scan.ToolCalls)},
		{"Total Tokens", fmt.Sprintf("%d", scan.TotalTokens)},
		{"Started", startTime.Format("2006-01-02 15:04:05 MST")},
		{"Finished", endTime.Format("2006-01-02 15:04:05 MST")},
	}

	for i, m := range metaItems {
		bgColor := darkBg
		if i%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, pdf.GetY(), 190, 8, bgColor)
		pdf.SetFont("Helvetica", "B", 9)
		setColor(gray)
		pdf.CellFormat(45, 8, "  "+m[0], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		pdf.CellFormat(145, 8, m[1], "", 1, "L", false, 0, "")
	}

	// ─── METHODOLOGY ──────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(coral)
	pdf.CellFormat(190, 12, "Testing Methodology", "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 9)
	setColor(white)
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, "Xalgorix follows a comprehensive 22-phase penetration testing methodology "+
		"aligned with OWASP, PTES, and industry best practices. Each phase is executed by an autonomous AI agent "+
		"with tool access to terminal, browser, and specialized security utilities.", "", "L", false)
	pdf.Ln(4)

	// Determine which phases were executed
	executedPhases := scan.Phases
	allPhases := len(executedPhases) == 0 // empty = all phases
	for phaseNum := 1; phaseNum <= 22; phaseNum++ {
		name, ok := methodologyPhaseNames[phaseNum]
		if !ok {
			continue
		}
		executed := allPhases
		if !allPhases {
			for _, p := range executedPhases {
				if p == phaseNum {
					executed = true
					break
				}
			}
		}
		rowY := pdf.GetY()
		if rowY > 270 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, coral)
			pdf.SetY(15)
			rowY = pdf.GetY()
		}
		bgColor := darkBg
		if phaseNum%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, rowY, 190, 7, bgColor)
		// Status indicator
		if executed {
			drawRect(12, rowY+1.5, 4, 4, teal)
		} else {
			drawRect(12, rowY+1.5, 4, 4, gray)
		}
		pdf.SetXY(20, rowY)
		pdf.SetFont("Helvetica", "", 8)
		if executed {
			setColor(white)
		} else {
			setColor(gray)
		}
		pdf.CellFormat(180, 7, fmt.Sprintf("Phase %d: %s", phaseNum, name), "", 1, "L", false, 0, "")
	}

	// Legend
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 7)
	setColor(gray)
	pdf.SetX(10)
	drawRect(12, pdf.GetY()+1, 3, 3, teal)
	pdf.SetX(18)
	pdf.CellFormat(30, 5, "= Executed", "", 0, "L", false, 0, "")
	drawRect(50, pdf.GetY()+1, 3, 3, gray)
	pdf.SetX(56)
	pdf.CellFormat(30, 5, "= Skipped", "", 1, "L", false, 0, "")

	// ─── BLUE TEAM TIMESTAMPS ─────────────────────────────
	pdf.Ln(10)
	if pdf.GetY() > 230 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)
		pdf.SetY(15)
	}
	pdf.SetFont("Helvetica", "B", 16)
	setColor(coral)
	pdf.CellFormat(190, 10, "Blue Team Reference Timestamps", "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+1, 50, 0.8, teal)
	pdf.Ln(6)

	pdf.SetFont("Helvetica", "", 8)
	setColor(gray)
	pdf.SetX(10)
	pdf.MultiCell(190, 4, "The following RFC3339 timestamps enable Blue Team operators to correlate "+
		"scan activity with SIEM/log sources for use-case development and alert tuning.", "", "L", false)
	pdf.Ln(3)

	tsItems := [][2]string{
		{"Scan Start", scan.StartedAt},
		{"Scan End", scan.FinishedAt},
	}
	// Add per-vulnerability discovery timestamps
	for i, v := range scan.Vulns {
		if i >= 20 {
			break // Limit to 20 to avoid excessive pages
		}
		ts := scan.StartedAt // fallback
		if v.CVSS > 0 {
			ts = scan.StartedAt
		}
		tsItems = append(tsItems, [2]string{
			fmt.Sprintf("Vuln #%d: %s", i+1, v.Title),
			ts,
		})
	}

	for i, ts := range tsItems {
		if pdf.GetY() > 270 {
			pdf.AddPage()
			drawRect(0, 0, 210, 297, darkBg)
			drawRect(0, 0, 210, 1.5, coral)
			pdf.SetY(15)
		}
		bgColor := darkBg
		if i%2 == 0 {
			bgColor = sectionBg
		}
		drawRect(10, pdf.GetY(), 190, 7, bgColor)
		pdf.SetFont("Helvetica", "B", 7)
		setColor(gray)
		titleStr := ts[0]
		if len(titleStr) > 50 {
			titleStr = titleStr[:47] + "..."
		}
		pdf.CellFormat(70, 7, "  "+titleStr, "", 0, "L", false, 0, "")
		pdf.SetFont("Courier", "", 7)
		setColor(teal)
		pdf.CellFormat(120, 7, ts[1], "", 1, "L", false, 0, "")
	}

	// ─── VULNERABILITY DETAILS ─────────────────────────────
	if len(scan.Vulns) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, "Vulnerability Details", "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		for idx, v := range scan.Vulns {
			sc := sevColor(v.Severity)

			// Check if we need a new page (leave 80mm minimum)
			if pdf.GetY() > 220 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}

			// Vuln header bar
			headerY := pdf.GetY()
			drawRect(10, headerY, 190, 10, sectionBg)
			drawRect(10, headerY, 3, 10, sc)

			pdf.SetXY(16, headerY+1)
			pdf.SetFont("Helvetica", "B", 10)
			setColor(white)
			pdf.CellFormat(0, 8, fmt.Sprintf("#%d  %s", idx+1, v.Title), "", 0, "L", false, 0, "")

			// Severity badge
			pdf.SetXY(170, headerY+2)
			pdf.SetFont("Helvetica", "B", 8)
			drawRect(170, headerY+2, 28, 6, sc)
			pdf.SetTextColor(255, 255, 255)
			pdf.CellFormat(28, 6, strings.ToUpper(v.Severity), "", 0, "C", false, 0, "")

			pdf.SetY(headerY + 12)

			// Verification method badge
			if v.VerificationMethod != "" {
				pdf.SetFont("Helvetica", "I", 7)
				setColor(teal)
				pdf.SetX(14)
				pdf.CellFormat(0, 5, fmt.Sprintf("Verified via: %s", strings.ToUpper(v.VerificationMethod)), "", 1, "L", false, 0, "")
			}

			// Vuln meta row
			metaY := pdf.GetY()
			pdf.SetFont("Helvetica", "", 8)
			if v.CVSS > 0 {
				setColor(gray)
				pdf.SetXY(14, metaY)
				pdf.CellFormat(15, 5, "CVSS:", "", 0, "L", false, 0, "")
				setColor(sc)
				pdf.SetFont("Helvetica", "B", 8)
				pdf.CellFormat(15, 5, fmt.Sprintf("%.1f", v.CVSS), "", 0, "L", false, 0, "")
				// Show CVSS vector if available
				if v.CVSSVector != "" {
					setColor(gray)
					pdf.SetFont("Helvetica", "", 7)
					pdf.CellFormat(80, 5, v.CVSSVector, "", 0, "L", false, 0, "")
				}
			}
			if v.CVE != "" {
				setColor(gray)
				pdf.SetFont("Helvetica", "", 8)
				pdf.CellFormat(10, 5, "CVE:", "", 0, "L", false, 0, "")
				setColor(white)
				pdf.CellFormat(30, 5, v.CVE, "", 0, "L", false, 0, "")
			}
			if v.Method != "" {
				setColor(gray)
				pdf.SetFont("Helvetica", "", 8)
				pdf.CellFormat(15, 5, "Method:", "", 0, "L", false, 0, "")
				setColor(white)
				pdf.CellFormat(15, 5, v.Method, "", 0, "L", false, 0, "")
			}
			pdf.Ln(7)

			// Sections - only add if content exists
			type section struct {
				label   string
				content string
			}

			sections := []section{}
			if v.Endpoint != "" {
				sections = append(sections, section{"ENDPOINT", v.Endpoint})
			}
			if v.Description != "" {
				sections = append(sections, section{"DESCRIPTION", v.Description})
			}
			if v.Impact != "" {
				sections = append(sections, section{"IMPACT", v.Impact})
			}
			if v.TechnicalAnalysis != "" {
				sections = append(sections, section{"TECHNICAL ANALYSIS", v.TechnicalAnalysis})
			}
			if v.PoCDescription != "" {
				sections = append(sections, section{"PROOF OF CONCEPT", v.PoCDescription})
			}
			if v.PoCScript != "" {
				sections = append(sections, section{"POC SCRIPT", v.PoCScript})
			}
			if v.ExploitationProof != "" {
				sections = append(sections, section{"EXPLOITATION PROOF", v.ExploitationProof})
			}
			if v.Remediation != "" {
				sections = append(sections, section{"REMEDIATION", v.Remediation})
			}

			for _, sec := range sections {
				if pdf.GetY() > 250 {
					pdf.AddPage()
					drawRect(0, 0, 210, 297, darkBg)
					drawRect(0, 0, 210, 1.5, coral)
					pdf.SetY(15)
				}

				// Section header with dark background for contrast
				secY := pdf.GetY()
				drawRect(10, secY, 190, 8, sectionBg)

				pdf.SetXY(14, secY+1)
				pdf.SetFont("Helvetica", "B", 8)
				setColor(coral)
				pdf.CellFormat(0, 6, sec.label, "", 0, "L", false, 0, "")

				pdf.SetY(secY + 9)

				// Content
				pdf.SetFont("Helvetica", "", 9)
				if sec.label == "POC SCRIPT" || sec.label == "ENDPOINT" || sec.label == "EXPLOITATION PROOF" {
					// Code-style content with dynamic height
					codeY := pdf.GetY()
					content := sec.content
					if len(content) > 2000 {
						content = content[:2000] + "\n... (truncated)"
					}
					// Calculate dynamic height based on content
					lines := strings.Count(content, "\n") + 1
					blockHeight := float64(lines)*4 + 6 // 4mm per line + padding
					if blockHeight < 15 {
						blockHeight = 15
					}
					if blockHeight > 150 {
						blockHeight = 150 // Cap to prevent page overflow
					}
					// Check if we need a new page for this code block
					if codeY+blockHeight > 270 {
						pdf.AddPage()
						drawRect(0, 0, 210, 297, darkBg)
						drawRect(0, 0, 210, 1.5, coral)
						pdf.SetY(15)
						codeY = pdf.GetY()
					}
					drawRect(14, codeY, 182, blockHeight, [3]int{20, 25, 40})
					pdf.SetXY(17, codeY+3)
					pdf.SetFont("Courier", "", 7)
					if sec.label == "EXPLOITATION PROOF" {
						setColor([3]int{255, 200, 100}) // Gold/amber for exploitation proof
					} else {
						setColor(cyan)
					}
					pdf.MultiCell(175, 4, content, "", "L", false)
				} else {
					setColor(white)
					pdf.SetX(14)
					pdf.MultiCell(182, 5, sec.content, "", "L", false)
				}
				pdf.Ln(4)
			}

			// Separator between vulns
			pdf.Ln(4)
			if idx < len(scan.Vulns)-1 {
				drawRect(30, pdf.GetY(), 150, 0.3, sectionBg)
				pdf.Ln(6)
			}
		}
	}

	// ─── TESTED ENDPOINTS ─────────────────────────────────
	// Only add if there are endpoints
	endpointSet := make(map[string]bool)
	var endpoints []string
	for _, evt := range scan.Events {
		if evt.Type == "tool_call" && evt.ToolName == "terminal_execute" {
			if strings.Contains(evt.ToolArgs["command"], "http") {
				lines := strings.Split(evt.ToolArgs["command"], "\n")
				for _, line := range lines {
					if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
						for _, word := range strings.Fields(line) {
							if strings.Contains(word, "http") {
								u := extractURL(word)
								if u != "" && !endpointSet[u] {
									endpointSet[u] = true
									endpoints = append(endpoints, u)
								}
							}
						}
					}
				}
			}
		}
	}

	if len(endpoints) > 0 {
		pdf.AddPage()
		drawRect(0, 0, 210, 297, darkBg)
		drawRect(0, 0, 210, 1.5, coral)

		pdf.SetY(15)
		pdf.SetFont("Helvetica", "B", 22)
		setColor(coral)
		pdf.CellFormat(190, 12, "Tested Endpoints & URLs", "", 1, "L", false, 0, "")
		drawRect(10, pdf.GetY()+2, 50, 0.8, coral)
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 9)
		setColor(white)
		// Show first 30 endpoints
		displayEndpoints := endpoints
		if len(displayEndpoints) > 30 {
			displayEndpoints = displayEndpoints[:30]
		}
		for _, ep := range displayEndpoints {
			if pdf.GetY() > 265 {
				pdf.AddPage()
				drawRect(0, 0, 210, 297, darkBg)
				drawRect(0, 0, 210, 1.5, coral)
				pdf.SetY(15)
			}
			pdf.SetFont("Courier", "", 8)
			setColor(cyan)
			pdf.CellFormat(190, 5, "- "+ep, "", 1, "L", false, 0, "")
		}
		if len(endpoints) > 30 {
			pdf.Ln(2)
			pdf.SetFont("Helvetica", "", 9)
			setColor(gray)
			pdf.CellFormat(190, 5, fmt.Sprintf("... and %d more endpoints", len(endpoints)-30), "", 1, "L", false, 0, "")
		}
	}

	// ─── DISCLAIMER ──────────────────────────────────────
	pdf.AddPage()
	drawRect(0, 0, 210, 297, darkBg)
	drawRect(0, 0, 210, 1.5, coral)

	pdf.SetY(15)
	pdf.SetFont("Helvetica", "B", 22)
	setColor(red)
	pdf.CellFormat(190, 12, "Disclaimer", "", 1, "L", false, 0, "")
	drawRect(10, pdf.GetY()+2, 50, 0.8, teal)
	pdf.Ln(10)

	disclaimer := `This penetration test was conducted by Xalgorix, an autonomous AI-powered security assessment tool. The findings in this report are based on automated testing and manual verification where possible.

IMPORTANT NOTICES:

* Scope: This assessment was limited to the target systems explicitly listed in this report. Any systems or services outside the defined scope were not tested.

* False Positives: While Xalgorix attempts to verify findings before reporting, some findings may require manual validation. We recommend validating all critical and high-severity findings before taking remediation actions.

* Limitations: Automated testing cannot discover all vulnerabilities. Manual testing, code review, and other complementary security activities are recommended for comprehensive security coverage.

* Legal: This assessment was conducted with authorization from the target owner. Unauthorized security testing is illegal. Ensure you have proper authorization before testing any system.

* Report Accuracy: This report is provided "as is" without warranties of any kind. The testing methodology and findings are based on the tools and techniques available at the time of testing.

* Remediation: For any vulnerabilities found, follow industry best practices for remediation. Consult with security professionals for complex vulnerabilities.

Generated by Xalgorix - Autonomous AI Pentesting Engine
https://github.com/xalgord/xalgorix`

	pdf.SetFont("Helvetica", "", 10)
	setColor(white)
	pdf.MultiCell(182, 5, disclaimer, "", "L", false)

	// Save PDF — use currentScanDir which is the actual scan directory
	filename := fmt.Sprintf("xalgorix_report_%s.pdf", scan.ID)
	// Try saving to the scan directory first, fall back to dataDir
	outPath := filepath.Join(s.currentScanDir, filename)
	if s.currentScanDir == "" {
		outPath = filepath.Join(s.dataDir, filename)
	}
	err := pdf.OutputFileAndClose(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to generate PDF: %w", err)
	}

	return outPath, nil
}

// extractURL extracts a clean URL from a string
func extractURL(s string) string {
	start := strings.Index(s, "http")
	if start == -1 {
		return ""
	}
	end := len(s)
	delimiters := []string{" ", "\"", "'", ">", "<", "|", "\n", "\r"}
	for _, d := range delimiters {
		if idx := strings.Index(s[start:], d); idx != -1 && start+idx < end {
			end = start + idx
		}
	}
	url := s[start:end]
	url = strings.TrimSpace(url)
	url = strings.TrimRight(url, ".,;:!)]}>")
	return url
}
