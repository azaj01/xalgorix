// Package skills provides the read_skill and list_skills tools for on-demand knowledge loading.
package skills

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

//go:embed data/*/*/*
var embeddedSkills embed.FS

// Register adds skill tools to the registry.
func Register(r *tools.Registry, _ string) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		// Should not happen unless embed is empty
		subFS = embeddedSkills
	}
	r.Register(&tools.Tool{
		Name:        "read_skill",
		Description: "Load a structured cybersecurity skill to get deep testing/defense methodology, tooling commands, and verification steps. Use this BEFORE attempting work in a specific domain (e.g., read_skill name=analyzing-active-directory-acl-abuse). The skill catalog is sourced from the agentskills.io standard and covers offensive testing, threat hunting, DFIR, cloud, mobile, OT/ICS, AI security, and more. Run list_skills first to discover what's available.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Kebab-case skill name without extension (e.g., performing-memory-forensics-with-volatility3, analyzing-active-directory-acl-abuse). Use list_skills to discover names.", Required: true},
			{Name: "category", Description: "Optional category to disambiguate (e.g., web-application-security, threat-hunting, reconnaissance). If omitted, all categories are searched.", Required: false},
		},
		Execute: makeReadSkill(subFS),
	})

	r.Register(&tools.Tool{
		Name:        "list_skills",
		Description: "List all available skills organized by category. Call this to see what deep knowledge is available before deciding which skills to load for your current engagement.",
		Parameters: []tools.Parameter{
			{Name: "category", Description: "Optional category filter (e.g., web-application-security, malware-analysis, reconnaissance). Omit to list all.", Required: false},
		},
		Execute: makeListSkills(subFS),
	})
}

// listCategories returns the set of category directories that exist on the
// embedded skill filesystem. This replaces the previous hardcoded list so
// adding a new category folder is a zero-code change.
func listCategories(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil
	}
	cats := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "" || name == "." || strings.HasPrefix(name, ".") {
			continue
		}
		cats = append(cats, name)
	}
	sort.Strings(cats)
	return cats
}

// skillAliases maps common shorthand names to their canonical full skill
// directory names. This lets the LLM agent use natural terms like "xss",
// "sqli", or "ssrf" without knowing the verbose directory name.
var skillAliases = map[string]string{
	// ── Web application vulnerabilities ──────────────────────────────
	"sql-injection":                    "exploiting-sql-injection-vulnerabilities",
	"sqli":                             "exploiting-sql-injection-vulnerabilities",
	"sql-injection-sqlmap":             "exploiting-sql-injection-with-sqlmap",
	"sqlmap":                           "exploiting-sql-injection-with-sqlmap",
	"nosql-injection":                  "exploiting-nosql-injection-vulnerabilities",
	"nosqli":                           "exploiting-nosql-injection-vulnerabilities",
	"xss":                              "testing-for-xss-vulnerabilities",
	"cross-site-scripting":             "testing-for-xss-vulnerabilities",
	"xss-burp":                         "testing-for-xss-vulnerabilities-with-burpsuite",
	"ssrf":                             "performing-ssrf-vulnerability-exploitation",
	"blind-ssrf":                       "performing-blind-ssrf-exploitation",
	"csrf":                             "performing-csrf-attack-simulation",
	"cross-site-request-forgery":       "performing-csrf-attack-simulation",
	"xxe":                              "testing-for-xxe-injection-vulnerabilities",
	"xml-external-entity":              "testing-for-xxe-injection-vulnerabilities",
	"idor":                             "exploiting-idor-vulnerabilities",
	"insecure-direct-object-reference": "exploiting-idor-vulnerabilities",
	"ssti":                             "exploiting-template-injection-vulnerabilities",
	"template-injection":               "exploiting-template-injection-vulnerabilities",
	"server-side-template-injection":   "exploiting-template-injection-vulnerabilities",
	"cors":                             "testing-cors-misconfiguration",
	"cors-misconfiguration":            "testing-cors-misconfiguration",
	"open-redirect":                    "testing-for-open-redirect-vulnerabilities",
	"clickjacking":                     "performing-clickjacking-attack-test",
	"deserialization":                  "exploiting-insecure-deserialization",
	"insecure-deserialization":         "exploiting-insecure-deserialization",
	"race-condition":                   "exploiting-race-condition-vulnerabilities",
	"mass-assignment":                  "exploiting-mass-assignment-in-rest-apis",
	"api-injection":                    "exploiting-api-injection-vulnerabilities",
	"command-injection":                "detecting-modbus-command-injection-attacks",

	// ── Authentication & authorization ───────────────────────────────
	"jwt":               "exploiting-jwt-algorithm-confusion-attack",
	"jwt-attack":        "exploiting-jwt-algorithm-confusion-attack",
	"jwt-signing":       "implementing-jwt-signing-and-verification",
	"oauth":             "exploiting-oauth-misconfiguration",
	"oauth-misconfig":   "exploiting-oauth-misconfiguration",
	"oauth-token-theft": "detecting-oauth-token-theft",
	"forced-browsing":   "bypassing-authentication-with-forced-browsing",
	"brute-force":       "detecting-rdp-brute-force-attacks",
	"passwordless":      "implementing-passwordless-authentication-with-fido2",
	"fido2":             "implementing-passwordless-authentication-with-fido2",

	// ── Reconnaissance ───────────────────────────────────────────────
	"recon":             "conducting-external-reconnaissance-with-osint",
	"reconnaissance":    "conducting-external-reconnaissance-with-osint",
	"osint":             "performing-open-source-intelligence-gathering",
	"subdomain":         "performing-subdomain-enumeration-with-subfinder",
	"subdomain-enum":    "performing-subdomain-enumeration-with-subfinder",
	"subfinder":         "performing-subdomain-enumeration-with-subfinder",
	"nmap":              "scanning-network-with-nmap-advanced",
	"network-scan":      "scanning-network-with-nmap-advanced",
	"api-enumeration":   "detecting-api-enumeration-attacks",
	"shadow-api":        "detecting-shadow-api-endpoints",
	"cert-transparency": "analyzing-certificate-transparency-for-phishing",

	// ── API security ─────────────────────────────────────────────────
	"api-security":      "conducting-api-security-testing",
	"api-gateway":       "implementing-api-gateway-security-controls",
	"api-rate-limiting": "implementing-api-rate-limiting-and-throttling",
	"api-schema":        "implementing-api-schema-validation-security",
	"api-keys":          "implementing-api-key-security-controls",
	"api-abuse":         "implementing-api-abuse-detection-with-rate-limiting",
	"api-posture":       "implementing-api-security-posture-management",
	"data-exposure":     "exploiting-excessive-data-exposure-in-api",

	// ── Active Directory ─────────────────────────────────────────────
	"ad-pentest":       "performing-active-directory-penetration-test",
	"active-directory": "performing-active-directory-penetration-test",
	"bloodhound":       "exploiting-active-directory-with-bloodhound",
	"ad-acl":           "analyzing-active-directory-acl-abuse",
	"kerberoasting":    "performing-active-directory-penetration-test",
	"dcsync":           "detecting-dcsync-attack-in-active-directory",
	"ad-cert":          "exploiting-active-directory-certificate-services-esc1",

	// ── Lateral movement & privilege escalation ──────────────────────
	"lateral-movement":     "detecting-lateral-movement-in-network",
	"privilege-escalation": "detecting-privilege-escalation-attempts",
	"privesc":              "detecting-privilege-escalation-attempts",
	"aws-privesc":          "detecting-aws-iam-privilege-escalation",
	"azure-lateral":        "detecting-azure-lateral-movement",
	"dcom":                 "hunting-for-dcom-lateral-movement",
	"wmi":                  "hunting-for-lateral-movement-via-wmi",

	// ── Phishing ─────────────────────────────────────────────────────
	"phishing":            "conducting-phishing-incident-response",
	"spearphishing":       "conducting-spearphishing-simulation-campaign",
	"phishing-simulation": "executing-phishing-simulation-campaign",
	"qr-phishing":         "detecting-qr-code-phishing-with-email-security",
	"email-headers":       "analyzing-email-headers-for-phishing-investigation",

	// ── Cloud & Kubernetes ───────────────────────────────────────────
	"k8s-privesc":    "detecting-privilege-escalation-in-kubernetes-pods",
	"opa-gatekeeper": "implementing-opa-gatekeeper-for-policy-enforcement",
	"azure-ad":       "auditing-azure-active-directory-configuration",
	"azure-pim":      "implementing-azure-ad-privileged-identity-management",

	// ── Memory / binary exploitation ─────────────────────────────────
	"heap-spray": "analyzing-heap-spray-exploitation",

	// ── Detection & monitoring ───────────────────────────────────────
	"sql-injection-waf": "detecting-sql-injection-via-waf-logs",
	"lateral-splunk":    "detecting-lateral-movement-with-splunk",
	"lateral-zeek":      "detecting-lateral-movement-with-zeek",

	// ── Mobile ───────────────────────────────────────────────────────
	"burpsuite-mobile": "intercepting-mobile-traffic-with-burpsuite",
	"burp":             "intercepting-mobile-traffic-with-burpsuite",

	// ── File upload testing ──────────────────────────────────────────
	"file-upload":     "exploiting-file-upload-vulnerabilities",
	"upload":          "exploiting-file-upload-vulnerabilities",
	"upload-bypass":   "exploiting-file-upload-vulnerabilities",
	"webshell-upload": "exploiting-file-upload-vulnerabilities",

	// ── CMS-specific testing ────────────────────────────────────────
	"cms":         "performing-cms-specific-security-testing",
	"cms-testing": "performing-cms-specific-security-testing",
	"wordpress":   "performing-cms-specific-security-testing",
	"wpscan":      "performing-cms-specific-security-testing",
	"drupal":      "performing-cms-specific-security-testing",
	"joomla":      "performing-cms-specific-security-testing",

	// ── Subdomain takeover ──────────────────────────────────────────
	"subdomain-takeover": "exploiting-subdomain-takeover-vulnerabilities",
	"takeover":           "exploiting-subdomain-takeover-vulnerabilities",
	"dangling-cname":     "exploiting-subdomain-takeover-vulnerabilities",

	// ── Zero-day & novel vulnerability discovery ────────────────────
	"zero-day":        "performing-zero-day-vulnerability-discovery",
	"0day":            "performing-zero-day-vulnerability-discovery",
	"novel-vuln":      "performing-zero-day-vulnerability-discovery",
	"attack-chaining": "performing-zero-day-vulnerability-discovery",
	"logic-flaw":      "performing-zero-day-vulnerability-discovery",

	// ── Exploit verification ────────────────────────────────────────
	"exploit-verification": "performing-exploit-verification",
	"verify-exploit":       "performing-exploit-verification",
	"false-positive":       "performing-exploit-verification",
	"proof-of-concept":     "performing-exploit-verification",
	"poc":                  "performing-exploit-verification",

	// ── Email security testing ──────────────────────────────────────
	"email-security": "performing-email-security-testing",
	"email-testing":  "performing-email-security-testing",
	"smtp-relay":     "performing-email-security-testing",
	"email-spoofing": "performing-email-security-testing",
	"spf-bypass":     "performing-email-security-testing",

	// ── Misc ─────────────────────────────────────────────────────────
	"darkweb": "monitoring-darkweb-sources",
	"dmarc":   "performing-dmarc-policy-enforcement-rollout",
}

// resolveAlias returns the canonical skill name for a shorthand alias.
// If no alias matches, the original name is returned unchanged.
func resolveAlias(name string) string {
	key := strings.ToLower(name)
	if canonical, ok := skillAliases[key]; ok {
		return canonical
	}
	return name
}

func makeReadSkill(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		name := strings.TrimSpace(args["name"])
		category := strings.TrimSpace(args["category"])

		// Sanitize category (only allow alphanum and dash)
		category = sanitizeSlug(category)

		if name == "" {
			return tools.Result{Error: "skill name is required"}, nil
		}

		// Strip a trailing /SKILL.md, .md, or any extension the user supplied,
		// then sanitize. This accepts both old-style ("sql_injection") and
		// kebab-case names as exposed by list_skills.
		name = strings.TrimSuffix(name, "/SKILL.md")
		name = strings.TrimSuffix(name, ".md")
		name = sanitizeSlug(name)
		if name == "" {
			return tools.Result{Error: "skill name is empty after sanitization"}, nil
		}

		// Resolve common shorthand aliases (e.g. "xss" → full skill name).
		name = resolveAlias(name)

		// If a category was specified, look there first.
		if category != "" {
			skillPath := category + "/" + name + "/SKILL.md"
			if data, err := fs.ReadFile(fsys, skillPath); err == nil {
				return tools.Result{Output: string(data)}, nil
			}
		}

		// Fallback: scan every category. With ~754 entries this is still fast
		// because fs.ReadFile on an embedded FS is O(1) per lookup.
		if found, where := searchAllCategories(fsys, name); found != "" {
			out := found
			if category != "" && where != category {
				out = fmt.Sprintf("Note: skill not found in category '%s'; loaded from '%s'.\n\n%s",
					category, where, found)
			}
			return tools.Result{Output: out}, nil
		}

		// Best-effort hint when the user has a near-match name.
		hint := fuzzyHint(fsys, name)
		errMsg := fmt.Sprintf("skill not found: %s — use list_skills to see available skills", name)
		if hint != "" {
			errMsg += "\nDid you mean: " + hint
		}
		return tools.Result{Error: errMsg}, nil
	}
}

// sanitizeSlug keeps only alphanumerics, dash, and underscore. This both
// prevents path traversal and normalizes user input.
func sanitizeSlug(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		}
		return -1
	}, s)
}

// searchAllCategories looks up `<category>/<name>/SKILL.md` across every
// category directory currently embedded. Returns the file contents and the
// category it was found under.
func searchAllCategories(fsys fs.FS, name string) (string, string) {
	for _, cat := range listCategories(fsys) {
		path := cat + "/" + name + "/SKILL.md"
		if data, err := fs.ReadFile(fsys, path); err == nil {
			return string(data), cat
		}
	}
	return "", ""
}

// fuzzyHint returns up to 3 skill names whose lowercase form contains the
// query as a substring. Used to nudge the LLM toward a valid name when a
// lookup fails. Empty string when no candidates match.
func fuzzyHint(fsys fs.FS, query string) string {
	q := strings.ToLower(query)
	if q == "" {
		return ""
	}
	var matches []string
	for _, cat := range listCategories(fsys) {
		entries, err := fs.ReadDir(fsys, cat)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			n := e.Name()
			if strings.Contains(strings.ToLower(n), q) {
				matches = append(matches, n)
				if len(matches) >= 3 {
					return strings.Join(matches, ", ")
				}
			}
		}
	}
	return strings.Join(matches, ", ")
}

func makeListSkills(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		filterCat := strings.TrimSpace(args["category"])
		filterCat = sanitizeSlug(filterCat)

		var categories []string
		if filterCat != "" {
			categories = []string{filterCat}
		} else {
			categories = listCategories(fsys)
		}

		var b strings.Builder
		b.WriteString("Available Skills\n\n")

		totalSkills := 0
		for _, cat := range categories {
			entries, err := fs.ReadDir(fsys, cat)
			if err != nil {
				continue
			}

			var skills []string
			for _, e := range entries {
				// Only list directories (skill packages)
				if !e.IsDir() || e.Name() == ".gitkeep" {
					continue
				}
				skills = append(skills, e.Name())
			}

			if len(skills) == 0 {
				continue
			}

			sort.Strings(skills)
			totalSkills += len(skills)

			b.WriteString(fmt.Sprintf("### %s (%d skills)\n", strings.ToUpper(cat), len(skills)))
			for _, s := range skills {
				b.WriteString(fmt.Sprintf("  - %s\n", s))
			}
			b.WriteString("\n")
		}

		b.WriteString(fmt.Sprintf("Total: %d skills available\n", totalSkills))
		b.WriteString("\nUsage: read_skill(name=\"skill_name\")  -- category is optional\n")

		return tools.Result{Output: b.String()}, nil
	}
}
