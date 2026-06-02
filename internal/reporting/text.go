package reporting

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ParseTime tolerates both RFC3339 and RFC3339Nano. An empty string or any
// unparseable value yields the zero time so callers can render a
// "Not recorded" placeholder.
func ParseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

// FormatDate renders a date for cover-page display. Zero values produce the
// "Not recorded" placeholder used throughout the report.
func FormatDate(t time.Time) string {
	if t.IsZero() {
		return "Not recorded"
	}
	return t.Format("January 2, 2006")
}

// FormatTimestamp renders a timestamp suitable for the metadata table and
// the Blue Team correlation appendix.
func FormatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "Not recorded"
	}
	return t.Format("2006-01-02 15:04:05 MST")
}

// FormatDuration renders a human-readable wall-clock duration between two
// times. If the start or end is missing, or the end precedes the start,
// the report shows "In progress".
func FormatDuration(startTime, endTime time.Time) string {
	if startTime.IsZero() || endTime.IsZero() || endTime.Before(startTime) {
		return "In progress"
	}
	d := endTime.Sub(startTime).Round(time.Second)
	if d.Hours() >= 1 {
		return fmt.Sprintf("%dh %dm %ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
	}
	if d.Minutes() >= 1 {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// DisplayText collapses runs of whitespace, falls back to a placeholder
// when empty, and rune-truncates to max characters with an ellipsis. The
// behavior is byte-identical to the previous reportDisplayText helper.
func DisplayText(value string, fallback string, max int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		value = fallback
	}
	if max > 0 && len([]rune(value)) > max {
		runes := []rune(value)
		return string(runes[:max-3]) + "..."
	}
	return value
}

// HostLabel extracts a hostname from a target string. It tolerates targets
// without a scheme (re-parses with https:// prepended) and ultimately
// falls back to a slash-trimmed copy of the original target.
func HostLabel(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return "Target"
	}
	parsed, err := url.Parse(target)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if !strings.Contains(target, "://") {
		if parsed, err := url.Parse("https://" + target); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return strings.Trim(target, "/")
}

// BrandName resolves the cover-page brand string for a scan. It prefers a
// caller-supplied company name, then the scan name, then the parsed host,
// then the raw target. Empty / nil input returns "Target".
func BrandName(scan *Scan) string {
	if scan == nil {
		return "Target"
	}
	for _, candidate := range []string{scan.CompanyName, scan.Name, HostLabel(scan.Target), scan.Target} {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			return candidate
		}
	}
	return "Target"
}

// Initials produces a one-or-two-character monogram for the cover-page
// fallback when no logo image is supplied. Punctuation and whitespace are
// treated as word separators; only ASCII alphanumerics survive.
func Initials(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "XT"
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '-' || r == '_' || r == '.' || r == '/' || r == ':'
	})
	initials := ""
	for _, part := range parts {
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				if r >= 'a' && r <= 'z' {
					r -= 'a' - 'A'
				}
				initials += string(r)
				break
			}
		}
		if len(initials) >= 2 {
			break
		}
	}
	if initials == "" {
		return "XT"
	}
	return initials
}

// PrepareCodeBlock soft-wraps a raw payload (PoC script, exploitation
// proof, raw endpoint) to fit a fixed-width code box in the PDF. Lines
// beyond maxLines are dropped with a "(truncated)" marker.
func PrepareCodeBlock(content string, maxLines, maxCols int) string {
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return ""
	}
	var out []string
	truncated := false
	for _, line := range strings.Split(content, "\n") {
		runes := []rune(line)
		if len(runes) == 0 {
			out = append(out, "")
		}
		for len(runes) > 0 {
			if len(out) >= maxLines {
				truncated = true
				break
			}
			take := maxCols
			if len(runes) < take {
				take = len(runes)
			}
			out = append(out, string(runes[:take]))
			runes = runes[take:]
		}
		if truncated {
			break
		}
	}
	if truncated || len(out) > maxLines {
		if len(out) >= maxLines {
			out = out[:maxLines]
		}
		out = append(out, "... (truncated)")
	}
	return strings.Join(out, "\n")
}

// ExtractURL pulls a clean URL out of a free-form word. The URL ends at
// the first whitespace, quote, angle bracket, pipe, or newline; trailing
// punctuation is stripped.
func ExtractURL(s string) string {
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
	out := s[start:end]
	out = strings.TrimSpace(out)
	out = strings.TrimRight(out, ".,;:!)]}>")
	return out
}
