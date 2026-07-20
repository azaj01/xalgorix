package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

var requestRatePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bmax(?:imum)?\s+(?:of\s+)?([0-9]+(?:\.[0-9]+)?)\s*(?:requests?|reqs?)\s*(?:/|per)?\s*(?:second|sec|s)\b`),
	regexp.MustCompile(`(?i)\b(?:limit|cap|throttle)\s+(?:to|at)?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:requests?|reqs?|rps)\s*(?:/|per)?\s*(?:second|sec|s)?\b`),
	regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+)?)\s*(?:rps|req/s|reqs/s|requests?/s|requests?\s*/\s*(?:sec|second))\b`),
	regexp.MustCompile(`(?i)\b([0-9]+(?:\.[0-9]+)?)\s*(?:requests?|reqs?)\s+per\s+(?:second|sec)\b`),
}

func instructionRequestRatePolicy(instruction string) scanctx.RequestRatePolicy {
	instruction = strings.TrimSpace(instruction)
	if instruction == "" {
		return scanctx.RequestRatePolicy{}
	}
	for _, pattern := range requestRatePatterns {
		match := pattern.FindStringSubmatch(instruction)
		if len(match) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(match[1], 64)
		if err != nil || value <= 0 {
			continue
		}
		return scanctx.RequestRatePolicy{MaxRPS: value, Source: "custom instructions"}
	}
	return scanctx.RequestRatePolicy{}
}

// EffectiveRequestRatePolicy resolves the scan's outbound request budget. The
// most restrictive non-zero policy wins, so a user instruction such as
// "max 3 requests/sec" lowers the configured XALGORIX_RATE_RPS budget.
func EffectiveRequestRatePolicy(cfg *config.Config, instruction string) scanctx.RequestRatePolicy {
	var policy scanctx.RequestRatePolicy
	if cfg != nil && cfg.RateLimitRPS > 0 {
		policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS, Source: "XALGORIX_RATE_RPS"}
	}
	custom := instructionRequestRatePolicy(instruction)
	if custom.Enabled() && (!policy.Enabled() || custom.MaxRPS <= policy.MaxRPS) {
		policy = custom
	}
	return scanctx.NormalizeRequestRatePolicy(policy)
}

func buildRequestRatePolicySection(policy scanctx.RequestRatePolicy) string {
	if !policy.Enabled() {
		return ""
	}
	rate := formatRatePolicyValue(policy.MaxRPS)
	delay := formatRatePolicyDelay(policy)
	threads := policy.CommandRPS()
	return fmt.Sprintf(`### Request Rate Policy
- Effective outbound target-touching request budget: **max %s requests/second** (%s).
- This overrides every methodology example and every tool default for TARGET-HAMMERING tools. Never choose a higher rate, timing template, thread count, or crawler concurrency for them.
- EXEMPT — subdomain discovery & liveness tools run at FULL speed: subfinder, assetfinder, findomain, amass, dnsx, httpx, puredns, massdns, shuffledns, alterx. They hit third-party sources or fan out ONE request across many distinct hosts, so the per-target cap does not apply. Use high concurrency/rate for these so enumeration of large targets actually completes.
- For nuclei/katana/naabu/feroxbuster (they focus load on one host/app), use rate flags at or below %d and keep concurrency at or below %d.
- For nmap, do not use -T4/-T5 or --min-rate. Use -T2, --max-rate %d, and --scan-delay %s or slower.
- For ffuf, use -rate %d and -t %d or lower. For gobuster, use --delay %s and a single worker because it has no reliable global RPS limiter.
- For custom loops, xargs, parallel, or scripts, add sleeps/delays so aggregate traffic stays under %s requests/second.`, rate, policy.Source, threads, threads, threads, delay, threads, threads, delay, rate)
}

func rateLimitedChecklist(checklist string, policy scanctx.RequestRatePolicy) string {
	if !policy.Enabled() {
		if cfg := config.Get(); cfg != nil && cfg.RateLimitRPS > 0 {
			policy = scanctx.RequestRatePolicy{MaxRPS: cfg.RateLimitRPS, Source: "XALGORIX_RATE_RPS"}
		}
	}
	if !policy.Enabled() {
		policy = scanctx.RequestRatePolicy{MaxRPS: 1, Source: "safe fallback"}
	}
	rate := strconv.Itoa(policy.CommandRPS())
	delay := formatRatePolicyDelay(policy)
	checklist = strings.ReplaceAll(checklist, "RATE_LIMIT", rate)
	checklist = strings.ReplaceAll(checklist, "RATE_DELAY", delay)
	return checklist
}

func formatRatePolicyValue(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(value, 'f', 3, 64), "0"), ".")
}

func formatRatePolicyDelay(policy scanctx.RequestRatePolicy) string {
	delay := policy.Delay()
	if delay <= 0 {
		return "0ms"
	}
	if delay%time.Second == 0 {
		return strconv.Itoa(int(delay/time.Second)) + "s"
	}
	return strconv.Itoa(int(delay/time.Millisecond)) + "ms"
}
