package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// ---------------------------------------------------------------------------
// overBudget — resource caps / early stopping (MAPTA §2.7/§3.3)
// ---------------------------------------------------------------------------

func TestOverBudget_NilConfig(t *testing.T) {
	a := &Agent{}
	if over, _ := a.overBudget(1_000_000); over {
		t.Fatal("nil cfg must never be over budget")
	}
}

func TestOverBudget_AllUnlimitedByDefault(t *testing.T) {
	a := &Agent{cfg: &config.Config{}} // all caps 0 = unlimited
	a.scanStart = time.Now().Add(-24 * time.Hour)
	if over, why := a.overBudget(1_000_000); over {
		t.Fatalf("zero caps must be unlimited, got over=%v (%s)", over, why)
	}
}

func TestOverBudget_ToolCallCap(t *testing.T) {
	a := &Agent{cfg: &config.Config{MaxToolCalls: 5}}
	if over, _ := a.overBudget(4); over {
		t.Fatal("4 < cap 5 must not be over")
	}
	if over, why := a.overBudget(5); !over {
		t.Fatal("5 >= cap 5 must be over")
	} else if !strings.Contains(why, "tool calls") {
		t.Fatalf("reason should mention tool calls, got %q", why)
	}
	if over, _ := a.overBudget(9); !over {
		t.Fatal("9 >= cap 5 must be over")
	}
}

func TestOverBudget_DurationCap(t *testing.T) {
	a := &Agent{cfg: &config.Config{MaxDurationSec: 10}}
	// scanStart zero → duration check is skipped (guarded).
	if over, _ := a.overBudget(0); over {
		t.Fatal("zero scanStart must skip the duration cap")
	}
	// Elapsed beyond cap → over.
	a.scanStart = time.Now().Add(-30 * time.Second)
	if over, why := a.overBudget(0); !over {
		t.Fatal("30s elapsed >= 10s cap must be over")
	} else if !strings.Contains(why, "time") {
		t.Fatalf("reason should mention time, got %q", why)
	}
	// Fresh start → under.
	a.scanStart = time.Now()
	if over, _ := a.overBudget(0); over {
		t.Fatal("fresh start must be under the duration cap")
	}
}

func TestOverBudget_TokenCapSkippedWithNilClient(t *testing.T) {
	// MaxTokens set but client nil → the token branch must be skipped
	// safely (no nil deref), reporting not-over.
	a := &Agent{cfg: &config.Config{MaxTokens: 1}}
	if over, _ := a.overBudget(0); over {
		t.Fatal("token cap must be skipped when client is nil")
	}
}

// ---------------------------------------------------------------------------
// redactSecrets — operator credentials must never leak into telemetry
// ---------------------------------------------------------------------------

func TestRedactSecrets(t *testing.T) {
	a := &Agent{secretValues: []string{"s3cr3t-token-value", "cookievalue123"}}

	if got := a.redactSecrets(""); got != "" {
		t.Fatalf("empty input must return empty, got %q", got)
	}
	in := "Authorization: Bearer s3cr3t-token-value and Cookie: x=cookievalue123"
	got := a.redactSecrets(in)
	if strings.Contains(got, "s3cr3t-token-value") || strings.Contains(got, "cookievalue123") {
		t.Fatalf("secrets leaked after redaction: %q", got)
	}
	if !strings.Contains(got, "***REDACTED***") {
		t.Fatalf("expected redaction marker, got %q", got)
	}
}

func TestRedactSecrets_NoSecretsConfigured(t *testing.T) {
	a := &Agent{}
	in := "nothing to redact here"
	if got := a.redactSecrets(in); got != in {
		t.Fatalf("with no secrets the string must pass through unchanged, got %q", got)
	}
}

func TestRedactSecrets_SkipsEmptySecretEntry(t *testing.T) {
	// An empty entry in secretValues must not cause every string to be
	// mangled (strings.Contains(s, "") is always true).
	a := &Agent{secretValues: []string{""}}
	in := "harmless content"
	if got := a.redactSecrets(in); got != in {
		t.Fatalf("empty secret entry must be ignored, got %q", got)
	}
}

func TestCredentialsInURL(t *testing.T) {
	// A tokenized GitHub clone URL must yield the userinfo AND the token so
	// both are redacted from telemetry/logs/git errors.
	creds := credentialsInURL("https://x-access-token:ghp_abcd1234efgh@github.com/org/repo.git")
	joined := strings.Join(creds, "|")
	if !strings.Contains(joined, "ghp_abcd1234efgh") {
		t.Fatalf("token not extracted for redaction: %v", creds)
	}
	if !strings.Contains(joined, "x-access-token:ghp_abcd1234efgh") {
		t.Fatalf("full userinfo not extracted: %v", creds)
	}

	// A plain (public) URL has no credentials to redact.
	if got := credentialsInURL("https://github.com/org/repo.git"); got != nil {
		t.Fatalf("public URL must yield no credentials, got %v", got)
	}
	// A bare path / non-URL yields nothing.
	if got := credentialsInURL("/local/path/to/source"); got != nil {
		t.Fatalf("local path must yield no credentials, got %v", got)
	}
	// A short token is skipped (avoids redacting trivial substrings), but the
	// combined userinfo is still long enough to register.
	creds = credentialsInURL("https://u:xy@host/r.git")
	if strings.Contains(strings.Join(creds, "|"), "|xy") {
		t.Fatalf("short token should be skipped, got %v", creds)
	}
}

// ---------------------------------------------------------------------------
// Per-scan setters
// ---------------------------------------------------------------------------

func TestSetTargetAuthTrims(t *testing.T) {
	a := &Agent{}
	a.SetTargetAuth("   Cookie: s=1   ")
	if a.targetAuth != "Cookie: s=1" {
		t.Fatalf("targetAuth = %q, want trimmed", a.targetAuth)
	}
	a.SetTargetAuth("   ")
	if a.targetAuth != "" {
		t.Fatalf("whitespace-only must clear targetAuth, got %q", a.targetAuth)
	}
}

func TestSetSourceRepoTrims(t *testing.T) {
	a := &Agent{}
	a.SetSourceRepo("  https://github.com/x/y.git \n")
	if a.sourceRepo != "https://github.com/x/y.git" {
		t.Fatalf("sourceRepo = %q, want trimmed", a.sourceRepo)
	}
}

// ---------------------------------------------------------------------------
// authGuidance — briefing only when credentials supplied
// ---------------------------------------------------------------------------

func TestAuthGuidance_EmptyWhenNoAuth(t *testing.T) {
	a := &Agent{}
	if g := a.authGuidance(); g != "" {
		t.Fatalf("no auth must yield empty guidance, got %q", g)
	}
}

func TestAuthGuidance_SecondAccountBOLA(t *testing.T) {
	a := &Agent{
		targetAuth:  "Authorization: Bearer accountA",
		targetAuthB: "Authorization: Bearer accountB",
	}
	g := a.authGuidance()
	for _, want := range []string{"SECOND ACCOUNT", "BOLA", "accountB", "horizontal access"} {
		if !strings.Contains(g, want) {
			t.Errorf("second-account guidance missing %q:\n%s", want, g)
		}
	}
	// Account B's token must appear (so the agent can use it) — redaction of
	// telemetry is handled separately at emit time.
	if !strings.Contains(g, "accountB") {
		t.Fatal("expected account B token in guidance")
	}
	// Without a second account, no SECOND ACCOUNT section.
	a2 := &Agent{targetAuth: "Authorization: Bearer only"}
	if strings.Contains(a2.authGuidance(), "SECOND ACCOUNT") {
		t.Fatal("no second-account section expected when B is unset")
	}
}

func TestAuthGuidance_MentionsHeadersAndPostAuthSurface(t *testing.T) {
	a := &Agent{targetAuth: "Cookie: session=abc; Authorization: Bearer xyz"}
	g := a.authGuidance()
	if g == "" {
		t.Fatal("expected non-empty guidance when auth is configured")
	}
	for _, want := range []string{"AUTHENTICATED SESSION", "Cookie", "Authorization", "IDOR"} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance missing %q:\n%s", want, g)
		}
	}
}
