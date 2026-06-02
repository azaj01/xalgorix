package billing

// File config.go implements task 4.1 of the xalgorix-saas spec: a config
// loader for the Dodo Payments client that mirrors the precedence rules in
// BugReportly/lib/dodoPayments.js (functions getDodoEnvironment and
// getDodoClient).
//
// The four environment variables are:
//
//   - DODO_PAYMENTS_API_KEY      (required, trimmed)
//   - DODO_PAYMENTS_WEBHOOK_KEY  (optional, trimmed)
//   - DODO_PAYMENTS_ENVIRONMENT  (optional, defaults to "test_mode";
//                                 only "test_mode" and "live_mode" accepted)
//   - DODO_PAYMENTS_BASE_URL     (optional, trimmed; overrides Environment)
//
// Requirements: 5.1

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Environment values recognised by Dodo Payments. The JS reference encodes
// these as a Set (DODO_ENVIRONMENTS) keyed on the string literal values.
const (
	EnvTestMode = "test_mode"
	EnvLiveMode = "live_mode"
)

// Environment variable names. Centralising them here keeps the loader, the
// table tests, and any docs/CI checks in lock-step.
const (
	envAPIKey      = "DODO_PAYMENTS_API_KEY"
	envWebhookKey  = "DODO_PAYMENTS_WEBHOOK_KEY"
	envEnvironment = "DODO_PAYMENTS_ENVIRONMENT"
	envBaseURL     = "DODO_PAYMENTS_BASE_URL"
)

// Config holds the resolved Dodo Payments configuration. The shape matches
// the design document's "Billing Integration → Configuration" snippet so that
// downstream tasks (4.2 NewClient, 4.5 Webhook handler) can consume it
// without further translation.
type Config struct {
	// APIKey is the Dodo bearer token (DODO_PAYMENTS_API_KEY). Always set
	// on a Config returned by LoadConfig.
	APIKey string
	// WebhookKey is the HMAC secret used to verify Dodo webhooks. May be
	// empty when DODO_PAYMENTS_WEBHOOK_KEY is unset; the webhook handler
	// is the only caller that must enforce its presence (task 4.5).
	WebhookKey string
	// Environment is one of EnvTestMode or EnvLiveMode. Defaults to
	// EnvTestMode when DODO_PAYMENTS_ENVIRONMENT is unset.
	Environment string
	// BaseURL, when non-empty, overrides the hosted URL derived from
	// Environment. Mirrors the JS reference where setting baseURL omits
	// the environment field on the SDK options.
	BaseURL string
}

// Sentinel errors. They are returned from LoadConfig and wrapped with %w so
// callers can use errors.Is to discriminate without parsing strings.
var (
	// ErrAPIKeyMissing is returned when DODO_PAYMENTS_API_KEY is unset
	// or contains only whitespace. This is fatal — the SDK cannot be
	// constructed without a bearer token.
	ErrAPIKeyMissing = errors.New("billing: DODO_PAYMENTS_API_KEY is not configured")
	// ErrUnknownEnvironment is returned when DODO_PAYMENTS_ENVIRONMENT
	// is set to something other than "test_mode" or "live_mode". The JS
	// reference silently coerces unknown values to "test_mode"; the Go
	// loader is stricter so misconfiguration is detected at boot rather
	// than after a failed live charge.
	ErrUnknownEnvironment = errors.New("billing: DODO_PAYMENTS_ENVIRONMENT must be \"test_mode\" or \"live_mode\"")
)

// LoadConfig resolves a Config from the process environment using the
// precedence rules described in the package overview. The function is
// pure with respect to its inputs: every value is read through os.Getenv
// at call time.
//
// On success it returns a Config whose APIKey is non-empty and whose
// Environment is exactly one of EnvTestMode or EnvLiveMode. WebhookKey and
// BaseURL are returned as-is (post trim) and may be empty.
//
// On failure it returns the zero Config and one of the sentinel errors
// above. The error chain is preserved so callers can write
// errors.Is(err, ErrUnknownEnvironment).
func LoadConfig() (Config, error) {
	cfg := Config{
		APIKey:     strings.TrimSpace(os.Getenv(envAPIKey)),
		WebhookKey: strings.TrimSpace(os.Getenv(envWebhookKey)),
		BaseURL:    strings.TrimSpace(os.Getenv(envBaseURL)),
	}

	if cfg.APIKey == "" {
		return Config{}, ErrAPIKeyMissing
	}

	env, err := resolveEnvironment(os.Getenv(envEnvironment))
	if err != nil {
		return Config{}, err
	}
	cfg.Environment = env

	return cfg, nil
}

// resolveEnvironment applies the JS reference's environment precedence:
// trim, default to EnvTestMode when empty, otherwise require an exact
// match against the recognised set. Returning a wrapped sentinel keeps
// errors.Is(err, ErrUnknownEnvironment) usable while still surfacing the
// offending value to operators.
func resolveEnvironment(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	switch trimmed {
	case "":
		return EnvTestMode, nil
	case EnvTestMode, EnvLiveMode:
		return trimmed, nil
	default:
		return "", fmt.Errorf("%w: got %q", ErrUnknownEnvironment, trimmed)
	}
}
