package billing

// File config_test.go covers every precedence branch in LoadConfig:
//
//   - missing DODO_PAYMENTS_API_KEY        -> ErrAPIKeyMissing
//   - whitespace-only DODO_PAYMENTS_API_KEY -> ErrAPIKeyMissing (post trim)
//   - DODO_PAYMENTS_ENVIRONMENT unset       -> defaults to test_mode
//   - DODO_PAYMENTS_ENVIRONMENT=test_mode   -> echoed
//   - DODO_PAYMENTS_ENVIRONMENT=live_mode   -> echoed
//   - DODO_PAYMENTS_ENVIRONMENT=other       -> ErrUnknownEnvironment
//   - DODO_PAYMENTS_WEBHOOK_KEY trimmed and propagated
//   - DODO_PAYMENTS_BASE_URL trimmed and propagated alongside Environment
//
// Requirements: 5.1

import (
	"errors"
	"testing"
)

// configEnv lists every environment variable the loader reads. Tests use
// t.Setenv per variable so default-unset cases stay default-unset.
var configEnv = []string{
	envAPIKey,
	envWebhookKey,
	envEnvironment,
	envBaseURL,
}

// applyEnv applies the supplied (var -> value) map for the duration of the
// test using t.Setenv. A nil value (absent from the map) means the variable
// is left unset; t.Setenv with the empty string would clobber that
// distinction, so we Unsetenv via os pkg through the test helper instead.
func applyEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range configEnv {
		if v, ok := env[k]; ok {
			t.Setenv(k, v)
		} else {
			// t.Setenv automatically restores the prior value on
			// cleanup; calling it with "" is sufficient because no
			// branch under test distinguishes "unset" from
			// "empty" — the loader trims and treats both as the
			// default case.
			t.Setenv(k, "")
		}
	}
}

func TestLoadConfig(t *testing.T) {
	// Note: cannot call t.Parallel here because every subtest uses
	// t.Setenv, which marks the parent test as non-parallelisable.
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr error
	}{
		{
			name: "api key missing returns ErrAPIKeyMissing",
			env: map[string]string{
				envEnvironment: EnvLiveMode,
			},
			wantErr: ErrAPIKeyMissing,
		},
		{
			name: "api key whitespace only returns ErrAPIKeyMissing",
			env: map[string]string{
				envAPIKey: "   \t  ",
			},
			wantErr: ErrAPIKeyMissing,
		},
		{
			name: "environment unset defaults to test_mode",
			env: map[string]string{
				envAPIKey: "sk_live_abc",
			},
			want: Config{
				APIKey:      "sk_live_abc",
				Environment: EnvTestMode,
			},
		},
		{
			name: "environment whitespace defaults to test_mode",
			env: map[string]string{
				envAPIKey:      "sk_test_abc",
				envEnvironment: "   ",
			},
			want: Config{
				APIKey:      "sk_test_abc",
				Environment: EnvTestMode,
			},
		},
		{
			name: "environment test_mode is echoed",
			env: map[string]string{
				envAPIKey:      "sk_test_abc",
				envEnvironment: EnvTestMode,
			},
			want: Config{
				APIKey:      "sk_test_abc",
				Environment: EnvTestMode,
			},
		},
		{
			name: "environment live_mode is echoed",
			env: map[string]string{
				envAPIKey:      "sk_live_abc",
				envEnvironment: EnvLiveMode,
			},
			want: Config{
				APIKey:      "sk_live_abc",
				Environment: EnvLiveMode,
			},
		},
		{
			name: "unknown environment is rejected",
			env: map[string]string{
				envAPIKey:      "sk_live_abc",
				envEnvironment: "production",
			},
			wantErr: ErrUnknownEnvironment,
		},
		{
			name: "webhook key is trimmed and propagated",
			env: map[string]string{
				envAPIKey:     "sk_test_abc",
				envWebhookKey: "  whk_xyz  ",
			},
			want: Config{
				APIKey:      "sk_test_abc",
				WebhookKey:  "whk_xyz",
				Environment: EnvTestMode,
			},
		},
		{
			name: "base url is trimmed and propagated alongside environment",
			env: map[string]string{
				envAPIKey:      "sk_live_abc",
				envEnvironment: EnvLiveMode,
				envBaseURL:     "  https://billing.example.com/v1  ",
			},
			want: Config{
				APIKey:      "sk_live_abc",
				Environment: EnvLiveMode,
				BaseURL:     "https://billing.example.com/v1",
			},
		},
		{
			name: "all fields together",
			env: map[string]string{
				envAPIKey:      " sk_live_abc ",
				envWebhookKey:  " whk_xyz ",
				envEnvironment: EnvLiveMode,
				envBaseURL:     " https://billing.example.com ",
			},
			want: Config{
				APIKey:      "sk_live_abc",
				WebhookKey:  "whk_xyz",
				Environment: EnvLiveMode,
				BaseURL:     "https://billing.example.com",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv mutates os.Environ and forbids t.Parallel
			// on this subtest or its parent. Subtests run
			// sequentially within TestLoadConfig as a result.
			applyEnv(t, tc.env)

			got, err := LoadConfig()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("LoadConfig err = %v, want errors.Is %v", err, tc.wantErr)
				}
				if got != (Config{}) {
					t.Fatalf("LoadConfig on error = %+v, want zero Config", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig unexpected err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("LoadConfig = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestResolveEnvironment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    string
		wantErr error
	}{
		{in: "", want: EnvTestMode},
		{in: "   ", want: EnvTestMode},
		{in: EnvTestMode, want: EnvTestMode},
		{in: EnvLiveMode, want: EnvLiveMode},
		{in: "  live_mode  ", want: EnvLiveMode},
		{in: "staging", wantErr: ErrUnknownEnvironment},
		{in: "TEST_MODE", wantErr: ErrUnknownEnvironment}, // case sensitive
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()
			got, err := resolveEnvironment(c.in)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("resolveEnvironment(%q) err = %v, want errors.Is %v", c.in, err, c.wantErr)
				}
				if got != "" {
					t.Fatalf("resolveEnvironment(%q) on error returned %q, want empty", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEnvironment(%q) unexpected err = %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("resolveEnvironment(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
