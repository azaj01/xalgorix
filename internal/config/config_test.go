package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvOr(t *testing.T) {
	// Unset env var should return fallback
	os.Unsetenv("TEST_XALGORIX_ENVVAR")
	if got := envOr("TEST_XALGORIX_ENVVAR", "default_val"); got != "default_val" {
		t.Errorf("expected 'default_val', got '%s'", got)
	}

	// Set env var should return it
	os.Setenv("TEST_XALGORIX_ENVVAR", "custom_val")
	defer os.Unsetenv("TEST_XALGORIX_ENVVAR")
	if got := envOr("TEST_XALGORIX_ENVVAR", "default_val"); got != "custom_val" {
		t.Errorf("expected 'custom_val', got '%s'", got)
	}
}

func TestEnvOrInt(t *testing.T) {
	os.Unsetenv("TEST_XALGORIX_INT")
	if got := envOrInt("TEST_XALGORIX_INT", 42); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}

	os.Setenv("TEST_XALGORIX_INT", "99")
	defer os.Unsetenv("TEST_XALGORIX_INT")
	if got := envOrInt("TEST_XALGORIX_INT", 42); got != 99 {
		t.Errorf("expected 99, got %d", got)
	}

	// Invalid int should return fallback
	os.Setenv("TEST_XALGORIX_INT", "not_a_number")
	if got := envOrInt("TEST_XALGORIX_INT", 42); got != 42 {
		t.Errorf("expected fallback 42 for invalid int, got %d", got)
	}
}

func TestEnvOrBool(t *testing.T) {
	os.Unsetenv("TEST_XALGORIX_BOOL")
	if got := envOrBool("TEST_XALGORIX_BOOL", false); got != false {
		t.Error("expected false for unset env")
	}

	trueValues := []string{"1", "true", "TRUE", "True", "yes", "YES", "Yes"}
	for _, v := range trueValues {
		os.Setenv("TEST_XALGORIX_BOOL", v)
		if got := envOrBool("TEST_XALGORIX_BOOL", false); got != true {
			t.Errorf("expected true for %q, got false", v)
		}
	}

	falseValues := []string{"0", "false", "no", "anything"}
	for _, v := range falseValues {
		os.Setenv("TEST_XALGORIX_BOOL", v)
		if got := envOrBool("TEST_XALGORIX_BOOL", false); got != false {
			t.Errorf("expected false for %q, got true", v)
		}
	}

	os.Unsetenv("TEST_XALGORIX_BOOL")
}

func TestLoadEnvFile(t *testing.T) {
	// Create temp env file
	dir := t.TempDir()
	envFile := filepath.Join(dir, "test.env")

	content := `# Comment line
XALGORIX_TEST_KEY1=value1
export XALGORIX_TEST_KEY2=value2
XALGORIX_TEST_KEY3="quoted_value"
XALGORIX_TEST_KEY4='single_quoted'

# Another comment
XALGORIX_TEST_KEY5=with=equals=signs
`
	os.WriteFile(envFile, []byte(content), 0644)

	// Clean up env vars
	defer func() {
		for i := 1; i <= 5; i++ {
			os.Unsetenv("XALGORIX_TEST_KEY" + string(rune('0'+i)))
		}
	}()

	loadEnvFile(envFile)

	tests := []struct {
		key  string
		want string
	}{
		{"XALGORIX_TEST_KEY1", "value1"},
		{"XALGORIX_TEST_KEY2", "value2"},
		{"XALGORIX_TEST_KEY3", "quoted_value"},
		{"XALGORIX_TEST_KEY4", "single_quoted"},
		{"XALGORIX_TEST_KEY5", "with=equals=signs"},
	}

	for _, tt := range tests {
		if got := os.Getenv(tt.key); got != tt.want {
			t.Errorf("%s: expected %q, got %q", tt.key, tt.want, got)
		}
	}
}

func TestLoadEnvFile_NonExistent(t *testing.T) {
	// Should not panic on missing file
	loadEnvFile("/nonexistent/path/.env")
}

func TestConfig_Validate(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty LLM")
	}

	cfg.LLM = "openai/gpt-5.4"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error with LLM set, got: %v", err)
	}
}

func TestConfig_WorkspacePath(t *testing.T) {
	cfg := &Config{Workspace: "/home/user/project"}

	// Relative path should be joined with workspace
	if got := cfg.WorkspacePath("subdir/file.txt"); got != "/home/user/project/subdir/file.txt" {
		t.Errorf("expected joined path, got: %s", got)
	}

	// Absolute path should be returned as-is
	if got := cfg.WorkspacePath("/absolute/path"); got != "/absolute/path" {
		t.Errorf("expected absolute path as-is, got: %s", got)
	}
}

func TestConfig_ResolveModel(t *testing.T) {
	cfg := &Config{LLM: "openai/gpt-5.4"}
	if api := cfg.ResolveModel(); api != "openai/gpt-5.4" {
		t.Errorf("expected 'openai/gpt-5.4', got %q", api)
	}

	cfg.LLM = ""
	if api := cfg.ResolveModel(); api != "" {
		t.Errorf("expected empty for empty LLM, got %q", api)
	}
}
