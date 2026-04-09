// Package config provides configuration management for Xalgorix.
// All configuration is loaded from environment variables with XALGORIX_ prefix.
package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Config holds all Xalgorix configuration.
type Config struct {
	// LLM settings
	LLM             string // XALGORIX_LLM — model name (e.g. "openai/gpt-5.4", "anthropic/claude-sonnet-4-6")
	APIBase         string // XALGORIX_API_BASE — API endpoint
	APIKey          string // XALGORIX_API_KEY — API key
	ReasoningEffort string // XALGORIX_REASONING_EFFORT — "low", "medium", "high"
	LLMMaxRetries   int    // XALGORIX_LLM_MAX_RETRIES
	MemCompTimeout  int    // XALGORIX_MEMORY_COMPRESSOR_TIMEOUT

	// Runtime settings
	RuntimeBackend string // XALGORIX_RUNTIME_BACKEND — always "native"
	Workspace      string // XALGORIX_WORKSPACE — workspace root dir
	DisableBrowser bool   // XALGORIX_DISABLE_BROWSER
	MaxIterations  int    // XALGORIX_MAX_ITERATIONS — 0 = unlimited

	// Rate limiting & API settings
	RateLimitRequests int // XALGORIX_RATE_LIMIT_REQUESTS — requests per window
	RateLimitWindow   int // XALGORIX_RATE_LIMIT_WINDOW — window in seconds

	// Caido proxy
	CaidoPort     int    // CAIDO_PORT
	CaidoAPIToken string // CAIDO_API_TOKEN

	// Telemetry
	Telemetry    bool   // XALGORIX_TELEMETRY
	OTelEndpoint string // XALGORIX_OTEL_ENDPOINT

	// Web Search API
	GeminiAPIKey string // GEMINI_API_KEY - for web search using Gemini

	// AgentMail - temp email for sign-up verification
	AgentMailAPIKey string // AGENTMAIL_API_KEY - AgentMail API key
	AgentMailPod    string // AGENTMAIL_POD - AgentMail pod (e.g., "am_us_pod_47")

	// Dashboard auth
	Username string // XALGORIX_USERNAME - dashboard login username
	Password string // XALGORIX_PASSWORD - dashboard login password

	// Paths
	HomeDir   string // ~/.xalgorix
	SkillsDir string // embedded or local skills directory
}

var (
	globalConfig *Config
	configOnce   sync.Once
)

// Get returns the global configuration singleton.
func Get() *Config {
	configOnce.Do(func() {
		globalConfig = load()
	})
	return globalConfig
}

// load reads all configuration from environment variables with defaults.
// It first loads env files so config works even under sudo.
func load() *Config {
	// Load env files (lower priority first, later files override)
	loadEnvFile("/etc/xalgorix.env")
	// Try the actual user's home (works even under sudo)
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		loadEnvFile(filepath.Join("/home", sudoUser, ".xalgorix.env"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: failed to get home directory: %v (using /root)", err)
		home = "/root"
	}
	loadEnvFile(filepath.Join(home, ".xalgorix.env"))

	xalgorixHome := filepath.Join(home, ".xalgorix")

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("Warning: failed to get working directory: %v", err)
		cwd = home
	}
	workspace := envOr("XALGORIX_WORKSPACE", cwd)

	cfg := &Config{
		// LLM
		LLM:             envOr("XALGORIX_LLM", ""),
		APIBase:         envOr("XALGORIX_API_BASE", ""),
		APIKey:          envOr("XALGORIX_API_KEY", ""),
		ReasoningEffort: envOr("XALGORIX_REASONING_EFFORT", "high"),
		LLMMaxRetries:   envOrInt("XALGORIX_LLM_MAX_RETRIES", 5),
		MemCompTimeout:  envOrInt("XALGORIX_MEMORY_COMPRESSOR_TIMEOUT", 30),

		// Runtime
		RuntimeBackend: "native", // Always native in Go version
		Workspace:      workspace,
		DisableBrowser: envOrBool("XALGORIX_DISABLE_BROWSER", false),
		MaxIterations:  envOrInt("XALGORIX_MAX_ITERATIONS", 0),

		// Rate limiting (defaults: 60 requests per 60 seconds)
		RateLimitRequests: envOrInt("XALGORIX_RATE_LIMIT_REQUESTS", 60),
		RateLimitWindow:   envOrInt("XALGORIX_RATE_LIMIT_WINDOW", 60),

		// Caido
		CaidoPort:     envOrInt("CAIDO_PORT", 0), // 0 = auto-detect
		CaidoAPIToken: envOr("CAIDO_API_TOKEN", ""),

		// Telemetry
		Telemetry:    envOrBool("XALGORIX_TELEMETRY", true),
		OTelEndpoint: envOr("XALGORIX_OTEL_ENDPOINT", ""),

		// Web Search API
		GeminiAPIKey:    envOr("GEMINI_API_KEY", ""),
		AgentMailAPIKey: envOr("AGENTMAIL_API_KEY", ""),
		AgentMailPod:    envOr("AGENTMAIL_POD", ""),

		// Dashboard auth
		Username: envOr("XALGORIX_USERNAME", ""),
		Password: envOr("XALGORIX_PASSWORD", ""),

		// Paths
		HomeDir:   xalgorixHome,
		SkillsDir: filepath.Join(xalgorixHome, "skills"),
	}

	// Debug: show loaded config so users can verify correct env was picked up
	maskedKey := ""
	if len(cfg.APIKey) > 8 {
		maskedKey = cfg.APIKey[:4] + "****" + cfg.APIKey[len(cfg.APIKey)-4:]
	} else if cfg.APIKey != "" {
		maskedKey = "****"
	}
	fmt.Printf("[config] Loaded: LLM=%q APIBase=%q APIKey=%s\n", cfg.LLM, cfg.APIBase, maskedKey)

	return cfg
}

// ResolveModel resolves a model name.
func (c *Config) ResolveModel() string {
	model := c.LLM
	if model == "" {
		return ""
	}
	return model
}

// WorkspacePath resolves a path relative to the workspace.
func (c *Config) WorkspacePath(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(c.Workspace, rel)
}

// Validate checks that required configuration is present.
func (c *Config) Validate() error {
	if c.LLM == "" {
		return fmt.Errorf("XALGORIX_LLM is required. Set it to a model like 'openai/gpt-5.4' or 'anthropic/claude-sonnet-4-6'")
	}

	return nil
}

// CheckEnvFile checks if .xalgorix.env exists and has valid content.
func CheckEnvFile() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot find home directory: %w", err)
	}

	envPath := filepath.Join(home, ".xalgorix.env")

	// Check if file exists
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s\n\nPlease create it with:\n  XALGORIX_LLM=minimax/MiniMax-M2.7\n  XALGORIX_API_KEY=your_api_key\n\nOr run: xalgorix --setup", envPath)
	}

	// Read file directly to check for required variables (not system env vars)
	llm := ""
	apiKey := ""

	f, err := os.Open(envPath)
	if err != nil {
		return fmt.Errorf("cannot read config file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "XALGORIX_LLM":
			llm = value
		case "XALGORIX_API_KEY":
			apiKey = value
		}
	}

	if llm == "" || apiKey == "" {
		return fmt.Errorf("configuration file is invalid or missing required variables\n\nPlease add to %s:\n  XALGORIX_LLM=minimax/MiniMax-M2.7\n  XALGORIX_API_KEY=your_api_key", envPath)
	}

	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envOrBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		v = strings.ToLower(v)
		return v == "1" || v == "true" || v == "yes"
	}
	return fallback
}

// loadEnvFile reads a KEY=VALUE env file and sets env vars.
// Later calls override earlier ones, so higher-priority files should be loaded last.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // File doesn't exist, skip silently
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse KEY=VALUE (strip optional "export " prefix and quotes)
		line = strings.TrimPrefix(line, "export ")
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Strip surrounding quotes
		value = strings.Trim(value, "\"'")
		// Always set — later files override earlier ones
		os.Setenv(key, value)
	}
}
