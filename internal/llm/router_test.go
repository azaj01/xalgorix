package llm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

func TestKeyStore_SetAndGet(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	key := ProviderKey{
		ProviderID:  "openai",
		APIKey:      "sk-test-12345678",
		HeaderStyle: "openai",
		BaseURL:     "https://api.openai.com/v1",
	}

	if err := ks.Set(ctx, key); err != nil {
		t.Fatal(err)
	}

	got, ok := ks.Get("openai")
	if !ok {
		t.Fatal("expected key to be found")
	}
	if got.APIKey != key.APIKey {
		t.Errorf("got APIKey=%q, want %q", got.APIKey, key.APIKey)
	}
}

func TestKeyStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Write keys
	ks1, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks1.Set(ctx, ProviderKey{
		ProviderID: "anthropic",
		APIKey:     "sk-ant-test-123",
	}); err != nil {
		t.Fatal(err)
	}

	// Verify file exists
	fp := filepath.Join(dir, "llm_keys.json")
	if _, err := os.Stat(fp); err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	// Load into new instance
	ks2, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ks2.Get("anthropic")
	if !ok {
		t.Fatal("key not persisted across instances")
	}
	if got.APIKey != "sk-ant-test-123" {
		t.Errorf("persisted key = %q, want sk-ant-test-123", got.APIKey)
	}
}

func TestKeyStore_List_MasksKeys(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ks.Set(ctx, ProviderKey{ProviderID: "openai", APIKey: "sk-test-12345678"})

	listed := ks.List()
	if len(listed) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listed))
	}
	if listed[0].APIKey == "sk-test-12345678" {
		t.Error("List() should mask API keys")
	}
	if listed[0].APIKey != "****5678" {
		t.Errorf("masked key = %q, want ****5678", listed[0].APIKey)
	}
}

func TestKeyStore_SetMultiple(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	err = ks.SetMultiple(ctx, []ProviderKey{
		{ProviderID: "openai", APIKey: "sk-openai"},
		{ProviderID: "anthropic", APIKey: "sk-anthropic"},
		{ProviderID: "google", APIKey: "ai-google"},
	})
	if err != nil {
		t.Fatal(err)
	}

	providers := ks.ConfiguredProviders()
	if len(providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(providers))
	}
}

func TestKeyStore_Delete(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ks.Set(ctx, ProviderKey{ProviderID: "openai", APIKey: "sk-test"})

	if !ks.HasKey("openai") {
		t.Fatal("expected key to exist")
	}

	ks.Delete(ctx, "openai")

	if ks.HasKey("openai") {
		t.Error("key should have been deleted")
	}
}

func TestRouter_Route(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ks.Set(ctx, ProviderKey{
		ProviderID:  "openai",
		APIKey:      "sk-test-openai",
		HeaderStyle: "openai",
		BaseURL:     "https://api.openai.com/v1",
	})

	cat := providers.NewService()
	router := NewRouter(cat, ks)

	ep, err := router.Route(ctx, "gpt-4o")
	if err != nil {
		t.Fatal(err)
	}

	if ep.Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", ep.Model)
	}
	if ep.HeaderStyle != "openai" {
		t.Errorf("headerStyle = %q, want openai", ep.HeaderStyle)
	}
	if ep.APIKey != "sk-test-openai" {
		t.Errorf("apiKey = %q, want sk-test-openai", ep.APIKey)
	}
	if ep.Auth != AuthAPIKey {
		t.Errorf("auth = %q, want api_key", ep.Auth)
	}
	if ep.URL == "" {
		t.Error("URL should not be empty")
	}
}

func TestRouter_Route_NoKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	cat := providers.NewService()
	router := NewRouter(cat, ks)

	_, err = router.Route(context.Background(), "gpt-4o")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	configError := &ConfigError{}
	if !errors.As(err, &configError) {
		t.Errorf("expected *ConfigError, got %T", err)
	}
}

func TestRouter_Route_UnknownModel(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	cat := providers.NewService()
	router := NewRouter(cat, ks)

	_, err = router.Route(context.Background(), "totally-unknown-model-xyz")
	if err == nil {
		t.Fatal("expected error for unknown model")
	}
}

func TestRouter_TestRoute(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ks.Set(ctx, ProviderKey{ProviderID: "anthropic", APIKey: "sk-ant-test"})

	cat := providers.NewService()
	router := NewRouter(cat, ks)

	result, err := router.TestRoute("claude-sonnet-4-20250514")
	if err != nil {
		t.Fatal(err)
	}

	if result.ProviderID != "anthropic" {
		t.Errorf("providerID = %q, want anthropic", result.ProviderID)
	}
	if !result.HasKey {
		t.Error("expected HasKey = true")
	}
	if result.HeaderStyle != "anthropic" {
		t.Errorf("headerStyle = %q, want anthropic", result.HeaderStyle)
	}
}

func TestRouter_CanRoute(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	cat := providers.NewService()
	router := NewRouter(cat, ks)

	if router.CanRoute() {
		t.Error("should not be able to route with no keys")
	}

	ks.Set(context.Background(), ProviderKey{ProviderID: "openai", APIKey: "sk-test"})
	if !router.CanRoute() {
		t.Error("should be able to route with at least one key")
	}
}
