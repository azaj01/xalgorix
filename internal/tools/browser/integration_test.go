package browser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// action is a shorthand for browserActionWithContext using the test's context ID.
func action(ctxID string, args map[string]string) (string, error) {
	res, err := browserActionWithContext(ctxID, args)
	return res.Output, err
}

// launchCtx launches a browser for the given context with optional URL, registers cleanup.
func launchCtx(t *testing.T, ctxID, url string) {
	t.Helper()
	args := map[string]string{"command": "launch"}
	if url != "" {
		args["url"] = url
	}
	_, err := browserActionWithContext(ctxID, args)
	if err != nil {
		t.Fatalf("launch failed: %v", err)
	}
	t.Cleanup(func() {
		browserActionWithContext(ctxID, map[string]string{"command": "close"})
	})
}

// injectHTML injects HTML into the current page body via execute_js.
func injectHTML(t *testing.T, ctxID, html string) {
	t.Helper()
	code := fmt.Sprintf(`() => { document.body.innerHTML = '%s'; }`, html)
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "execute_js", "code": code})
	if err != nil {
		t.Fatalf("inject HTML failed: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.1 Core Lifecycle
// ═══════════════════════════════════════════════════════════

func TestLaunch_NoURL(t *testing.T) {
	ctxID := "int-launch-nourl"
	launchCtx(t, ctxID, "")
	s := getBrowserStoreByID(ctxID)
	if s.browser == nil {
		t.Error("browser should not be nil after launch")
	}
}

func TestLaunch_WithURL(t *testing.T) {
	ctxID := "int-launch-url"
	launchCtx(t, ctxID, "https://example.com")
	out, _ := action(ctxID, map[string]string{"command": "get_url"})
	if !strings.Contains(out, "example.com") {
		t.Errorf("URL = %q, want contains 'example.com'", out)
	}
}

func TestClose_NotLaunched(t *testing.T) {
	ctxID := "int-close-noop"
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "close"})
	if err != nil {
		t.Errorf("close on unlaunched should not error: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.2 Navigation
// ═══════════════════════════════════════════════════════════

func TestGoto_ValidURL(t *testing.T) {
	ctxID := "int-goto"
	launchCtx(t, ctxID, "")
	out, err := action(ctxID, map[string]string{"command": "goto", "url": "https://example.com"})
	if err != nil {
		t.Fatalf("goto failed: %v", err)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("output = %q, want 'example.com'", out)
	}
}

func TestGetURL(t *testing.T) {
	ctxID := "int-geturl"
	launchCtx(t, ctxID, "https://example.com")
	out, _ := action(ctxID, map[string]string{"command": "get_url"})
	if !strings.Contains(out, "example.com") {
		t.Errorf("get_url = %q, want 'example.com'", out)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.3 Element Interaction
// ═══════════════════════════════════════════════════════════

func TestSnapshot_ElementDiscovery(t *testing.T) {
	ctxID := "int-snapshot"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<input type="text" placeholder="Username"><button>Click</button>`)

	out, err := action(ctxID, map[string]string{"command": "snapshot"})
	if err != nil {
		t.Fatalf("snapshot failed: %v", err)
	}
	if !strings.Contains(out, "[@e1]") || !strings.Contains(out, "input") {
		t.Errorf("snapshot missing input element: %s", out)
	}
	if !strings.Contains(out, "[@e2]") || !strings.Contains(out, "button") {
		t.Errorf("snapshot missing button element: %s", out)
	}
}

func TestSnapshot_HiddenElements(t *testing.T) {
	ctxID := "int-snapshot-hidden"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<button>Visible</button><a href="#" style="display:none;">Hidden</a>`)

	out, _ := action(ctxID, map[string]string{"command": "snapshot"})
	if strings.Contains(out, "Hidden") {
		t.Errorf("snapshot should not contain hidden elements: %s", out)
	}
}

func TestClick_SemanticID(t *testing.T) {
	ctxID := "int-click-semantic"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<button>Click Me</button>`)
	action(ctxID, map[string]string{"command": "snapshot"})

	_, err := browserActionWithContext(ctxID, map[string]string{"command": "click", "selector": "@e1"})
	if err != nil {
		t.Errorf("click @e1 failed: %v", err)
	}
}

func TestClick_NotFound(t *testing.T) {
	ctxID := "int-click-nf"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "click", "selector": "#nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent selector")
	}
}

func TestType_SemanticID(t *testing.T) {
	ctxID := "int-type-semantic"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<input type="text" placeholder="Name">`)
	action(ctxID, map[string]string{"command": "snapshot"})

	_, err := browserActionWithContext(ctxID, map[string]string{"command": "type", "selector": "@e1", "text": "hello"})
	if err != nil {
		t.Errorf("type @e1 failed: %v", err)
	}
}

func TestType_NotFound(t *testing.T) {
	ctxID := "int-type-nf"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "type", "selector": "#nope", "text": "x"})
	if err == nil {
		t.Error("expected error for nonexistent selector")
	}
}

func TestSubmit_AutoDetect(t *testing.T) {
	ctxID := "int-submit-auto"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<form><input type="text" name="q"><button type="submit">Go</button></form>`)

	_, err := browserActionWithContext(ctxID, map[string]string{"command": "submit"})
	if err != nil {
		t.Errorf("submit auto-detect failed: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.4 Scroll
// ═══════════════════════════════════════════════════════════

func TestScroll_Down(t *testing.T) {
	ctxID := "int-scroll-down"
	launchCtx(t, ctxID, "https://example.com")
	out, err := action(ctxID, map[string]string{"command": "scroll", "direction": "down"})
	if err != nil {
		t.Fatalf("scroll failed: %v", err)
	}
	if !strings.Contains(out, "Scrolled") {
		t.Errorf("output = %q, want 'Scrolled'", out)
	}
}

func TestScroll_Up(t *testing.T) {
	ctxID := "int-scroll-up"
	launchCtx(t, ctxID, "https://example.com")
	out, _ := action(ctxID, map[string]string{"command": "scroll", "direction": "up"})
	if !strings.Contains(out, "Scrolled") {
		t.Errorf("output = %q, want 'Scrolled'", out)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.5 Screenshot
// ═══════════════════════════════════════════════════════════

func TestScreenshot_Capture(t *testing.T) {
	ctxID := "int-screenshot"
	launchCtx(t, ctxID, "https://example.com")
	res, err := browserActionWithContext(ctxID, map[string]string{"command": "screenshot"})
	if err != nil {
		t.Fatalf("screenshot failed: %v", err)
	}
	if res.Metadata == nil || res.Metadata["screenshot"] == nil {
		t.Error("screenshot metadata missing")
	}
	if size, ok := res.Metadata["size_bytes"].(int); ok && size == 0 {
		t.Error("screenshot size is 0")
	}
}

// ═══════════════════════════════════════════════════════════
// 3.6 HTML & JavaScript
// ═══════════════════════════════════════════════════════════

func TestGetHTML_FullPage(t *testing.T) {
	ctxID := "int-html-full"
	launchCtx(t, ctxID, "https://example.com")
	out, _ := action(ctxID, map[string]string{"command": "get_html"})
	if !strings.Contains(strings.ToLower(out), "<html") {
		t.Errorf("get_html should contain <html, got: %.100s", out)
	}
}

func TestGetHTML_SelectorNotFound(t *testing.T) {
	ctxID := "int-html-nf"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "get_html", "selector": "#nope"})
	if err == nil {
		t.Error("expected error for nonexistent selector")
	}
}

func TestExecuteJS_ReturnValue(t *testing.T) {
	ctxID := "int-js-return"
	launchCtx(t, ctxID, "https://example.com")
	out, err := action(ctxID, map[string]string{"command": "execute_js", "code": "() => 2 + 2"})
	if err != nil {
		t.Fatalf("execute_js failed: %v", err)
	}
	if !strings.Contains(out, "4") {
		t.Errorf("execute_js = %q, want '4'", out)
	}
}

func TestExecuteJS_EmptyCode(t *testing.T) {
	ctxID := "int-js-empty"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "execute_js", "code": ""})
	if err == nil {
		t.Error("expected error for empty code")
	}
}

// ═══════════════════════════════════════════════════════════
// 3.7 Cookies
// ═══════════════════════════════════════════════════════════

func TestSetCookie_MissingName(t *testing.T) {
	ctxID := "int-cookie-noname"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "set_cookie", "text": "val"})
	if err == nil {
		t.Error("expected error for missing cookie name")
	}
}

func TestSetCookie_MissingValue(t *testing.T) {
	ctxID := "int-cookie-noval"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "set_cookie", "name": "test"})
	if err == nil {
		t.Error("expected error for missing cookie value")
	}
}

func TestSetAndGetCookies(t *testing.T) {
	ctxID := "int-cookie-roundtrip"
	launchCtx(t, ctxID, "https://example.com")

	_, err := browserActionWithContext(ctxID, map[string]string{
		"command": "set_cookie", "name": "testcookie", "text": "testvalue", "domain": "example.com",
	})
	if err != nil {
		t.Fatalf("set_cookie failed: %v", err)
	}

	out, err := action(ctxID, map[string]string{"command": "get_cookies"})
	if err != nil {
		t.Fatalf("get_cookies failed: %v", err)
	}
	if !strings.Contains(out, "testcookie") {
		t.Errorf("get_cookies should contain 'testcookie', got: %s", out)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.8 Session Save/Load
// ═══════════════════════════════════════════════════════════

func TestSaveSession_InMemory(t *testing.T) {
	ctxID := "int-session-mem"
	launchCtx(t, ctxID, "https://example.com")
	browserActionWithContext(ctxID, map[string]string{
		"command": "set_cookie", "name": "sess", "text": "val", "domain": "example.com",
	})
	out, err := action(ctxID, map[string]string{"command": "save_session"})
	if err != nil {
		t.Fatalf("save_session failed: %v", err)
	}
	if !strings.Contains(out, "Session saved") {
		t.Errorf("output = %q, want 'Session saved'", out)
	}
}

func TestLoadSession_NoSaved(t *testing.T) {
	ctxID := "int-session-nosaved"
	launchCtx(t, ctxID, "https://example.com")
	out, _ := action(ctxID, map[string]string{"command": "load_session"})
	if !strings.Contains(out, "No saved session") {
		t.Errorf("output = %q, want 'No saved session'", out)
	}
}

func TestSaveSession_ToDisk(t *testing.T) {
	ctxID := "int-session-disk"
	tmpDir := t.TempDir()
	SetSessionPathForCtx(ctxID, tmpDir)

	launchCtx(t, ctxID, "https://example.com")
	browserActionWithContext(ctxID, map[string]string{
		"command": "set_cookie", "name": "disk", "text": "val", "domain": "example.com",
	})
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "save_session"})
	if err != nil {
		t.Fatalf("save_session failed: %v", err)
	}

	path := filepath.Join(tmpDir, "session.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("session.json not created at %s", path)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.9 Wait
// ═══════════════════════════════════════════════════════════

func TestWait_SelectorFound(t *testing.T) {
	ctxID := "int-wait-found"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<div id="target">Here</div>`)

	out, err := action(ctxID, map[string]string{"command": "wait", "selector": "#target", "timeout": "5"})
	if err != nil {
		t.Fatalf("wait failed: %v", err)
	}
	if !strings.Contains(out, "Element found") {
		t.Errorf("output = %q, want 'Element found'", out)
	}
}

func TestWait_SelectorTimeout(t *testing.T) {
	ctxID := "int-wait-timeout"
	launchCtx(t, ctxID, "https://example.com")

	out, _ := action(ctxID, map[string]string{"command": "wait", "selector": "#nonexistent", "timeout": "1"})
	if !strings.Contains(out, "did not appear") {
		t.Errorf("output = %q, want 'did not appear'", out)
	}
}

func TestWait_PageStabilize(t *testing.T) {
	ctxID := "int-wait-stable"
	launchCtx(t, ctxID, "https://example.com")

	out, _ := action(ctxID, map[string]string{"command": "wait"})
	if !strings.Contains(out, "stabilized") {
		t.Errorf("output = %q, want 'stabilized'", out)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.10 Fill Form
// ═══════════════════════════════════════════════════════════

func TestFillForm_EmptyFields(t *testing.T) {
	ctxID := "int-form-empty"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "fill_form", "fields": ""})
	if err == nil {
		t.Error("expected error for empty fields")
	}
}

func TestFillForm_FieldNotFound(t *testing.T) {
	ctxID := "int-form-nf"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<form><input name="email"></form>`)

	out, _ := action(ctxID, map[string]string{"command": "fill_form", "fields": "nonexistent=val"})
	if !strings.Contains(out, "NOT FOUND") {
		t.Errorf("output = %q, want 'NOT FOUND'", out)
	}
}

func TestFillForm_MultipleFields(t *testing.T) {
	ctxID := "int-form-multi"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<form><input name="email"><input name="password"></form>`)

	out, err := action(ctxID, map[string]string{"command": "fill_form", "fields": "email=test@mail.com|password=Pass123"})
	if err != nil {
		t.Fatalf("fill_form failed: %v", err)
	}
	if !strings.Contains(out, "email") || !strings.Contains(out, "password") {
		t.Errorf("output = %q, want both fields", out)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.11 Tabs
// ═══════════════════════════════════════════════════════════

func TestNewTab(t *testing.T) {
	ctxID := "int-newtab"
	launchCtx(t, ctxID, "https://example.com")

	out, err := action(ctxID, map[string]string{"command": "new_tab"})
	if err != nil {
		t.Fatalf("new_tab failed: %v", err)
	}
	if !strings.Contains(out, "tab_2") {
		t.Errorf("output = %q, want 'tab_2'", out)
	}
}

func TestSwitchTab(t *testing.T) {
	ctxID := "int-switchtab"
	launchCtx(t, ctxID, "https://example.com")
	action(ctxID, map[string]string{"command": "new_tab"})

	out, err := action(ctxID, map[string]string{"command": "switch_tab", "tab_id": "tab_1"})
	if err != nil {
		t.Fatalf("switch_tab failed: %v", err)
	}
	if !strings.Contains(out, "tab_1") {
		t.Errorf("output = %q, want 'tab_1'", out)
	}
}

func TestSwitchTab_NotFound(t *testing.T) {
	ctxID := "int-switchtab-nf"
	launchCtx(t, ctxID, "https://example.com")
	_, err := browserActionWithContext(ctxID, map[string]string{"command": "switch_tab", "tab_id": "tab_99"})
	if err == nil {
		t.Error("expected error for nonexistent tab")
	}
}

// ═══════════════════════════════════════════════════════════
// 3.12 Extract Links
// ═══════════════════════════════════════════════════════════

func TestExtractLinks_WithLinks(t *testing.T) {
	ctxID := "int-links"
	launchCtx(t, ctxID, "https://example.com")
	injectHTML(t, ctxID, `<a href="https://a.com">A</a><a href="https://b.com">B</a>`)

	out, err := action(ctxID, map[string]string{"command": "extract_links"})
	if err != nil {
		t.Fatalf("extract_links failed: %v", err)
	}
	if !strings.Contains(out, "a.com") || !strings.Contains(out, "b.com") {
		t.Errorf("output = %q, want both links", out)
	}
}

// ═══════════════════════════════════════════════════════════
// 3.13 Context Isolation & Cleanup
// ═══════════════════════════════════════════════════════════

func TestCleanupContext_NonExistent(t *testing.T) {
	// Should not panic
	CleanupContext("nonexistent-ctx-1234")
}

func TestContextIsolation(t *testing.T) {
	ctxA := "int-iso-a"
	ctxB := "int-iso-b"

	launchCtx(t, ctxA, "https://example.com")
	launchCtx(t, ctxB, "https://example.com")

	// Inject different content into each context
	injectHTML(t, ctxA, `<div id="ctx-a">A</div>`)
	injectHTML(t, ctxB, `<div id="ctx-b">B</div>`)

	htmlA, _ := action(ctxA, map[string]string{"command": "get_html"})
	htmlB, _ := action(ctxB, map[string]string{"command": "get_html"})

	if !strings.Contains(htmlA, "ctx-a") {
		t.Error("context A should contain 'ctx-a'")
	}
	if !strings.Contains(htmlB, "ctx-b") {
		t.Error("context B should contain 'ctx-b'")
	}
	if strings.Contains(htmlA, "ctx-b") {
		t.Error("context A should NOT contain 'ctx-b'")
	}
}

// ═══════════════════════════════════════════════════════════
// 3.14 Existing test from browser_test.go (keeping for compat)
// ═══════════════════════════════════════════════════════════

func TestBrowserSnapshot_Full(t *testing.T) {
	ctxID := scanctx.Default().ID

	// Launch
	_, err := browserActionWithContext(ctxID, map[string]string{
		"command": "launch", "url": "https://example.com",
	})
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	t.Cleanup(func() {
		browserActionWithContext(ctxID, map[string]string{"command": "close"})
	})

	// Inject
	injectHTML(t, ctxID, `<h1>Test Page</h1><input type="text" placeholder="Username"><button>Click Me</button><a href="#" style="display:none;">Hidden Link</a>`)

	// Snapshot
	res, err := browserActionWithContext(ctxID, map[string]string{"command": "snapshot"})
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	out := res.Output
	if !strings.Contains(out, "[@e1]") || !strings.Contains(out, "input(text)") {
		t.Errorf("Snapshot missing input element: %s", out)
	}
	if !strings.Contains(out, "[@e2]") || !strings.Contains(out, "button") {
		t.Errorf("Snapshot missing button element: %s", out)
	}
	if strings.Contains(out, "Hidden Link") {
		t.Errorf("Snapshot captured hidden elements: %s", out)
	}

	// Semantic type
	_, err = browserActionWithContext(ctxID, map[string]string{"command": "type", "selector": "@e1", "text": "admin_user"})
	if err != nil {
		t.Fatalf("Semantic type failed: %v", err)
	}

	// Semantic click
	_, err = browserActionWithContext(ctxID, map[string]string{"command": "click", "selector": "@e2"})
	if err != nil {
		t.Fatalf("Semantic click failed: %v", err)
	}
}
