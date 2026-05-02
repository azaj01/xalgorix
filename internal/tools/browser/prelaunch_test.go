package browser

import (
	"strings"
	"testing"
)

// TestPreLaunch_AllCommands verifies every command returns "browser not launched"
// when invoked on a fresh context with no active browser.
func TestPreLaunch_AllCommands(t *testing.T) {
	ctxID := "test-prelaunch-guard"

	commands := []struct {
		name string
		args map[string]string
	}{
		{"goto", map[string]string{"command": "goto", "url": "https://example.com"}},
		{"snapshot", map[string]string{"command": "snapshot"}},
		{"click", map[string]string{"command": "click", "selector": "#btn"}},
		{"type", map[string]string{"command": "type", "selector": "#in", "text": "x"}},
		{"submit", map[string]string{"command": "submit"}},
		{"scroll", map[string]string{"command": "scroll", "direction": "down"}},
		{"screenshot", map[string]string{"command": "screenshot"}},
		{"get_html", map[string]string{"command": "get_html"}},
		{"execute_js", map[string]string{"command": "execute_js", "code": "() => 1"}},
		{"get_cookies", map[string]string{"command": "get_cookies"}},
		{"set_cookie", map[string]string{"command": "set_cookie", "name": "a", "text": "b"}},
		{"save_session", map[string]string{"command": "save_session"}},
		{"load_session", map[string]string{"command": "load_session"}},
		{"wait", map[string]string{"command": "wait", "selector": "#x"}},
		{"select", map[string]string{"command": "select", "selector": "#s", "text": "v"}},
		{"fill_form", map[string]string{"command": "fill_form", "fields": "a=b"}},
		{"get_url", map[string]string{"command": "get_url"}},
		{"iframe", map[string]string{"command": "iframe", "selector": "iframe"}},
		{"extract_links", map[string]string{"command": "extract_links"}},
		{"new_tab", map[string]string{"command": "new_tab"}},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			_, err := browserActionWithContext(ctxID, tc.args)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "browser not launched") &&
				!strings.Contains(err.Error(), "not launched") {
				t.Errorf("%s: error = %q, want 'browser not launched'", tc.name, err.Error())
			}
		})
	}
}
