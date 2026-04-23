package browser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// testBrowserAction is a test helper that routes through the default ScanContext.
func testBrowserAction(args map[string]string) (tools.Result, error) {
	return browserActionWithContext(scanctx.Default().ID, args)
}

func TestBrowserSnapshot(t *testing.T) {
	// 1. Launch browser to example.com
	res, err := testBrowserAction(map[string]string{
		"command": "launch",
		"url":     "https://example.com",
	})
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}

	// 2. Inject interactive elements
	jsCode := `() => { document.body.innerHTML = '<h1>Test Page</h1><input type="text" placeholder="Username"><button>Click Me</button><a href="#" style="display:none;">Hidden Link</a>'; }`
	_, err = testBrowserAction(map[string]string{
		"command": "execute_js",
		"code":    jsCode,
	})
	if err != nil {
		t.Fatalf("JS injection failed: %v", err)
	}

	// 3. Take snapshot
	res, err = testBrowserAction(map[string]string{
		"command": "snapshot",
	})
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	output := res.Output
	fmt.Println("SNAPSHOT OUTPUT:\n", output)

	if !strings.Contains(output, "[@e1]") || !strings.Contains(output, "input(text)") {
		t.Errorf("Snapshot did not capture input element properly. Got:\n%s", output)
	}
	if !strings.Contains(output, "[@e2]") || !strings.Contains(output, "button") {
		t.Errorf("Snapshot did not capture button element properly. Got:\n%s", output)
	}
	if strings.Contains(output, "Hidden Link") {
		t.Errorf("Snapshot captured hidden elements. Got:\n%s", output)
	}

	// 4. Test Semantic Type
	_, err = testBrowserAction(map[string]string{
		"command":  "type",
		"selector": "@e1",
		"text":     "admin_user",
	})
	if err != nil {
		t.Fatalf("Semantic type failed: %v", err)
	}

	// 5. Test Semantic Click
	_, err = testBrowserAction(map[string]string{
		"command":  "click",
		"selector": "@e2",
	})
	if err != nil {
		t.Fatalf("Semantic click failed: %v", err)
	}

	// 6. Cleanup
	testBrowserAction(map[string]string{
		"command": "close",
	})
}
