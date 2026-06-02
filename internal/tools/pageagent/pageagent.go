// Package pageagent provides an in-page GUI agent tool for granular
// web application menu and UI element control.
//
// Inspired by:
//   - nanobrowser (multi-agent Planner/Navigator decomposition)
//   - page-agent  (in-page DOM controller + MCP hub-bridge)
//
// Instead of requiring a separate Chrome extension, this tool injects
// JavaScript directly via the existing CDP/Rod connection, making it
// headless-compatible and CSP-immune.
package pageagent

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
)

// useExtension returns true if the WebSocket bridge has an active connection.
func useExtension() bool {
	return browser.GetBridge().IsConnected()
}

//go:embed scripts/discovery.js
var discoveryJS string

//go:embed scripts/controller.js
var controllerJS string

// NOTE: controllerInjected was removed as global state.
// ensureController() now queries the page directly to check if the
// controller is already loaded, making it inherently session-scoped.

// Register registers the page_agent tool in the tool registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "page_agent",
		Description: `Advanced in-page GUI agent for granular control over web application UI elements.
Use this when you need to discover, enumerate, and individually interact with menus,
dropdowns, tabs, accordions, modals, and other complex UI widgets.

WHEN TO USE THIS vs browser_action:
  - browser_action: Basic navigation, form filling, screenshots, JS execution
  - page_agent: Menu discovery, dropdown interaction, tab switching, accordion expansion,
    modal handling, hover-to-reveal menus, complex UI widget control

COMMANDS:
  discover_menus  — Enumerate all navigation menus, dropdowns, tabs, accordions, modals, forms
  discover_ui     — Get full interactive UI hierarchy (same as discover_menus but formatted as tree)
  interact        — Click/hover/toggle a specific element by its @xpaNN semantic ID
  get_menu_tree   — Get hierarchical menu structure for navigation planning
  hover_probe     — Hover over an element to discover hidden submenus that appear on hover
  wait_element    — Wait for a dynamic element to appear (selector-based)
  get_element_state — Get computed state of an element (visibility, expanded, disabled, etc.)

WORKFLOW EXAMPLE:
  1. discover_menus → see all menus, dropdowns, tabs on the page
  2. interact id=@xpa5 action=hover → hover over "Admin" menu to reveal submenu
  3. interact id=@xpa12 action=click → click "User Management" submenu item
  4. discover_menus → re-scan the new page to see its UI elements

ELEMENT IDs:
  Elements are tagged with @xpaNN IDs (e.g., @xpa1, @xpa2, @xpa15).
  Use these IDs with the interact, hover_probe, and get_element_state commands.`,
		Parameters: []tools.Parameter{
			{Name: "command", Description: "page_agent command (see list above)", Required: true},
			{Name: "id", Description: "Element @xpaNN ID (for interact/hover_probe/get_element_state)", Required: false},
			{Name: "action", Description: "Interaction action: click, hover, rightClick, doubleClick, focus, toggle (for interact)", Required: false},
			{Name: "selector", Description: "CSS selector (for wait_element)", Required: false},
			{Name: "text", Description: "Text to type (for interact with type action) or select value", Required: false},
			{Name: "timeout", Description: "Timeout in seconds (for wait_element, default: 10)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return pageAgentAction(r.GetScanContextID(), args)
		},
	})
}

func pageAgentAction(ctxID string, args map[string]string) (tools.Result, error) {
	command := args["command"]
	switch command {
	case "discover_menus":
		return discoverMenus(ctxID)
	case "discover_ui":
		return discoverUI(ctxID)
	case "interact":
		return interact(ctxID, args["id"], args["action"], args["text"])
	case "get_menu_tree":
		return getMenuTree(ctxID)
	case "hover_probe":
		return hoverProbe(ctxID, args["id"])
	case "wait_element":
		return waitElement(ctxID, args["selector"], args["timeout"])
	case "get_element_state":
		return getElementState(ctxID, args["id"])
	default:
		return tools.Result{}, fmt.Errorf("unknown page_agent command: %s. Available: discover_menus, discover_ui, interact, get_menu_tree, hover_probe, wait_element, get_element_state", command)
	}
}

// ── Helpers ────────────────────────────────────────────────────────────

// parseXPAID strips the @ prefix from user-provided IDs.
func parseXPAID(id string) string {
	return strings.TrimPrefix(id, "@")
}

// ensureController injects the controller.js script if not already injected.
// Queries the page directly rather than relying on package-level state.
func ensureController(ctxID string) error {
	page := browser.GetCurrentPageForCtx(ctxID)
	if page == nil {
		return fmt.Errorf("browser not launched — use browser_action launch first")
	}

	// Check if controller is already loaded in this page's DOM
	checkResult, err := page.Timeout(5 * time.Second).Eval(`(() => { return typeof window.__xpa_controller_loaded !== 'undefined' ? 'loaded' : 'missing'; })()`)
	if err == nil && checkResult.Value.String() == "loaded" {
		return nil // Already injected in this page
	}

	result, err := page.Timeout(15 * time.Second).Eval(controllerJS)
	if err != nil {
		return fmt.Errorf("failed to inject controller: %w", err)
	}
	if result.Value.String() == "xpa_controller_loaded" {
		log.Printf("[page_agent] Controller script injected successfully")
	}
	return nil
}

// resetControllerState is a no-op — controller injection state is now
// page-intrinsic (checked via DOM query in ensureController).
func resetControllerState() {
	// No global state to reset — ensureController queries the page directly.
}

// ── Commands ───────────────────────────────────────────────────────────

// discoverMenus runs the discovery script and returns structured results.
// Tries extension bridge first, falls back to CDP Eval.
func discoverMenus(ctxID string) (tools.Result, error) {
	// Reset controller state since discovery re-tags elements
	resetControllerState()

	var raw string

	if useExtension() {
		// Route through extension content script
		resultJSON, err := browser.GetBridge().SendCommand("discover", nil)
		if err != nil {
			log.Printf("[page_agent] Extension discover failed, falling back to CDP: %v", err)
		} else {
			raw = string(resultJSON)
		}
	}

	// CDP fallback
	if raw == "" {
		page := browser.GetCurrentPageForCtx(ctxID)
		if page == nil {
			return tools.Result{}, fmt.Errorf("browser not launched — use browser_action launch first")
		}
		result, err := page.Timeout(15 * time.Second).Eval(discoveryJS)
		if err != nil {
			return tools.Result{}, fmt.Errorf("discovery script failed: %w", err)
		}
		raw = result.Value.String()
	}

	// Parse the JSON to produce a readable summary
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		// Return raw if parsing fails
		return tools.Result{Output: raw}, nil
	}

	var b strings.Builder
	b.WriteString("=== Page Agent — UI Discovery ===\n")

	if url, ok := data["url"].(string); ok {
		b.WriteString(fmt.Sprintf("URL: %s\n", url))
	}
	if title, ok := data["title"].(string); ok {
		b.WriteString(fmt.Sprintf("Title: %s\n", title))
	}

	if counts, ok := data["counts"].(map[string]interface{}); ok {
		b.WriteString("\n📊 COUNTS:\n")
		for k, v := range counts {
			b.WriteString(fmt.Sprintf("  %s: %.0f\n", k, v))
		}
	}

	// Format each section
	sections := []struct {
		key   string
		emoji string
		label string
	}{
		{"menus", "🧭", "NAVIGATION MENUS"},
		{"dropdowns", "📂", "DROPDOWNS"},
		{"tabs", "📑", "TABS"},
		{"accordions", "🪗", "ACCORDIONS"},
		{"modals", "🪟", "MODALS/DIALOGS"},
		{"forms", "📝", "FORMS"},
		{"other", "🔍", "OTHER (Hover Menus, etc.)"},
	}

	for _, s := range sections {
		items, ok := data[s.key].([]interface{})
		if !ok || len(items) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("\n%s %s (%d):\n", s.emoji, s.label, len(items)))

		for _, item := range items {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			formatElement(&b, m, "  ")
		}
	}

	b.WriteString("\n💡 Use 'interact id=@xpaN action=click/hover' to interact with elements.\n")
	b.WriteString("💡 Use 'hover_probe id=@xpaN' to discover hidden submenus.\n")

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"raw_json": raw,
		},
	}, nil
}

// formatElement recursively formats a UI element for display.
func formatElement(b *strings.Builder, m map[string]interface{}, indent string) {
	id, _ := m["id"].(string)
	tag, _ := m["tag"].(string)
	elemType, _ := m["type"].(string)
	label, _ := m["label"].(string)
	visible, _ := m["visible"].(bool)
	disabled, _ := m["disabled"].(bool)

	// Build the element line
	flags := ""
	if !visible {
		flags += " [HIDDEN]"
	}
	if disabled {
		flags += " [DISABLED]"
	}
	if expanded, ok := m["expanded"].(bool); ok {
		if expanded {
			flags += " [EXPANDED]"
		} else {
			flags += " [COLLAPSED]"
		}
	}
	if hasPopup, ok := m["hasPopup"].(string); ok {
		flags += fmt.Sprintf(" [popup=%s]", hasPopup)
	}

	fmt.Fprintf(b, "%s[@%s] %s(%s)", indent, id, tag, elemType)
	if label != "" {
		fmt.Fprintf(b, " \"%s\"", label)
	}
	b.WriteString(flags)
	b.WriteString("\n")

	// Format children
	if children, ok := m["children"].([]interface{}); ok {
		for _, child := range children {
			cm, ok := child.(map[string]interface{})
			if !ok {
				continue
			}
			formatElement(b, cm, indent+"  ")
		}
	}

	// Format panel (for dropdowns)
	if panel, ok := m["panel"].(map[string]interface{}); ok {
		fmt.Fprintf(b, "%s  └─ Panel:\n", indent)
		formatElement(b, panel, indent+"    ")
	}
}

// discoverUI is an alias for discoverMenus with tree formatting.
func discoverUI(ctxID string) (tools.Result, error) {
	return discoverMenus(ctxID)
}

// interact executes an action on a specific element.
// HYBRID APPROACH: Uses Rod's native CDP Input domain for physical interactions
// (isTrusted:true), falls back to JS synthetic events only when native fails.
func interact(ctxID, id, action, text string) (tools.Result, error) {
	if id == "" {
		return tools.Result{}, fmt.Errorf("id parameter is required (e.g., @xpa5)")
	}
	if action == "" {
		action = "click"
	}

	xpaID := parseXPAID(id)
	selector := fmt.Sprintf(`[data-xpa-id="%s"]`, xpaID)

	// Validate required params early — avoid running 3 tiers to get the same error
	if (action == "type" || action == "select") && text == "" {
		return tools.Result{}, fmt.Errorf("text parameter is required for %s action", action)
	}

	page := browser.GetCurrentPageForCtx(ctxID)
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched — use browser_action launch first")
	}

	// ── Fast bail: element not in DOM at all ───────────────────────
	// If the data-xpa-id doesn't exist, no tier can help — tell agent to re-discover.
	has, _, _ := page.Has(selector)
	if !has {
		return tools.Result{}, fmt.Errorf(
			"element @%s not found in DOM — the page may have changed. Run discover to get fresh element IDs",
			xpaID,
		)
	}

	// ── Native Rod Input (isTrusted:true) ──────────────────────────
	// Try Rod's native element operations first — these go through
	// Chrome's CDP Input domain producing real browser-level events.
	nativeErr := nativeInteract(page, selector, xpaID, action, text)
	if nativeErr == nil {
		label := getElementLabel(page, selector)
		return tools.Result{
			Output: fmt.Sprintf("✓ [native] %s on @%s (%s) — isTrusted:true", action, xpaID, label),
			Metadata: map[string]any{
				"action":    action,
				"elementId": xpaID,
				"isTrusted": true,
				"method":    "native_cdp_input",
				"label":     label,
				"url":       getCurrentURL(page),
			},
		}, nil
	}

	log.Printf("[page_agent] Native interact failed for @%s (%s), falling back to JS: %v", xpaID, action, nativeErr)

	// ── Extension bridge fallback (isTrusted:false) ────────────────
	if useExtension() {
		var resultJSON json.RawMessage
		var err error

		switch action {
		case "type":
			if text == "" {
				return tools.Result{}, fmt.Errorf("text parameter is required for type action")
			}
			resultJSON, err = browser.GetBridge().SendCommand("type_text", map[string]interface{}{
				"id": xpaID, "text": text, "clear": true,
			})
		case "select":
			if text == "" {
				return tools.Result{}, fmt.Errorf("text parameter is required for select action")
			}
			resultJSON, err = browser.GetBridge().SendCommand("select_option", map[string]interface{}{
				"id": xpaID, "value": text,
			})
		default:
			resultJSON, err = browser.GetBridge().SendCommand("interact", map[string]interface{}{
				"id": xpaID, "action": action,
			})
		}

		if err == nil {
			return parseJSResult(string(resultJSON), action)
		}
		log.Printf("[page_agent] Extension interact also failed: %v", err)
	}

	// ── CDP Eval fallback (isTrusted:false) ────────────────────────
	if err := ensureController(ctxID); err != nil {
		return tools.Result{}, err
	}

	// Special case: type action
	if action == "type" {
		if text == "" {
			return tools.Result{}, fmt.Errorf("text parameter is required for type action")
		}
		code := fmt.Sprintf(`() => xpa_type("%s", "%s", true)`, xpaID, escapeJS(text))
		result, err := page.Timeout(15 * time.Second).Eval(code)
		if err != nil {
			return tools.Result{}, fmt.Errorf("type action failed: %w", err)
		}
		return parseJSResult(result.Value.String(), "type")
	}

	// Special case: select action
	if action == "select" {
		if text == "" {
			return tools.Result{}, fmt.Errorf("text parameter is required for select action")
		}
		code := fmt.Sprintf(`() => xpa_select("%s", "%s")`, xpaID, escapeJS(text))
		result, err := page.Timeout(15 * time.Second).Eval(code)
		if err != nil {
			return tools.Result{}, fmt.Errorf("select action failed: %w", err)
		}
		return parseJSResult(result.Value.String(), "select")
	}

	// General interact
	code := fmt.Sprintf(`() => xpa_interact("%s", "%s")`, xpaID, escapeJS(action))
	result, err := page.Timeout(15 * time.Second).Eval(code)
	if err != nil {
		return tools.Result{}, fmt.Errorf("interact failed: %w", err)
	}

	return parseJSResult(result.Value.String(), action)
}

// nativeInteract uses Rod's native element methods for isTrusted:true interactions.
// This goes through Chrome's CDP Input domain — the same pipeline as real human input.
func nativeInteract(page *rod.Page, selector, xpaID, action, text string) error {
	// Fast existence check — if element isn't in DOM, don't waste time waiting
	has, _, err := page.Has(selector)
	if err != nil || !has {
		return fmt.Errorf("element @%s not in DOM (stale ID — re-discover needed)", xpaID)
	}

	el, err := page.Timeout(2 * time.Second).Element(selector)
	if err != nil {
		return fmt.Errorf("element @%s not found: %w", xpaID, err)
	}

	switch action {
	case "click":
		return el.Click(proto.InputMouseButtonLeft, 1)

	case "rightClick":
		return el.Click(proto.InputMouseButtonRight, 1)

	case "doubleClick":
		return el.Click(proto.InputMouseButtonLeft, 2)

	case "hover":
		return el.Hover()

	case "type":
		if text == "" {
			return fmt.Errorf("text is required for type action")
		}
		// Clear existing content then type new text
		if err := el.SelectAllText(); err != nil {
			// Fallback: focus and use keyboard
			if err := el.Focus(); err != nil {
				return err
			}
		}
		return el.Input(text)

	case "focus":
		return el.Focus()

	case "blur":
		return el.Blur()

	case "scroll":
		return el.ScrollIntoView()

	case "select":
		if text == "" {
			return fmt.Errorf("value is required for select action")
		}
		return el.Select([]string{text}, true, rod.SelectorTypeText)

	default:
		return fmt.Errorf("unsupported native action: %s", action)
	}
}

// getElementLabel extracts a human-readable label for the element.
func getElementLabel(page *rod.Page, selector string) string {
	has, _, _ := page.Has(selector)
	if !has {
		return "element"
	}
	el, err := page.Timeout(500 * time.Millisecond).Element(selector)
	if err != nil {
		return "element"
	}
	text, err := el.Text()
	if err != nil || text == "" {
		return "element"
	}
	text = strings.TrimSpace(text)
	if len(text) > 60 {
		text = text[:60] + "…"
	}
	return text
}

// getCurrentURL returns the current page URL.
func getCurrentURL(page *rod.Page) string {
	info, err := page.Info()
	if err != nil {
		return ""
	}
	return info.URL
}

// getMenuTree returns a hierarchical view of navigation menus.
func getMenuTree(ctxID string) (tools.Result, error) {
	page := browser.GetCurrentPageForCtx(ctxID)
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	script := `() => {
		const tree = [];
		document.querySelectorAll('nav, [role="navigation"], [role="menubar"]').forEach(nav => {
			const build = (el, depth) => {
				const items = [];
				const children = el.querySelectorAll(':scope > a, :scope > button, :scope > li, :scope > ul > li, :scope > [role="menuitem"]');
				children.forEach(child => {
					const label = (child.textContent || '').trim().replace(/\s+/g, ' ').substring(0, 60);
					if (!label) return;
					const id = child.getAttribute('data-xpa-id') || '';
					const href = child.href || '';
					const sub = child.querySelector('ul, [role="menu"]');
					const item = { id: '@' + id, label, href };
					if (sub && depth < 3) {
						item.children = build(sub, depth + 1);
					}
					items.push(item);
				});
				return items;
			};
			const navLabel = (nav.getAttribute('aria-label') || nav.textContent || '').trim().substring(0, 40);
			const navId = nav.getAttribute('data-xpa-id') || '';
			tree.push({ id: '@' + navId, label: navLabel, children: build(nav, 0) });
		});
		return JSON.stringify(tree);
	}`

	result, err := page.Timeout(15 * time.Second).Eval(script)
	if err != nil {
		return tools.Result{}, fmt.Errorf("menu tree extraction failed: %w", err)
	}

	raw := result.Value.String()

	// Pretty-print the tree
	var tree []interface{}
	if err := json.Unmarshal([]byte(raw), &tree); err != nil {
		return tools.Result{Output: raw}, nil
	}

	var b strings.Builder
	b.WriteString("=== Menu Tree ===\n\n")
	for _, nav := range tree {
		m, ok := nav.(map[string]interface{})
		if !ok {
			continue
		}
		formatMenuNode(&b, m, "")
	}

	return tools.Result{Output: b.String()}, nil
}

func formatMenuNode(b *strings.Builder, m map[string]interface{}, indent string) {
	id, _ := m["id"].(string)
	label, _ := m["label"].(string)
	href, _ := m["href"].(string)

	fmt.Fprintf(b, "%s[%s] %s", indent, id, label)
	if href != "" {
		fmt.Fprintf(b, " → %s", href)
	}
	b.WriteString("\n")

	if children, ok := m["children"].([]interface{}); ok {
		for _, child := range children {
			cm, ok := child.(map[string]interface{})
			if !ok {
				continue
			}
			formatMenuNode(b, cm, indent+"  ")
		}
	}
}

// hoverProbe hovers over an element and reports what new elements appeared.
func hoverProbe(ctxID, id string) (tools.Result, error) {
	if id == "" {
		return tools.Result{}, fmt.Errorf("id parameter is required")
	}

	xpaID := parseXPAID(id)

	// Try extension bridge first
	if useExtension() {
		resultJSON, err := browser.GetBridge().SendCommand("hover_probe", map[string]interface{}{
			"id": xpaID,
		})
		if err == nil {
			return parseJSResult(string(resultJSON), "hover_probe")
		}
		log.Printf("[page_agent] Extension hover_probe failed, falling back to CDP: %v", err)
	}

	// CDP fallback — hover then re-discover
	result, err := interact(ctxID, id, "hover", "")
	if err != nil {
		return result, err
	}

	// After hovering, run a quick discovery to see what's new
	page := browser.GetCurrentPageForCtx(ctxID)
	if page == nil {
		return result, nil
	}

	// Small delay to let hover menus render
	time.Sleep(500 * time.Millisecond)

	// Quick scan for newly visible menus
	script := `() => {
		const newItems = [];
		document.querySelectorAll('[role="menu"]:not([data-xpa-scanned]), ul.dropdown-menu:not([data-xpa-scanned]), .submenu:not([data-xpa-scanned])').forEach(el => {
			const style = window.getComputedStyle(el);
			if (style.display !== 'none' && style.visibility !== 'hidden') {
				el.setAttribute('data-xpa-scanned', 'true');
				const items = [];
				el.querySelectorAll('a, button, li, [role="menuitem"]').forEach(item => {
					const label = (item.textContent || '').trim().substring(0, 60);
					if (!label) return;
					let id = item.getAttribute('data-xpa-id');
					if (!id) {
						id = 'xpa' + Math.floor(Math.random() * 100000);
						item.setAttribute('data-xpa-id', id);
					}
					items.push({ id: '@' + id, label, tag: item.tagName.toLowerCase() });
				});
				newItems.push({
					tag: el.tagName.toLowerCase(),
					itemCount: items.length,
					items,
				});
			}
		});
		return JSON.stringify(newItems);
	}`

	probeResult, err := page.Timeout(10 * time.Second).Eval(script)
	if err != nil {
		return result, nil // Return the hover result even if probe fails
	}

	var newMenus []interface{}
	if err := json.Unmarshal([]byte(probeResult.Value.String()), &newMenus); err != nil || len(newMenus) == 0 {
		return tools.Result{
			Output: result.Output + "\n\nNo new menus appeared after hovering.",
		}, nil
	}

	var b strings.Builder
	b.WriteString(result.Output)
	b.WriteString(fmt.Sprintf("\n\n🔍 DISCOVERED %d hidden menu(s) after hover:\n", len(newMenus)))

	for _, menu := range newMenus {
		m, ok := menu.(map[string]interface{})
		if !ok {
			continue
		}
		b.WriteString(fmt.Sprintf("  <%s> with %.0f items:\n", m["tag"], m["itemCount"]))
		if items, ok := m["items"].([]interface{}); ok {
			for _, item := range items {
				im, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				b.WriteString(fmt.Sprintf("    [%s] %s (%s)\n", im["id"], im["label"], im["tag"]))
			}
		}
	}

	return tools.Result{Output: b.String()}, nil
}

// waitElement waits for a CSS selector to appear in the DOM.
func waitElement(ctxID, selector, timeoutStr string) (tools.Result, error) {
	if selector == "" {
		return tools.Result{}, fmt.Errorf("selector parameter is required")
	}

	timeoutMs := 10000
	if timeoutStr != "" {
		var secs int
		_, _ = fmt.Sscanf(timeoutStr, "%d", &secs)
		if secs > 0 {
			timeoutMs = secs * 1000
		}
	}

	// Try extension bridge first
	if useExtension() {
		resultJSON, err := browser.GetBridge().SendCommandWithTimeout("wait_element", map[string]interface{}{
			"selector": selector, "timeout": timeoutMs,
		}, time.Duration(timeoutMs+5000)*time.Millisecond)
		if err == nil {
			return parseJSResult(string(resultJSON), "wait_element")
		}
		log.Printf("[page_agent] Extension wait_element failed, falling back to CDP: %v", err)
	}

	// CDP fallback
	if err := ensureController(ctxID); err != nil {
		return tools.Result{}, err
	}

	page := browser.GetCurrentPageForCtx(ctxID)
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	code := fmt.Sprintf(`() => xpa_waitFor("%s", %d)`, escapeJS(selector), timeoutMs)
	goTimeout := time.Duration(timeoutMs+5000) * time.Millisecond
	result, err := page.Timeout(goTimeout).Eval(code)
	if err != nil {
		return tools.Result{}, fmt.Errorf("wait_element failed: %w", err)
	}

	return parseJSResult(result.Value.String(), "wait_element")
}

// getElementState returns the current state of an element.
func getElementState(ctxID, id string) (tools.Result, error) {
	if id == "" {
		return tools.Result{}, fmt.Errorf("id parameter is required")
	}

	xpaID := parseXPAID(id)

	// Try extension bridge first
	if useExtension() {
		resultJSON, err := browser.GetBridge().SendCommand("get_state", map[string]interface{}{
			"id": xpaID,
		})
		if err == nil {
			var state map[string]interface{}
			if err := json.Unmarshal(resultJSON, &state); err == nil {
				var b strings.Builder
				b.WriteString(fmt.Sprintf("Element State [@%s]:\n", xpaID))
				for k, v := range state {
					if v == nil {
						continue
					}
					b.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
				}
				return tools.Result{
					Output:   b.String(),
					Metadata: map[string]any{"state": state},
				}, nil
			}
		}
		log.Printf("[page_agent] Extension get_state failed, falling back to CDP: %v", err)
	}

	// CDP fallback
	if err := ensureController(ctxID); err != nil {
		return tools.Result{}, err
	}

	page := browser.GetCurrentPageForCtx(ctxID)
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	code := fmt.Sprintf(`() => xpa_getState("%s")`, xpaID)
	result, err := page.Timeout(10 * time.Second).Eval(code)
	if err != nil {
		return tools.Result{}, fmt.Errorf("get_element_state failed: %w", err)
	}

	raw := result.Value.String()

	var state map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return tools.Result{Output: raw}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Element State [@%s]:\n", xpaID))
	for k, v := range state {
		if v == nil {
			continue
		}
		b.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
	}

	return tools.Result{
		Output:   b.String(),
		Metadata: map[string]any{"state": state},
	}, nil
}

// ── Utility ────────────────────────────────────────────────────────────

// escapeJS escapes a string for safe embedding in JavaScript code.
func escapeJS(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// parseJSResult parses a JSON result from controller.js and formats it.
func parseJSResult(raw, action string) (tools.Result, error) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return tools.Result{Output: raw}, nil
	}

	success, _ := data["success"].(bool)
	if !success {
		errMsg, _ := data["error"].(string)
		return tools.Result{
			Output: fmt.Sprintf("❌ %s failed: %s", action, errMsg),
		}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("✅ %s succeeded\n", action))

	if eid, ok := data["elementId"].(string); ok {
		b.WriteString(fmt.Sprintf("  Element: @%s\n", eid))
	}
	if label, ok := data["label"].(string); ok && label != "" {
		b.WriteString(fmt.Sprintf("  Label: \"%s\"\n", label))
	}
	if tag, ok := data["tag"].(string); ok {
		b.WriteString(fmt.Sprintf("  Tag: <%s>\n", tag))
	}
	if url, ok := data["url"].(string); ok {
		b.WriteString(fmt.Sprintf("  URL: %s\n", url))
	}
	if newState, ok := data["newState"].(map[string]interface{}); ok && len(newState) > 0 {
		b.WriteString("  New State:\n")
		for k, v := range newState {
			b.WriteString(fmt.Sprintf("    %s: %v\n", k, v))
		}
	}
	if changes, ok := data["domChanges"].([]interface{}); ok && len(changes) > 0 {
		b.WriteString(fmt.Sprintf("  DOM Changes (%d):\n", len(changes)))
		for _, c := range changes {
			cm, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			b.WriteString(fmt.Sprintf("    → %s <%s> \"%s\"\n", cm["type"], cm["tag"], cm["text"]))
		}
	}

	return tools.Result{Output: b.String()}, nil
}
