// Package browser provides browser automation tools via go-rod/rod.
package browser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

var (
	mu         sync.Mutex
	browser    *rod.Browser
	page       *rod.Page
	pages      map[string]*rod.Page
	nextTab    int
	currentTab string
	// Captured cookies for session persistence
	savedCookies []*proto.NetworkCookie
	// Disk-backed session path
	sessionPath string
)

// savedCookieEntry is a JSON-serializable cookie for disk persistence.
type savedCookieEntry struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
}

// SetSessionPath configures where session.json is saved on disk.
func SetSessionPath(dir string) {
	mu.Lock()
	defer mu.Unlock()
	if dir != "" {
		sessionPath = filepath.Join(dir, "session.json")
	} else {
		sessionPath = ""
	}
}

func init() {
	pages = make(map[string]*rod.Page)
	nextTab = 1
}

// Register adds browser tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name: "browser_action",
		Description: `Control a headless Chromium browser for web interaction, login flows, and security testing.

ACTIONS:
  launch       — Start browser and optionally navigate to URL
  goto         — Navigate to a URL (waits for page load)
  snapshot     — Get interactive element tree with semantic IDs (@e1, @e2...) for clicking/typing
  click        — Click an element by CSS selector or @eX ID from snapshot
  type         — Type text into an input field
  submit       — Submit a form (click submit button or press Enter on a field)
  scroll       — Scroll page up or down
  screenshot   — Capture full-page PNG screenshot
  get_html     — Get raw HTML of page or specific element
  execute_js   — Run arbitrary JavaScript (e.g., document.cookie)
  get_cookies  — Get all cookies for the current domain
  set_cookie   — Set a cookie (name, value, domain)
  save_session — Save current cookies for later restoration
  load_session — Restore previously saved cookies
  wait         — Wait for a selector to appear or for navigation
  select       — Select an option from a dropdown
  fill_form    — Auto-fill a form: provide field=value pairs
  get_url      — Get current page URL
  iframe       — Switch into an iframe by selector/index
  main_frame   — Switch back to main page frame from iframe
  extract_links— Extract all links from the page (useful for verification emails)
  new_tab      — Open a new browser tab
  switch_tab   — Switch between tabs
  close        — Close browser

SIGNUP/LOGIN WORKFLOW:
  1. launch url=https://target.com/signup
  2. snapshot → identify form fields
  3. type selector=@e3 text=testuser123
  4. type selector=@e5 text=user@agentmail.to (from agentmail create_inbox)
  5. type selector=@e7 text=SecureP@ss123!
  6. click selector=@e9 (submit button)
  7. wait selector=".success" OR wait type=navigation
  8. Use agentmail wait_for_email to get verification link
  9. goto url=VERIFICATION_LINK
  10. get_cookies → save session tokens for authenticated testing`,
		Parameters: []tools.Parameter{
			{Name: "command", Description: "Browser action (see list above)", Required: true},
			{Name: "url", Description: "URL to navigate to (for launch/goto)", Required: false},
			{Name: "selector", Description: "CSS selector or semantic @eX ID from snapshot (for click/type/submit/wait/iframe/get_html/select)", Required: false},
			{Name: "text", Description: "Text to type (for type), option value (for select), or cookie value (for set_cookie)", Required: false},
			{Name: "code", Description: "JavaScript code to execute (for execute_js)", Required: false},
			{Name: "direction", Description: "Scroll direction: up or down (for scroll)", Required: false},
			{Name: "tab_id", Description: "Tab ID (for switch_tab)", Required: false},
			{Name: "proxy", Description: "Proxy: 'caido', 'none', or proxy URL", Required: false},
			{Name: "name", Description: "Cookie name (for set_cookie)", Required: false},
			{Name: "domain", Description: "Cookie domain (for set_cookie)", Required: false},
			{Name: "timeout", Description: "Timeout in seconds for wait actions (default: 10)", Required: false},
			{Name: "fields", Description: "Form fields as key=value pairs separated by | (for fill_form). Example: email=test@mail.com|password=Pass123|name=John", Required: false},
		},
		Execute: browserAction,
	})
}

// detectCaidoPort detects the Caido proxy port.
func detectCaidoPort() int {
	cfg := config.Get()
	if cfg.CaidoPort > 0 {
		return cfg.CaidoPort
	}
	return 8080
}

func ensureBrowser(proxy string) error {
	mu.Lock()
	defer mu.Unlock()

	if browser != nil {
		return nil
	}

	path, exists := launcher.LookPath()
	if !exists {
		// Fallback 1: Use Go's exec.LookPath which respects $PATH
		for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
			if p, err := exec.LookPath(name); err == nil {
				path = p
				exists = true
				break
			}
		}
	}
	if !exists {
		// Fallback 2: Check common Linux paths directly
		fallbacks := []string{
			"/usr/bin/chromium",
			"/usr/bin/google-chrome",
			"/usr/bin/chromium-browser",
			"/usr/bin/google-chrome-stable",
			"/snap/bin/chromium",
			"/usr/lib/chromium/chromium",
			"/usr/lib/chromium-browser/chromium-browser",
			"/opt/google/chrome/google-chrome",
			"/usr/local/bin/chromium",
		}
		for _, p := range fallbacks {
			if _, err := os.Stat(p); err == nil {
				path = p
				exists = true
				break
			}
		}
	}
	if !exists {
		// Fallback 3: Try to auto-install chromium
		installCmd := exec.Command("bash", "-c", "apt-get install -y -q chromium 2>&1 || apt-get install -y -q chromium-browser 2>&1")
		if out, err := installCmd.CombinedOutput(); err == nil {
			for _, name := range []string{"chromium", "chromium-browser"} {
				if p, err := exec.LookPath(name); err == nil {
					path = p
					exists = true
					break
				}
			}
			if !exists {
				return fmt.Errorf("Chromium installed but not found in PATH. Install output: %s", string(out))
			}
		} else {
			return fmt.Errorf("Chromium/Chrome not found and auto-install failed. Install manually with: sudo apt install chromium")
		}
	}

	ln := launcher.New().
		Bin(path).
		Headless(true).
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-gpu").
		Set("disable-web-security").           // Allow cross-origin for testing
		Set("allow-running-insecure-content"). // Allow mixed content
		Set("window-size", "1920,1080")

	if proxy == "caido" {
		caidoPort := detectCaidoPort()
		ln = ln.Set("proxy-server", fmt.Sprintf("http://127.0.0.1:%d", caidoPort)).
			Set("ignore-certificate-errors", "true")
	} else if proxy != "" && proxy != "none" {
		ln = ln.Set("proxy-server", proxy).
			Set("ignore-certificate-errors", "true")
	}

	u := ln.MustLaunch()

	browser = rod.New().ControlURL(u).MustConnect()
	return nil
}

// setupDialogHandler sets up auto-dismiss for JavaScript dialogs (alert/confirm/prompt)
// on a page. Without this, calling alert() in headless Chrome blocks page.Eval() forever.
// The dialog text is logged as proof of triggered XSS payloads.
func setupDialogHandler(p *rod.Page) {
	go p.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		dialogType := string(e.Type)
		msg := e.Message
		log.Printf("[browser] Auto-dismissing JS %s dialog: %q", dialogType, msg)
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(p)
	})()
}

func browserAction(args map[string]string) (tools.Result, error) {
	command := args["command"]

	switch command {
	case "launch":
		return launchBrowser(args["url"], args["proxy"])
	case "goto":
		return navigateTo(args["url"])
	case "snapshot":
		return takeSnapshot()
	case "click":
		return clickElement(args["selector"])
	case "type":
		return typeText(args["selector"], args["text"])
	case "submit":
		return submitForm(args["selector"])
	case "scroll":
		return scrollPage(args["direction"])
	case "screenshot":
		return takeScreenshot()
	case "get_html":
		return getHTML(args["selector"])
	case "execute_js":
		return executeJS(args["code"])
	case "get_cookies":
		return getCookies()
	case "set_cookie":
		return setCookie(args["name"], args["text"], args["domain"])
	case "save_session":
		return saveSession()
	case "load_session":
		return loadSession()
	case "wait":
		return waitFor(args["selector"], args["text"], args["timeout"])
	case "select":
		return selectOption(args["selector"], args["text"])
	case "fill_form":
		return fillForm(args["fields"])
	case "get_url":
		return getURL()
	case "iframe":
		return switchToIframe(args["selector"])
	case "main_frame":
		return switchToMainFrame()
	case "extract_links":
		return extractLinks()
	case "new_tab":
		return newTab(args["url"])
	case "switch_tab":
		return switchTab(args["tab_id"])
	case "close":
		return closeBrowser()
	default:
		return tools.Result{}, fmt.Errorf("unknown browser action: %s. Available: launch, goto, snapshot, click, type, submit, scroll, screenshot, get_html, execute_js, get_cookies, set_cookie, save_session, load_session, wait, select, fill_form, get_url, iframe, main_frame, extract_links, new_tab, switch_tab, close", command)
	}
}

func launchBrowser(rawURL, proxy string) (tools.Result, error) {
	if err := ensureBrowser(proxy); err != nil {
		return tools.Result{}, err
	}

	p := browser.MustPage()
	tabID := fmt.Sprintf("tab_%d", nextTab)
	nextTab++
	pages[tabID] = p
	currentTab = tabID
	page = p

	// Auto-dismiss JavaScript dialogs (alert/confirm/prompt) to prevent
	// page.Eval() from blocking forever in headless mode during XSS testing.
	setupDialogHandler(p)

	// Set a realistic user agent for login flows
	page.MustSetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	})

	if rawURL != "" {
		err := p.Timeout(20 * time.Second).Navigate(rawURL)
		if err == nil {
			p.Timeout(10 * time.Second).WaitStable(time.Second)
		}
	}

	return pageState("Browser launched", tabID)
}

func navigateTo(rawURL string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched — use launch first")
	}

	err := page.Timeout(20 * time.Second).Navigate(rawURL)
	if err == nil {
		// Wait for both DOM and network to become stable natively
		page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	}
	return pageState("Navigated", currentTab)
}

func parseSelector(selector string) string {
	if strings.HasPrefix(selector, "@e") {
		return fmt.Sprintf(`[data-xalgo-id="%s"]`, strings.TrimPrefix(selector, "@"))
	}
	return selector
}

func clickElement(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
	el, err := page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("element not found: %s", selector)
	}

	// Scroll element into view first
	el.MustScrollIntoView()
	el.MustClick()
	// Wait for any navigation or AJAX that results from the click
	time.Sleep(500 * time.Millisecond)
	page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	return pageState(fmt.Sprintf("Clicked: %s", selector), currentTab)
}

func typeText(selector, text string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
	el, err := page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("element not found: %s", selector)
	}

	// Clear existing content and type new text
	el.MustScrollIntoView()
	el.MustSelectAllText().MustInput(text)
	return pageState(fmt.Sprintf("Typed into: %s", selector), currentTab)
}

// submitForm submits a form — either clicks the submit button or presses Enter
func submitForm(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	if selector != "" {
		// Click the specified submit button/element
		selector = parseSelector(selector)
		el, err := page.Timeout(10 * time.Second).Element(selector)
		if err != nil {
			return tools.Result{}, fmt.Errorf("submit element not found: %s", selector)
		}
		el.MustScrollIntoView()
		el.MustClick()
	} else {
		// Try to find and click the first submit button in the page
		// Look for: button[type=submit], input[type=submit], button with submit text
		submitSelectors := []string{
			`button[type="submit"]`,
			`input[type="submit"]`,
			`button:not([type])`, // Buttons without type default to submit in forms
		}
		clicked := false
		for _, sel := range submitSelectors {
			el, err := page.Timeout(2 * time.Second).Element(sel)
			if err == nil {
				el.MustScrollIntoView()
				el.MustClick()
				clicked = true
				break
			}
		}
		if !clicked {
			// Fallback: press Enter on the active element
			page.Keyboard.Press(input.Enter)
		}
	}

	// Wait for navigation/AJAX after form submission
	time.Sleep(1 * time.Second)
	page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	return pageState("Form submitted", currentTab)
}

// getCookies returns all cookies for the current page
func getCookies() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	cookies, err := page.Cookies([]string{})
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to get cookies: %w", err)
	}

	if len(cookies) == 0 {
		return tools.Result{Output: "No cookies found for current page."}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Found %d cookies:\n\n", len(cookies)))
	for _, c := range cookies {
		flags := ""
		if c.HTTPOnly {
			flags += " HttpOnly"
		}
		if c.Secure {
			flags += " Secure"
		}
		if c.SameSite != "" {
			flags += " SameSite=" + string(c.SameSite)
		}
		b.WriteString(fmt.Sprintf("  %s = %s\n    Domain: %s  Path: %s  Expires: %s%s\n",
			c.Name, truncate(c.Value, 80), c.Domain, c.Path,
			formatExpiry(c.Expires), flags))
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"cookie_count": len(cookies),
		},
	}, nil
}

// setCookie sets a cookie on the current page
func setCookie(name, value, domain string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if name == "" || value == "" {
		return tools.Result{}, fmt.Errorf("name and text (value) are required for set_cookie")
	}

	// Auto-detect domain from current URL if not provided
	if domain == "" {
		info, _ := page.Info()
		if info != nil {
			u, err := url.Parse(info.URL)
			if err == nil {
				domain = u.Hostname()
			}
		}
	}

	err := page.SetCookies([]*proto.NetworkCookieParam{
		{
			Name:   name,
			Value:  value,
			Domain: domain,
			Path:   "/",
		},
	})
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to set cookie: %w", err)
	}

	return tools.Result{
		Output: fmt.Sprintf("Cookie set: %s=%s (domain: %s)", name, truncate(value, 40), domain),
	}, nil
}

// saveSession saves all current cookies for later restoration (memory + disk)
func saveSession() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	cookies, err := page.Cookies([]string{})
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to get cookies: %w", err)
	}

	savedCookies = cookies

	// Persist to disk
	if sessionPath != "" {
		entries := make([]savedCookieEntry, 0, len(cookies))
		for _, c := range cookies {
			entries = append(entries, savedCookieEntry{
				Name:     c.Name,
				Value:    c.Value,
				Domain:   c.Domain,
				Path:     c.Path,
				Secure:   c.Secure,
				HTTPOnly: c.HTTPOnly,
			})
		}
		data, err := json.MarshalIndent(entries, "", "  ")
		if err == nil {
			if err := os.WriteFile(sessionPath, data, 0644); err != nil {
				log.Printf("[browser] Warning: failed to save session to %s: %v", sessionPath, err)
			} else {
				log.Printf("[browser] Session saved to disk: %s (%d cookies)", sessionPath, len(entries))
			}
		}
	}

	return tools.Result{
		Output: fmt.Sprintf("✅ Session saved: %d cookies stored (memory + disk). Use load_session to restore.", len(cookies)),
		Metadata: map[string]any{"cookies_saved": len(cookies)},
	}, nil
}

// loadSession restores previously saved cookies (memory first, then disk fallback)
func loadSession() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	// Try disk fallback if no in-memory cookies
	if len(savedCookies) == 0 && sessionPath != "" {
		if data, err := os.ReadFile(sessionPath); err == nil {
			var entries []savedCookieEntry
			if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
				log.Printf("[browser] Loading %d cookies from disk: %s", len(entries), sessionPath)
				params := make([]*proto.NetworkCookieParam, 0, len(entries))
				for _, e := range entries {
					params = append(params, &proto.NetworkCookieParam{
						Name:     e.Name,
						Value:    e.Value,
						Domain:   e.Domain,
						Path:     e.Path,
						Secure:   e.Secure,
						HTTPOnly: e.HTTPOnly,
					})
				}
				if err := page.SetCookies(params); err != nil {
					return tools.Result{}, fmt.Errorf("failed to restore cookies from disk: %w", err)
				}
				page.Timeout(10 * time.Second).Reload()
				page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
				return tools.Result{
					Output: fmt.Sprintf("✅ Session restored from disk: %d cookies loaded and page refreshed.", len(entries)),
				}, nil
			}
		}
	}

	if len(savedCookies) == 0 {
		return tools.Result{Output: "No saved session found. Use save_session first after logging in."}, nil
	}

	params := make([]*proto.NetworkCookieParam, 0, len(savedCookies))
	for _, c := range savedCookies {
		params = append(params, &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		})
	}

	if err := page.SetCookies(params); err != nil {
		return tools.Result{}, fmt.Errorf("failed to restore cookies: %w", err)
	}

	// Reload page to apply cookies
	page.Timeout(10 * time.Second).Reload()
	page.Timeout(10 * time.Second).WaitStable(1 * time.Second)

	return tools.Result{
		Output: fmt.Sprintf("✅ Session restored: %d cookies loaded and page refreshed.", len(savedCookies)),
	}, nil
}

// waitFor waits for an element to appear, navigation to complete, or a timeout
func waitFor(selector, waitType, timeoutStr string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	timeout := 10 * time.Second
	if timeoutStr != "" {
		var secs int
		fmt.Sscanf(timeoutStr, "%d", &secs)
		if secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}

	if waitType == "navigation" || waitType == "nav" {
		// Wait for navigation to complete (URL change)
		info, _ := page.Info()
		oldURL := ""
		if info != nil {
			oldURL = info.URL
		}

		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			info, _ = page.Info()
			if info != nil && info.URL != oldURL {
				page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
				return pageState("Navigation detected", currentTab)
			}
		}
		return pageState("Wait completed (no navigation detected)", currentTab)
	}

	if selector != "" {
		selector = parseSelector(selector)
		_, err := page.Timeout(timeout).Element(selector)
		if err != nil {
			return tools.Result{Output: fmt.Sprintf("Element '%s' did not appear within %v", selector, timeout)}, nil
		}
		return pageState(fmt.Sprintf("Element found: %s", selector), currentTab)
	}

	// Default: just wait for page to stabilize
	page.Timeout(10 * time.Second).WaitStable(1 * time.Second)
	return pageState("Page stabilized", currentTab)
}

// selectOption selects an option from a <select> dropdown
func selectOption(selector, value string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
	el, err := page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("select element not found: %s", selector)
	}

	// Try selecting by value first, then by visible text
	err = el.Select([]string{value}, true, rod.SelectorTypeText)
	if err != nil {
		// Fallback: try by value attribute
		_, evalErr := page.Eval(fmt.Sprintf(`() => {
			const el = document.querySelector('%s');
			if (el) {
				for (const opt of el.options) {
					if (opt.value === '%s' || opt.text === '%s') {
						el.value = opt.value;
						el.dispatchEvent(new Event('change', { bubbles: true }));
						return true;
					}
				}
			}
			return false;
		}`, selector, value, value))
		if evalErr != nil {
			return tools.Result{}, fmt.Errorf("failed to select option '%s': %w", value, err)
		}
	}

	return tools.Result{Output: fmt.Sprintf("Selected '%s' in %s", value, selector)}, nil
}

// fillForm auto-fills multiple form fields at once
func fillForm(fields string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if fields == "" {
		return tools.Result{}, fmt.Errorf("fields parameter is required. Format: field1=value1|field2=value2")
	}

	pairs := strings.Split(fields, "|")
	filled := []string{}

	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			continue
		}
		fieldName := strings.TrimSpace(parts[0])
		fieldValue := strings.TrimSpace(parts[1])

		// Try multiple selector strategies to find the field
		selectors := []string{
			fmt.Sprintf(`input[name="%s"]`, fieldName),
			fmt.Sprintf(`input[id="%s"]`, fieldName),
			fmt.Sprintf(`input[placeholder*="%s" i]`, fieldName),
			fmt.Sprintf(`textarea[name="%s"]`, fieldName),
			fmt.Sprintf(`select[name="%s"]`, fieldName),
			fmt.Sprintf(`[aria-label*="%s" i]`, fieldName),
		}

		found := false
		for _, sel := range selectors {
			el, err := page.Timeout(2 * time.Second).Element(sel)
			if err == nil {
				tag, _ := el.Eval(`() => this.tagName.toLowerCase()`)
				if tag != nil && tag.Value.String() == "select" {
					el.Select([]string{fieldValue}, true, rod.SelectorTypeText)
				} else {
					el.MustScrollIntoView()
					el.MustSelectAllText().MustInput(fieldValue)
				}
				filled = append(filled, fieldName)
				found = true
				break
			}
		}
		if !found {
			filled = append(filled, fieldName+" (NOT FOUND)")
		}
	}

	return tools.Result{
		Output: fmt.Sprintf("Form filled: %s\n\nTip: Use 'submit' command to submit the form.", strings.Join(filled, ", ")),
	}, nil
}

// getURL returns the current page URL
func getURL() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	info, _ := page.Info()
	if info == nil {
		return tools.Result{Output: "Unable to get page info"}, nil
	}

	return tools.Result{
		Output:   info.URL,
		Metadata: map[string]any{"url": info.URL, "title": info.Title},
	}, nil
}

// switchToIframe switches page context into an iframe
func switchToIframe(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	if selector == "" {
		selector = "iframe"
	}
	selector = parseSelector(selector)

	el, err := page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("iframe not found: %s", selector)
	}

	frame, err := el.Frame()
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to access iframe: %w", err)
	}

	// Store the main page and switch context to the iframe's page
	iframeURL := ""
	frameInfo, _ := frame.Info()
	if frameInfo != nil {
		iframeURL = frameInfo.URL
	}

	// Create a virtual tab for the iframe
	tabID := fmt.Sprintf("iframe_%d", nextTab)
	nextTab++
	pages[tabID] = frame
	currentTab = tabID
	page = frame

	return tools.Result{
		Output: fmt.Sprintf("Switched to iframe: %s\n  URL: %s\n  Tab ID: %s (use main_frame to switch back)", selector, iframeURL, tabID),
	}, nil
}

// switchToMainFrame switches back to the main page from an iframe
func switchToMainFrame() (tools.Result, error) {
	// Find the first non-iframe tab
	for id, p := range pages {
		if !strings.HasPrefix(id, "iframe_") {
			page = p
			currentTab = id
			return pageState("Switched to main frame", currentTab)
		}
	}
	return tools.Result{Output: "No main frame found"}, nil
}

// extractLinks extracts all links from the current page
func extractLinks() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	script := `() => {
		const links = [];
		document.querySelectorAll('a[href]').forEach(a => {
			const href = a.href;
			const text = (a.innerText || a.title || a.getAttribute('aria-label') || '').trim().substring(0, 60);
			if (href && !href.startsWith('javascript:')) {
				links.push(text ? text + ' → ' + href : href);
			}
		});
		return links.join('\n');
	}`

	result, err := page.Eval(script)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to extract links: %w", err)
	}

	output := result.Value.String()
	if output == "" {
		output = "No links found on the page."
	}

	// Count links
	linkCount := len(strings.Split(output, "\n"))

	return tools.Result{
		Output:   fmt.Sprintf("Found %d links:\n\n%s", linkCount, output),
		Metadata: map[string]any{"link_count": linkCount},
	}, nil
}

func scrollPage(direction string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	switch strings.ToLower(direction) {
	case "down":
		page.Mouse.MustScroll(0, 500)
	case "up":
		page.Mouse.MustScroll(0, -500)
	default:
		page.Mouse.MustScroll(0, 500)
	}

	time.Sleep(500 * time.Millisecond)
	return pageState(fmt.Sprintf("Scrolled %s", direction), currentTab)
}

func takeScreenshot() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: nil,
	})
	if err != nil {
		return tools.Result{}, fmt.Errorf("screenshot failed: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(img)

	return tools.Result{
		Output: fmt.Sprintf("Screenshot captured (%d bytes)", len(img)),
		Metadata: map[string]any{
			"screenshot": b64,
			"format":     "png",
			"size_bytes": len(img),
		},
	}, nil
}

// takeSnapshot returns an enhanced accessibility tree with form-aware element detection
func takeSnapshot() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	script := `() => {
		let output = [];
		let counter = 1;
		
		// Enhanced selector: includes form elements, labels, and more interactive elements
		const elements = document.querySelectorAll(
			'a, button, input, select, textarea, label, ' +
			'[role="button"], [role="link"], [role="textbox"], [role="checkbox"], [role="radio"], ' +
			'[role="combobox"], [role="listbox"], [role="menuitem"], [role="tab"], ' +
			'[tabindex]:not([tabindex="-1"]), [contenteditable="true"], ' +
			'form, details, summary'
		);
		
		elements.forEach(el => {
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) return;
			const style = window.getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return;
			
			let id = 'e' + counter++;
			el.setAttribute('data-xalgo-id', id);
			
			let tag = el.tagName.toLowerCase();
			let type = el.type ? '(' + el.type + ')' : '';
			let name = el.name ? ' name="' + el.name + '"' : '';
			let placeholder = el.placeholder ? ' placeholder="' + el.placeholder + '"' : '';
			
			// Get text — priority: innerText > value > placeholder > aria-label > alt > title
			let text = '';
			if (tag === 'input' || tag === 'textarea') {
				text = el.value || el.placeholder || el.getAttribute('aria-label') || '';
			} else if (tag === 'select') {
				const selected = el.options[el.selectedIndex];
				text = selected ? selected.text : '';
			} else if (tag === 'label') {
				text = el.innerText || '';
				// Link label to its input
				const forEl = el.htmlFor ? document.getElementById(el.htmlFor) : el.querySelector('input,select,textarea');
				if (forEl) {
					const forId = forEl.getAttribute('data-xalgo-id');
					if (forId) text += ' → @' + forId;
				}
			} else {
				text = (el.innerText || el.getAttribute('aria-label') || el.alt || el.title || '').trim();
			}
			text = text.replace(/\n/g, ' ').substring(0, 60);
			
			// Build descriptor
			let desc = '[@' + id + '] ' + tag + type + name;
			if (text) desc += ' "' + text + '"';
			if (placeholder) desc += placeholder;
			
			// Mark required fields
			if (el.required) desc += ' [REQUIRED]';
			// Mark disabled
			if (el.disabled) desc += ' [DISABLED]';
			
			output.push(desc);
		});
		
		// Also note any visible forms
		const forms = document.querySelectorAll('form');
		if (forms.length > 0) {
			output.unshift('--- Page has ' + forms.length + ' form(s) ---');
		}
		
		return output.join('\n');
	}`

	result, err := page.Eval(script)
	if err != nil {
		return tools.Result{}, fmt.Errorf("snapshot failed: %w", err)
	}

	info, _ := page.Info()
	urlStr := ""
	if info != nil {
		urlStr = "\nURL: " + info.URL + "\n"
	}

	return tools.Result{
		Output: "Interactive Elements Tree:" + urlStr + "\n" + result.Value.String(),
	}, nil
}

func getHTML(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	var html string
	if selector != "" {
		selector = parseSelector(selector)
		el, err := page.Timeout(10 * time.Second).Element(selector)
		if err != nil {
			return tools.Result{}, fmt.Errorf("element not found: %s", selector)
		}
		html, _ = el.HTML()
	} else {
		html = page.MustHTML()
	}

	if len(html) > 20000 {
		html = html[:20000] + "\n\n... [HTML TRUNCATED]"
	}

	return tools.Result{Output: html}, nil
}

func executeJS(code string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	// Use a timeout to prevent blocking forever (e.g., alert() in headless Chrome).
	// The dialog handler auto-dismisses alerts, but we add a timeout as a safety net.
	result, err := page.Timeout(10 * time.Second).Eval(code)
	if err != nil {
		// If it timed out, it's likely a blocking dialog that wasn't caught
		if strings.Contains(err.Error(), "context deadline") || strings.Contains(err.Error(), "timeout") {
			return tools.Result{
				Output: "⚠️ JS execution timed out (likely a blocking dialog like alert/confirm/prompt). The dialog was triggered, which confirms JavaScript execution. Use page.Eval with a non-blocking approach instead.",
			}, nil
		}
		return tools.Result{}, fmt.Errorf("JS error: %w", err)
	}

	return tools.Result{Output: result.Value.String()}, nil
}

func newTab(rawURL string) (tools.Result, error) {
	if browser == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	p := browser.MustPage()
	tabID := fmt.Sprintf("tab_%d", nextTab)
	nextTab++
	pages[tabID] = p
	currentTab = tabID
	page = p

	// Auto-dismiss JavaScript dialogs on new tabs too
	setupDialogHandler(p)

	if rawURL != "" {
		err := p.Timeout(20 * time.Second).Navigate(rawURL)
		if err == nil {
			p.Timeout(10 * time.Second).WaitStable(1 * time.Second)
		}
	}

	return pageState("New tab opened", tabID)
}

func switchTab(tabID string) (tools.Result, error) {
	p, ok := pages[tabID]
	if !ok {
		return tools.Result{}, fmt.Errorf("tab not found: %s (available: %v)", tabID, tabList())
	}

	page = p
	currentTab = tabID
	return pageState("Switched tab", tabID)
}

func closeBrowser() (tools.Result, error) {
	mu.Lock()
	defer mu.Unlock()

	cleanupBrowserLocked()

	return tools.Result{Output: "Browser closed"}, nil
}

// cleanupBrowserLocked closes browser resources (must hold mu).
func cleanupBrowserLocked() {
	savedCookies = nil
	if browser != nil {
		browser.MustClose()
		browser = nil
		page = nil
		pages = make(map[string]*rod.Page)
	}
}

// CleanupBrowser safely closes any open browser and resets state.
// Called between scan phases and on agent stop to prevent stale connection usage.
func CleanupBrowser() {
	mu.Lock()
	defer mu.Unlock()
	if browser != nil {
		// Use recover to handle panics from already-dead browser processes
		func() {
			defer func() { recover() }()
			browser.MustClose()
		}()
		browser = nil
		page = nil
		pages = make(map[string]*rod.Page)
		savedCookies = nil
	}
}

func pageState(action, tabID string) (tools.Result, error) {
	if page == nil {
		return tools.Result{Output: action}, nil
	}

	info, _ := page.Info()
	rawURL := ""
	title := ""
	if info != nil {
		rawURL = info.URL
		title = info.Title
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n", action))
	b.WriteString(fmt.Sprintf("  Tab: %s\n", tabID))
	if rawURL != "" {
		b.WriteString(fmt.Sprintf("  URL: %s\n", rawURL))
	}
	if title != "" {
		b.WriteString(fmt.Sprintf("  Title: %s\n", title))
	}

	// List all tabs
	if len(pages) > 1 {
		b.WriteString("  All tabs: ")
		b.WriteString(strings.Join(tabList(), ", "))
		b.WriteString("\n")
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"url":    rawURL,
			"title":  title,
			"tab_id": tabID,
		},
	}, nil
}

func tabList() []string {
	tabs := make([]string, 0, len(pages))
	for id := range pages {
		tabs = append(tabs, id)
	}
	return tabs
}

// Helper: truncate string for display
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Helper: format cookie expiry timestamp
func formatExpiry(ts proto.TimeSinceEpoch) string {
	if ts == 0 {
		return "Session"
	}
	t := ts.Time()
	if t.IsZero() {
		return "Session"
	}
	return t.Format("2006-01-02 15:04")
}

// ExtractVerificationURL extracts verification/confirmation URLs from email body text.
// Useful for the agent to programmatically find verification links.
func ExtractVerificationURL(emailBody string) string {
	// Common verification URL patterns
	urlRegex := regexp.MustCompile(`https?://[^\s<>"']+(?:verif|confirm|activate|valid|token|auth|callback|reset|click)[^\s<>"']*`)
	match := urlRegex.FindString(emailBody)
	if match != "" {
		return strings.TrimRight(match, ".,;:!)]}>")
	}

	// Fallback: find any URL with a long token/hash parameter
	tokenURLRegex := regexp.MustCompile(`https?://[^\s<>"']*[?&][^\s<>"']*=[a-zA-Z0-9_-]{20,}[^\s<>"']*`)
	match = tokenURLRegex.FindString(emailBody)
	if match != "" {
		return strings.TrimRight(match, ".,;:!)]}>")
	}

	return ""
}
