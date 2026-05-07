// Package web provides the Xalgorix web UI server.
package web

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	mathrand "math/rand/v2"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// Version is set by main.go at startup — single source of truth.
var Version = "dev"

//go:embed static/*
var staticFiles embed.FS

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	stopCh   chan struct{}
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		stopCh:   make(chan struct{}),
	}
	// Cleanup old entries every minute
	go func() {
		for {
			select {
			case <-rl.stopCh:
				return
			case <-time.After(time.Minute):
				rl.cleanup()
			}
		}
	}()
	return rl
}

// Stop signals the cleanup goroutine to exit
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if now.Sub(t) < rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Get or create the slice
	times := rl.requests[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for WebSocket and static files
			if r.URL.Path == "/ws" || strings.HasPrefix(r.URL.Path, "/static") || strings.HasPrefix(r.URL.Path, "/assets") {
				next.ServeHTTP(w, r)
				return
			}

			// Use RemoteAddr only — do not trust X-Forwarded-For as it can be
			// spoofed when running without a trusted reverse proxy. Strip the
			// port so each TCP connection from the same client shares a bucket.
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── Authentication ─────────────────────────────────────────────────────────

// logRecover is a deferred recovery helper used by best-effort cleanup
// blocks. The previous pattern was `defer func() { recover() }()` which
// silently swallowed panics — making cleanup bugs invisible in
// production. logRecover preserves the original behaviour (don't crash
// the server during shutdown) while emitting a stack trace so the bug
// can be diagnosed.
//
// Usage: defer logRecover("scanSession.cleanup.scanctx")
func logRecover(label string) {
	if r := recover(); r != nil {
		log.Printf("[recover] %s: %v\n%s", label, r, debug.Stack())
	}
}

// authSessions stores valid session tokens (token → expiry)
var (
	authSessions      = make(map[string]time.Time)
	authSessionsMu    sync.RWMutex
	sessionReaperOnce sync.Once
)

const sessionCookieName = "xalgorix_session"
const sessionDuration = 24 * time.Hour
const sessionReaperInterval = 15 * time.Minute

// generateSessionToken creates a cryptographically random session token.
// Returns an error if the system entropy source is unavailable instead of
// terminating the whole process — callers should surface a 500 to the user.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand unavailable: %w", err)
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

// isValidSession checks if a session token is valid and not expired
func isValidSession(token string) bool {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	expiry, ok := authSessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(authSessions, token)
		return false
	}
	return true
}

// startSessionReaper sweeps expired session tokens on a fixed interval so the
// authSessions map cannot grow unbounded from abandoned cookies. Runs once
// per process.
func startSessionReaper() {
	sessionReaperOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(sessionReaperInterval)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				authSessionsMu.Lock()
				for tok, expiry := range authSessions {
					if now.After(expiry) {
						delete(authSessions, tok)
					}
				}
				authSessionsMu.Unlock()
			}
		}()
	})
}

// isCSRFSafe returns true when a state-changing request is verifiably
// originated from this site. We use Origin (and Referer as a fallback)
// because every modern browser sends one of them on POST/PUT/PATCH/DELETE,
// while non-browser API clients (curl, scripts, the LLM tooling) typically
// send neither — those are allowed through. SameSite=Strict on the session
// cookie already blocks the most common CSRF vectors; this is defense in
// depth for the Sec-Fetch-Site and document-form-submit edge cases.
func isCSRFSafe(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}

	// Browser hint: only "same-origin" is safe. Empty header means the
	// client probably isn't a browser, which we allow.
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "":
		// fall through to Origin/Referer checks
	case "same-origin", "none":
		return true
	default:
		// "same-site" or "cross-site" — refuse.
		return false
	}

	// Compare Origin/Referer host with request Host.
	check := func(raw string) (bool, bool) {
		if raw == "" {
			return false, false
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return false, true
		}
		return u.Host == r.Host, true
	}

	if ok, present := check(r.Header.Get("Origin")); present {
		return ok
	}
	if ok, present := check(r.Header.Get("Referer")); present {
		return ok
	}
	// Neither Origin nor Referer nor Sec-Fetch-Site present: not a browser.
	return true
}

// authMiddleware protects routes when auth is configured
func authMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// CSRF: validate state-changing requests on /api/* regardless of
			// whether auth is configured. This blocks an attacker page from
			// triggering a scan via the cookie even when no password is set
			// for local-loopback deployments.
			if strings.HasPrefix(path, "/api/") && path != "/api/auth/login" {
				if !isCSRFSafe(r) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "CSRF check failed: request origin does not match server host",
					})
					return
				}
			}

			// Skip auth if no credentials configured
			if cfg.Username == "" || cfg.Password == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Public routes that don't need auth
			if path == "/api/auth/login" || path == "/api/auth/status" ||
				strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/assets/") ||
				strings.HasPrefix(path, "/uploads/") {
				next.ServeHTTP(w, r)
				return
			}

			// Check for session cookie
			cookie, err := r.Cookie(sessionCookieName)
			if err == nil && isValidSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}

			// For API requests, return 401 JSON
			if strings.HasPrefix(path, "/api/") || path == "/ws" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication required",
				})
				return
			}

			// For page requests, serve login page
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(loginPageHTML))
		})
	}
}

// handleLogin handles POST /api/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// Constant-time comparison to avoid leaking the username/password length
	// or character-by-character match position via response time. We always
	// compare both fields even on a username miss so the work performed is
	// independent of which one is wrong.
	userMatch := subtle.ConstantTimeCompare([]byte(creds.Username), []byte(s.cfg.Username)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(creds.Password), []byte(s.cfg.Password)) == 1
	if !userMatch || !passMatch {
		// Rate-limit failed attempts
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	// Create session
	token, err := generateSessionToken()
	if err != nil {
		log.Printf("[auth] session token generation failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal error generating session"})
		return
	}
	authSessionsMu.Lock()
	authSessions[token] = time.Now().Add(sessionDuration)
	authSessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleLogout handles POST /api/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		authSessionsMu.Lock()
		delete(authSessions, cookie.Value)
		authSessionsMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
}

// handleAuthStatus handles GET /api/auth/status
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	authEnabled := s.cfg.Username != "" && s.cfg.Password != ""

	authenticated := false
	if authEnabled {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && isValidSession(cookie.Value) {
			authenticated = true
		}
	} else {
		authenticated = true // No auth configured = always authenticated
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"auth_enabled":  authEnabled,
		"authenticated": authenticated,
	})
}

// loginPageHTML is defined in login.go

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Reject cross-site WebSocket connections to prevent CSWSH attacks.
		// Allow if no Origin header (direct connection) or Origin matches Host.
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		// Parse origin and compare scheme+host with request Host
		if u, err := url.Parse(origin); err == nil {
			return u.Host == r.Host
		}
		return false
	},
	ReadBufferSize:  8192,
	WriteBufferSize: 32768,
}

const (
	// WebSocket keepalive settings
	wsPingInterval   = 30 * time.Second
	wsPongWait       = 60 * time.Second
	wsWriteWait      = 10 * time.Second
	wsMaxMessageSize = 8192 // max incoming message from client
	wsMaxClients     = 50
	wsSendBufSize    = 512 // buffered channel size per client
)

// wsClient wraps a WebSocket connection with a buffered send channel.
//
// Concurrency: instanceID is mutated by readPump (subscribe/unsubscribe)
// and read by broadcastToInstance / broadcastDashboard from other
// goroutines. ALL reads and writes MUST hold server.mu (RLock for reads,
// Lock for writes). The lock also guards iteration over server.clients,
// so an atomic.Pointer would be redundant and would split the invariant
// into two synchronization mechanisms.
type wsClient struct {
	conn       *websocket.Conn
	send       chan []byte
	server     *Server
	instanceID string // GUARDED BY server.mu — see struct doc.
}

// writePump drains the send channel and writes to the WebSocket.
// Also handles periodic ping messages for keepalive.
func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
		c.server.removeClient(c)
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				// Server closed the channel — send close frame
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads messages from the WebSocket (scan requests).
// Also sets up pong handler for keepalive.
func (c *wsClient) readPump() {
	defer func() {
		c.server.removeClient(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(wsMaxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		// Fast path: check message type with quick prefix check before JSON unmarshal
		// Avoids triple unmarshal for common subscribe/unsubscribe messages
		switch {
		case bytes.HasPrefix(msg, []byte(`{"subscribe"`)):
			var subMsg struct {
				Subscribe string `json:"subscribe"`
			}
			if err := json.Unmarshal(msg, &subMsg); err == nil && subMsg.Subscribe != "" {
				c.server.mu.Lock()
				c.instanceID = subMsg.Subscribe
				c.server.mu.Unlock()
				continue
			}
		case bytes.HasPrefix(msg, []byte(`{"unsubscribe"`)):
			var unsubMsg struct {
				Unsubscribe bool `json:"unsubscribe"`
			}
			if err := json.Unmarshal(msg, &unsubMsg); err == nil && unsubMsg.Unsubscribe {
				c.server.mu.Lock()
				c.instanceID = ""
				c.server.mu.Unlock()
				continue
			}
		}

		var req ScanRequest
		if err := json.Unmarshal(msg, &req); err == nil && len(req.Targets) > 0 {
			// Apply LLM provider settings from WebSocket message securely using a copy
			scanCfg := *c.server.cfg // shallow copy
			if req.Model != "" {
				scanCfg.LLM = req.Model
			}
			if req.APIKey != "" {
				scanCfg.APIKey = req.APIKey
			}
			if req.APIBase != "" {
				scanCfg.APIBase = req.APIBase
			}
			go c.server.runMultiScan(req, &scanCfg)
		}
	}
}

// ScanRequest is the JSON body for starting a scan.
type ScanRequest struct {
	Targets        []string `json:"targets"`
	Instruction    string   `json:"instruction"`
	ScanMode       string   `json:"scan_mode"`       // "single" or "wildcard"
	Model          string   `json:"model"`           // e.g. "minimax/MiniMax-M2.5"
	APIKey         string   `json:"api_key"`         // provider API key
	APIBase        string   `json:"api_base"`        // provider API base URL
	DiscordWebhook string   `json:"discord_webhook"` // Discord webhook URL
	SeverityFilter []string `json:"severity_filter"` // e.g. ["critical", "high"]
	Name           string   `json:"name"`            // user-defined scan name
	SaveOnly       bool     `json:"save_only"`       // if true, save scan config without starting
	Phases         []int    `json:"phases"`          // selected methodology phases (empty = all)
	CompanyName    string   `json:"company_name"`    // report branding: company name
	LogoPath       string   `json:"logo_path"`       // report branding: logo file path
	// Internal fields — `json:"-"` makes them un-settable from the wire.
	// Critical: a client must not be able to set InstanceID to spoof
	// broadcasts to another scan, or set IsResume to bypass the resume
	// codepath's safety checks.
	InstanceID string `json:"-"` // parent instance ID, threaded server-side
	IsResume   bool   `json:"-"` // true when auto-resuming after restart
}

// WSEvent is a WebSocket message sent to clients.
type WSEvent struct {
	Type           string            `json:"type"`
	Content        string            `json:"content,omitempty"`
	ToolName       string            `json:"tool_name,omitempty"`
	ToolArgs       map[string]string `json:"tool_args,omitempty"`
	Output         string            `json:"output,omitempty"`
	Error          string            `json:"error,omitempty"`
	AgentID        string            `json:"agent_id,omitempty"`
	Timestamp      string            `json:"timestamp,omitempty"`
	Vulns          []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex    int               `json:"target_index,omitempty"`
	TotalTargets   int               `json:"total_targets,omitempty"`
	Target         string            `json:"target,omitempty"`
	TotalTokens    int               `json:"total_tokens,omitempty"`
	SubTargetIndex int               `json:"sub_target_index,omitempty"` // subdomain index within a wildcard target
	SubTargetTotal int               `json:"sub_target_total,omitempty"` // total subdomains for current wildcard target
	ParentTarget   string            `json:"parent_target,omitempty"`    // parent domain for subdomain scans
}

// VulnSummary is a simplified vulnerability for the UI.
type VulnSummary struct {
	ID                 string  `json:"id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	Endpoint           string  `json:"endpoint"`
	CVSS               float64 `json:"cvss"`
	CVSSVector         string  `json:"cvss_vector,omitempty"`
	Description        string  `json:"description,omitempty"`
	Impact             string  `json:"impact,omitempty"`
	Method             string  `json:"method,omitempty"`
	CVE                string  `json:"cve,omitempty"`
	TechnicalAnalysis  string  `json:"technical_analysis,omitempty"`
	PoCDescription     string  `json:"poc_description,omitempty"`
	PoCScript          string  `json:"poc_script,omitempty"`
	Remediation        string  `json:"remediation,omitempty"`
	ExploitationProof  string  `json:"exploitation_proof,omitempty"`
	VerificationMethod string  `json:"verification_method,omitempty"`
}

// ScanRecord is a persisted scan result.
type ScanRecord struct {
	ID           string        `json:"id"`
	Target       string        `json:"target"`
	ParentTarget string        `json:"parent_target,omitempty"` // parent domain for subdomain scans (wildcard mode)
	StartedAt    string        `json:"started_at"`
	FinishedAt   string        `json:"finished_at,omitempty"`
	Status       string        `json:"status"`                // running, finished, stopped
	StopReason   string        `json:"stop_reason,omitempty"` // why scan stopped (error, user, watchdog, etc.)
	ScanMode     string        `json:"scan_mode,omitempty"`   // single, wildcard, dast
	Events       []WSEvent     `json:"events"`
	Vulns        []VulnSummary `json:"vulns"`
	TotalTokens  int           `json:"total_tokens"`
	Iterations   int           `json:"iterations"`
	ToolCalls    int           `json:"tool_calls"`
	CompanyName  string        `json:"company_name,omitempty"` // report branding: company name
	LogoPath     string        `json:"logo_path,omitempty"`    // report branding: logo path
	Phases       []int         `json:"phases,omitempty"`       // selected methodology phases
}

// QueueState persists scan queue state for recovery after restart
type QueueState struct {
	Targets     []string `json:"targets"`
	CurrentIdx  int      `json:"current_idx"`
	Instruction string   `json:"instruction"`
	ScanMode    string   `json:"scan_mode"`
	StartedAt   string   `json:"started_at"`
	Active      bool     `json:"active"`
}

// ScanInstance represents a running or completed scan instance.
type ScanInstance struct {
	ID                string        `json:"id"`
	Name              string        `json:"name,omitempty"`          // user-defined scan name
	Targets           string        `json:"targets"`
	ParentTarget      string        `json:"parent_target,omitempty"` // parent domain for subdomain scans
	Status            string        `json:"status"`                  // saved, running, paused, finished, stopped
	StartedAt         string        `json:"started_at"`
	FinishedAt        string        `json:"finished_at,omitempty"`
	StopReason        string        `json:"stop_reason,omitempty"` // why stopped (user, error, watchdog)
	Iterations        int           `json:"iterations"`
	ToolCalls         int           `json:"tool_calls"`
	VulnCount         int           `json:"vuln_count"`
	TotalTokens       int           `json:"total_tokens"`
	ScanMode          string        `json:"scan_mode"`
	Instruction       string        `json:"instruction,omitempty"`     // custom scan instructions for restart
	SeverityFilter    []string      `json:"severity_filter,omitempty"` // severity filter for restart
	Phases            []int         `json:"phases,omitempty"`          // selected methodology phases (empty = all)
	CompanyName       string        `json:"company_name,omitempty"`    // report branding: company name
	LogoPath          string        `json:"logo_path,omitempty"`       // report branding: logo path
	DiscordWebhook    string        `json:"-"`                         // discord webhook (not exposed to API)
	Vulns             []VulnSummary `json:"vulns,omitempty"`
	agent             *agent.Agent
	cancel            context.CancelFunc
	scanDir           string
	sctx              *scanctx.ScanContext // per-instance session state (vulns, notes, terminal, browser)
	events            []WSEvent            // buffered events for replay
	mu                sync.RWMutex
	lastSessionTokens int // tracks token count from current session for delta calculation
}

// maxConcurrentInstances removed — replaced by dynamic resource-aware
// admission via resources.CanAdmitScan(). See internal/resources/.

// saveQueueState saves the current queue state to disk
func (s *Server) saveQueueState(targets []string, idx int, instruction, scanMode string) {
	state := QueueState{
		Targets:     targets,
		CurrentIdx:  idx,
		Instruction: instruction,
		ScanMode:    scanMode,
		StartedAt:   time.Now().Format(time.RFC3339),
		Active:      true,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal queue state: %v", err)
		return
	}
	if err := os.WriteFile(s.queueStatePath(), data, 0644); err != nil {
		log.Printf("Error: failed to save queue state: %v", err)
	}
}

func (s *Server) queueStatePath() string {
	return filepath.Join(s.dataDir, "queue_state.json")
}

func (s *Server) loadQueueStateWithError() (*QueueState, error) {
	data, err := os.ReadFile(s.queueStatePath())
	if err != nil {
		return nil, err
	}
	var state QueueState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// loadQueueState loads queue state from disk if exists
func (s *Server) loadQueueState() *QueueState {
	state, err := s.loadQueueStateWithError()
	if err != nil {
		return nil
	}
	return state
}

func (s *Server) validQueueState(clearInvalid bool) (*QueueState, string) {
	state, err := s.loadQueueStateWithError()
	if err != nil {
		if clearInvalid && !os.IsNotExist(err) {
			log.Printf("[queue] Invalid queue state, clearing: %v", err)
			s.clearQueueState()
		}
		return nil, "missing_or_invalid"
	}
	if state == nil || !state.Active {
		return nil, "inactive"
	}
	if len(state.Targets) == 0 {
		if clearInvalid {
			s.clearQueueState()
		}
		return nil, "empty"
	}
	if state.CurrentIdx < 0 {
		if clearInvalid {
			log.Printf("[queue] Corrupt queue state (idx=%d), clearing.", state.CurrentIdx)
			s.clearQueueState()
		}
		return nil, "corrupt_index"
	}
	if state.CurrentIdx >= len(state.Targets) {
		if clearInvalid {
			log.Printf("[queue] Completed queue state (idx=%d, targets=%d), clearing.", state.CurrentIdx, len(state.Targets))
			s.clearQueueState()
		}
		return nil, "completed"
	}
	return state, ""
}

// clearQueueState removes the queue state file
func (s *Server) clearQueueState() {
	if err := os.Remove(s.queueStatePath()); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove queue state file: %v", err)
	}
}

// Server is the web UI server.
type Server struct {
	cfg                *config.Config
	port               int
	clients            map[*wsClient]bool
	mu                 sync.RWMutex
	currentAgents      map[string]*agent.Agent // scanID → agent (replaces singleton currentAgent)
	cancelScan         context.CancelFunc      // cancels the current scan session context
	running            atomic.Bool
	stopReq            atomic.Bool
	dataDir            string
	currentScanDir     string
	currentScanID      string
	discordWebhook     string
	discordMinSeverity string // minimum severity to send to Discord ("info", "low", "medium", "high", "critical")
	rateLimiter        *RateLimiter
	instances          map[string]*ScanInstance // concurrent scan instances
	instancesMu        sync.RWMutex
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, port int) *Server {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Warning: failed to get home directory: %v (using /root)", err)
		home = "/root"
	}
	dataDir := filepath.Join(home, "xalgorix-data")
	// Rate limit from config (defaults: 60 requests per minute)
	rl := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)

	srv := &Server{
		cfg:                cfg,
		port:               port,
		clients:            make(map[*wsClient]bool),
		currentAgents:      make(map[string]*agent.Agent),
		dataDir:            dataDir,
		discordWebhook:     os.Getenv("XALGORIX_DISCORD_WEBHOOK"),
		discordMinSeverity: strings.ToLower(strings.TrimSpace(os.Getenv("XALGORIX_DISCORD_MIN_SEVERITY"))),
		rateLimiter:        rl,
		instances:          make(map[string]*ScanInstance),
	}

	// Rebuild instances map from disk so dashboard shows historical scans on startup
	srv.rebuildInstancesFromDisk()

	return srv
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	// Reap expired session cookies in the background so the auth map cannot
	// grow unbounded from abandoned logins.
	if s.cfg.Username != "" && s.cfg.Password != "" {
		startSessionReaper()
	}

	// Auto-start Caido proxy in background if available
	startCaidoProxy()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}

	mux := http.NewServeMux()
	// SPA handler: serve static files if they exist, otherwise serve index.html
	fileServer := http.FileServer(http.FS(staticFS))
	// fs.Sub on embed.FS returns an fs.FS that does implement ReadFileFS today,
	// but assert with comma-ok so a future runtime change can't crash the server.
	rfs, hasRfs := staticFS.(fs.ReadFileFS)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the static file
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Check if it's a real static file - strip /static prefix since staticFS already points to static folder
		strippedPath := strings.TrimPrefix(path, "/static/")
		if hasRfs {
			if f, err := rfs.ReadFile(strippedPath); err == nil && f != nil {
				// Rewrite URL to serve from staticFS root (which is already "static")
				r.URL.Path = "/" + strippedPath
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		// Not a static file — serve index.html (SPA catch-all)
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scans/", s.handleGetScan)
	mux.HandleFunc("/api/upload-targets", s.handleUploadTargets)
	mux.HandleFunc("/api/upload-instructions", s.handleUploadInstructions)
	mux.HandleFunc("/api/upload-logo", s.handleUploadLogo)
	// Serve uploaded logos
	logosDir := filepath.Join(s.dataDir, "logos")
	os.MkdirAll(logosDir, 0755)
	mux.Handle("/uploads/logos/", http.StripPrefix("/uploads/logos/", http.FileServer(http.Dir(logosDir))))
	mux.HandleFunc("/api/report/", s.handleDownloadReport)
	mux.HandleFunc("/api/settings/rate-limit", s.handleRateLimit)
	mux.HandleFunc("/api/settings/agentmail", s.handleAgentMailSettings)
	mux.HandleFunc("/api/queue/status", s.handleQueueStatus)
	mux.HandleFunc("/api/queue/resume", s.handleQueueResume)
	mux.HandleFunc("/api/queue/clear", s.handleQueueClear)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/stop-notify", s.handleStopNotify)
	mux.HandleFunc("/api/instances", s.handleInstances)
	mux.HandleFunc("/api/instances/", s.handleInstanceAction)

	mux.HandleFunc("/api/chat", s.handleChat)

	// Auth routes (these are public — authMiddleware skips them)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)

	// Wrap with auth middleware (outermost) then rate limiting
	authMw := authMiddleware(s.cfg)
	rlMiddleware := rateLimitMiddleware(s.rateLimiter)

	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	log.Printf("Xalgorix Web UI → http://localhost:%d", s.port)
	log.Printf("Scan data → %s", s.dataDir)
	log.Printf("Rate limiting: %d requests/%ds per IP", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	if s.cfg.Username != "" && s.cfg.Password != "" {
		log.Printf("🔒 Authentication enabled (user: %s)", s.cfg.Username)
	} else {
		log.Printf("⚠️  Authentication disabled — set XALGORIX_USERNAME and XALGORIX_PASSWORD in ~/.xalgorix.env")
	}

	// ── Auto-resume interrupted scan queue after short startup delay ──
	go func() {
		time.Sleep(5 * time.Second) // let HTTP server fully initialize
		state, _ := s.validQueueState(true)
		if state == nil {
			return
		}
		remaining := state.Targets[state.CurrentIdx:]
		log.Printf("[AUTO-RESUME] Resuming interrupted scan queue: %d targets from index %d", len(remaining), state.CurrentIdx)
		req := ScanRequest{
			Targets:     remaining,
			Instruction: state.Instruction,
			ScanMode:    state.ScanMode,
			IsResume:    true,
		}
		scanCfg := *s.cfg
		s.runMultiScan(req, &scanCfg)
	}()

	// ── Graceful shutdown on SIGTERM/SIGINT ──
	httpServer := &http.Server{
		Addr:    addr,
		Handler: authMw(rlMiddleware(mux)),
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Printf("[SHUTDOWN] Received signal %s — saving state and shutting down gracefully", sig)

		// Stop all running scans so they save queue state
		s.stopReq.Store(true)
		s.mu.Lock()
		if s.cancelScan != nil {
			s.cancelScan()
		}
		for _, agnt := range s.currentAgents {
			if agnt != nil {
				agnt.Stop()
			}
		}
		s.mu.Unlock()

		// Stop all instances
		s.instancesMu.RLock()
		for _, inst := range s.instances {
			inst.mu.Lock()
			if inst.Status == "running" {
				inst.Status = "stopped"
				inst.StopReason = "signal_" + sig.String()
				inst.FinishedAt = time.Now().Format(time.RFC3339)
				if inst.agent != nil {
					inst.agent.Stop()
				}
			}
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()

		terminal.KillAllProcesses()

		// Send Discord notification. Use sig.String() explicitly so we get
		// "terminated"/"interrupt" rather than a numeric fallback for any
		// os.Signal implementation that doesn't satisfy fmt.Stringer.
		if s.discordWebhook != "" {
			s.sendDiscord(0xff6b6b, "🔄 Xalgorix Restarting", fmt.Sprintf("Service received %s signal. Saving state and restarting.\nInterrupted scans will auto-resume.", sig.String()))
		}

		// Give scans a moment to save their queue state
		time.Sleep(2 * time.Second)

		// Graceful HTTP shutdown (5s deadline for in-flight requests)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("[SHUTDOWN] HTTP shutdown error: %v", err)
		}

		s.rateLimiter.Stop()
		log.Printf("[SHUTDOWN] Graceful shutdown complete")
	}()

	err = httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil // graceful shutdown
	}
	return err
}

// initDataDir creates the data directory and cleans up old scans (>30 days).
func (s *Server) initDataDir() {
	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		log.Printf("Error: failed to create data directory %s: %v", s.dataDir, err)
	}

	// Cleanup scans older than 30 days
	entries, _ := os.ReadDir(s.dataDir)
	cutoff := time.Now().AddDate(0, 0, -30)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.RemoveAll(filepath.Join(s.dataDir, e.Name()))
			log.Printf("Cleaned up old scan: %s", e.Name())
		}
	}

	// Check for interrupted queue — will auto-resume after server starts
	if state, _ := s.validQueueState(true); state != nil {
		log.Printf("Found interrupted scan queue: %d targets remaining from index %d (will auto-resume in 5s)",
			len(state.Targets)-state.CurrentIdx, state.CurrentIdx)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Enforce max client limit
	s.mu.RLock()
	numClients := len(s.clients)
	s.mu.RUnlock()
	if numClients >= wsMaxClients {
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	client := &wsClient{
		conn:   conn,
		send:   make(chan []byte, wsSendBufSize),
		server: s,
	}

	s.mu.Lock()
	s.clients[client] = true
	s.mu.Unlock()

	// Start write pump in a goroutine
	go client.writePump()
	// Read pump runs in this goroutine (blocks until disconnect)
	client.readPump()
}

// removeClient safely removes a client from the server's client set.
func (s *Server) removeClient(c *wsClient) {
	s.mu.Lock()
	if _, ok := s.clients[c]; ok {
		delete(s.clients, c)
		close(c.send)
	}
	s.mu.Unlock()
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "targets required", http.StatusBadRequest)
		return
	}

	// Apply LLM provider settings from web UI securely using a copy
	scanCfg := *s.cfg // shallow copy
	if req.Model != "" {
		scanCfg.LLM = req.Model
	}
	if req.APIKey != "" {
		scanCfg.APIKey = req.APIKey
	}
	if req.APIBase != "" {
		scanCfg.APIBase = req.APIBase
	}

	// Save-only mode: create a persistent scan config without starting execution
	if req.SaveOnly {
		instanceID := randomSlug()
		inst := &ScanInstance{
			ID:             instanceID,
			Name:           req.Name,
			Targets:        strings.Join(req.Targets, ", "),
			Status:         "saved",
			StartedAt:      time.Now().Format(time.RFC3339Nano),
			ScanMode:       req.ScanMode,
			Instruction:    req.Instruction,
			SeverityFilter: req.SeverityFilter,
			Phases:         req.Phases,
			CompanyName:    req.CompanyName,
			LogoPath:       req.LogoPath,
			DiscordWebhook: req.DiscordWebhook,
		}
		s.instancesMu.Lock()
		s.instances[instanceID] = inst
		s.instancesMu.Unlock()
		s.broadcastDashboard(WSEvent{
			Type:    "instance_started",
			Content: instanceID,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "saved", "instance_id": instanceID})
		return
	}

	// Clear global stop flag so the new scan isn't immediately aborted
	// (fixes starvation bug where scans stay "pending" after Stop All)
	s.stopReq.Store(false)

	instanceID := randomSlug()
	req.Name = strings.TrimSpace(req.Name) // propagate name to running scans too
	go s.runMultiScan(req, &scanCfg, instanceID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": instanceID})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq.Store(true)

	// Cancel the current scan session context (interrupts LLM calls, tool execution)
	s.mu.Lock()
	cancel := s.cancelScan
	// Stop all tracked agents (safe for multi-instance)
	var agents []*agent.Agent
	for _, a := range s.currentAgents {
		agents = append(agents, a)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, agnt := range agents {
		if agnt != nil {
			agnt.Stop()
		}
	}

	// Stop ALL running instances (use write lock since we're modifying instance state)
	s.instancesMu.Lock()
	for _, inst := range s.instances {
		inst.mu.Lock()
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()
	}
	s.instancesMu.Unlock()

	// Kill all spawned processes as a safety net
	terminal.KillAllProcesses()

	s.broadcast(WSEvent{Type: "stopped", Content: "All instances stopped by user"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	scanID := s.currentScanID
	s.mu.RUnlock()

	// Count running instances
	s.instancesMu.RLock()
	runningCount := 0
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.Status == "running" {
			runningCount++
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Aggregate vulns across all active instances via their per-session context
	totalVulns := 0
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.RLock()
		if inst.sctx != nil {
			totalVulns += len(reporting.GetVulnerabilitiesForContext(inst.sctx.ID))
		}
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]any{
		"running":           s.running.Load() || runningCount > 0,
		"scan_id":           scanID,
		"vulns":             totalVulns,
		"running_instances": runningCount,
	})
}

// handleInstances returns all scan instances (running + recent)
func (s *Server) handleInstances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.instancesMu.RLock()
	instances := make([]*ScanInstance, 0, len(s.instances))
	for _, inst := range s.instances {
		inst.mu.RLock()
		instances = append(instances, &ScanInstance{
			ID:          inst.ID,
			Name:        inst.Name,
			Targets:     inst.Targets,
			Status:      inst.Status,
			StartedAt:   inst.StartedAt,
			FinishedAt:  inst.FinishedAt,
			Iterations:  inst.Iterations,
			ToolCalls:   inst.ToolCalls,
			VulnCount:   inst.VulnCount,
			TotalTokens: inst.TotalTokens,
			ScanMode:    inst.ScanMode,
			Phases:      inst.Phases,
			CompanyName: inst.CompanyName,
			LogoPath:    inst.LogoPath,
		})
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()

	// Sort: running first, then by start time descending
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Status == "running" && instances[j].Status != "running" {
			return true
		}
		if instances[i].Status != "running" && instances[j].Status == "running" {
			return false
		}
		return instances[i].StartedAt > instances[j].StartedAt
	})

	// Include resource stats so the UI can explain why scans are pending
	stats := resources.GetStats()
	level, _ := resources.CurrentLevel()
	effectiveMax, reason := resources.EffectiveMaxInstances()
	response := map[string]any{
		"instances": instances,
		"resources": map[string]any{
			"cpu_cores":               stats.CPUCores,
			"cpu_load_1m":             stats.LoadAvg1m,
			"ram_total_mb":            stats.MemTotalMB,
			"ram_available_mb":        stats.MemAvailableMB,
			"disk_free_mb":            stats.DiskFreeMB,
			"level":                   level.String(),
			"reason":                  reason,
			"max_instances":           effectiveMax,
			"manual_max_instances":    resources.MaxInstances(),
			"effective_max_instances": effectiveMax,
		},
	}
	json.NewEncoder(w).Encode(response)
}

// handleInstanceAction handles per-instance operations (stop, etc)
func (s *Server) handleInstanceAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// Path: /api/instances/{id}/stop or /api/instances/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/instances/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "instance ID required", http.StatusBadRequest)
		return
	}
	instanceID := parts[0]

	s.instancesMu.RLock()
	inst, ok := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if !ok {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}

	// GET /api/instances/{id} — return instance details
	if r.Method == http.MethodGet && (len(parts) == 1 || parts[1] == "") {
		inst.mu.RLock()
		json.NewEncoder(w).Encode(inst)
		inst.mu.RUnlock()
		return
	}

	// POST /api/instances/{id}/stop — stop specific instance
	if len(parts) >= 2 && parts[1] == "stop" && r.Method == http.MethodPost {
		inst.mu.Lock()
		// BUG FIX: Also handle "pending" instances, not just "running".
		// Without this, queued scans cannot be stopped from the UI.
		if inst.Status == "running" || inst.Status == "pending" || inst.Status == "paused" {
			inst.Status = "stopped"
			inst.StopReason = "user_stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339Nano)
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()

		// Broadcast stop to clients watching this instance
		s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Instance stopped by user"})
		// Broadcast update to dashboard clients
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

		json.NewEncoder(w).Encode(map[string]string{"status": "stopped", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/restart — restart scan with same config
	if len(parts) >= 2 && parts[1] == "restart" && r.Method == http.MethodPost {
		// BUG FIX: Validate that the instance is NOT still active before restarting.
		// Without this guard, restarting a running/pending instance creates a
		// duplicate scan, doubling resource usage against the same targets.
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus == "running" || currentStatus == "pending" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot restart: instance is still " + currentStatus,
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		instruction := inst.Instruction
		scanMode := inst.ScanMode
		severityFilter := inst.SeverityFilter
		discordWebhook := inst.DiscordWebhook
		phases := inst.Phases
		companyName := inst.CompanyName
		logoPath := inst.LogoPath
		instName := inst.Name
		inst.mu.RUnlock()

		// Clear global stop flag so the restarted scan isn't immediately aborted
		// by the queue wait loop checking stopReq.
		s.stopReq.Store(false)

		// Build a new ScanRequest from stored config
		req := ScanRequest{
			Targets:        targets,
			Instruction:    instruction,
			ScanMode:       scanMode,
			SeverityFilter: severityFilter,
			DiscordWebhook: discordWebhook,
			Name:           instName,
			Phases:         phases,
			CompanyName:    companyName,
			LogoPath:       logoPath,
		}

		scanCfg := *s.cfg // shallow copy
		go s.runMultiScan(req, &scanCfg)

		json.NewEncoder(w).Encode(map[string]string{"status": "restarted"})
		return
	}

	// POST /api/instances/{id}/start — start a saved scan
	if len(parts) >= 2 && parts[1] == "start" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus != "saved" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot start: instance is " + currentStatus + ", expected saved",
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		req := ScanRequest{
			Targets:        targets,
			Instruction:    inst.Instruction,
			ScanMode:       inst.ScanMode,
			SeverityFilter: inst.SeverityFilter,
			DiscordWebhook: inst.DiscordWebhook,
			Name:           inst.Name,
			Phases:         inst.Phases,
			CompanyName:    inst.CompanyName,
			LogoPath:       inst.LogoPath,
		}
		inst.mu.RUnlock()

		// Remove the saved instance — runMultiScan creates a new pending one
		s.instancesMu.Lock()
		delete(s.instances, instanceID)
		s.instancesMu.Unlock()

		s.stopReq.Store(false)
		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": newID})
		return
	}

	// POST /api/instances/{id}/pause — gracefully pause a running scan
	if len(parts) >= 2 && parts[1] == "pause" && r.Method == http.MethodPost {
		inst.mu.Lock()
		if inst.Status != "running" {
			inst.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot pause: instance is " + inst.Status,
			})
			return
		}
		inst.Status = "paused"
		inst.StopReason = "user_paused"
		if inst.cancel != nil {
			inst.cancel()
		}
		if inst.agent != nil {
			inst.agent.Stop()
		}
		inst.mu.Unlock()

		s.broadcastToInstance(instanceID, WSEvent{Type: "paused", Content: "Scan paused by user"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		json.NewEncoder(w).Encode(map[string]string{"status": "paused", "instance_id": instanceID})
		return
	}

	// POST /api/instances/{id}/resume — resume a paused scan
	if len(parts) >= 2 && parts[1] == "resume" && r.Method == http.MethodPost {
		inst.mu.RLock()
		currentStatus := inst.Status
		inst.mu.RUnlock()
		if currentStatus != "paused" {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "cannot resume: instance is " + currentStatus + ", expected paused",
			})
			return
		}

		inst.mu.RLock()
		targets := strings.Split(inst.Targets, ", ")
		req := ScanRequest{
			Targets:        targets,
			Instruction:    inst.Instruction,
			ScanMode:       inst.ScanMode,
			SeverityFilter: inst.SeverityFilter,
			DiscordWebhook: inst.DiscordWebhook,
			Name:           inst.Name,
			Phases:         inst.Phases,
			CompanyName:    inst.CompanyName,
			LogoPath:       inst.LogoPath,
			IsResume:       true, // preserve existing state (vulns, notes, recon)
		}
		inst.mu.RUnlock()

		// Remove the paused instance — a new one will be created by runMultiScan
		s.instancesMu.Lock()
		delete(s.instances, instanceID)
		s.instancesMu.Unlock()

		s.stopReq.Store(false)
		scanCfg := *s.cfg
		newID := randomSlug()
		go s.runMultiScan(req, &scanCfg, newID)

		s.broadcastToInstance(instanceID, WSEvent{Type: "resumed", Content: "Scan resumed"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		json.NewEncoder(w).Encode(map[string]string{"status": "resumed", "instance_id": newID})
		return
	}

	// GET /api/instances/{id}/events — return buffered event history
	if len(parts) >= 2 && parts[1] == "events" && r.Method == http.MethodGet {
		inst.mu.RLock()
		events := make([]WSEvent, len(inst.events))
		copy(events, inst.events)
		inst.mu.RUnlock()
		json.NewEncoder(w).Encode(events)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

// ────────────────────────────────────────────────────────
// scanSession — self-contained unit for a single scan run
// ────────────────────────────────────────────────────────

// scanSession isolates all per-scan state. Crashes in one session
// cannot corrupt server-level state or leak into subsequent scans.
type scanSession struct {
	id             string
	target         string
	parentTarget   string // parent domain for subdomain scans (wildcard mode)
	scanDir        string
	cfg            *config.Config
	agent          *agent.Agent
	events         chan agent.Event
	record         *ScanRecord
	server         *Server
	instruction    string
	severityFilter []string
	discoveryMode  bool
	genReport      bool
	resetState     bool
	instanceID     string               // parent instance ID for multi-instance tracking
	scanMode       string               // single, wildcard, dast — persisted so dashboard shows correct mode
	sctx           *scanctx.ScanContext // per-session isolated state
	companyName    string               // report branding: company name
	logoPath       string               // report branding: logo path
	phases         []int                // selected methodology phases

	// Wildcard lifecycle flags
	skipNotesCleanup     bool   // when true, don't delete notes store on cleanup (discovery phase)
	parentReportingCtxID string // stable context ID for accumulating vulns across wildcard subdomain scans
}

// cleanup tears down all per-session resources. Every sub-operation
// has its own panic guard so cleanup NEVER panics upward.
func (sess *scanSession) cleanup() {
	// Deactivate and close the per-session ScanContext (if set).
	// Close() calls Terminal.KillAll() and Browser.Close() internally,
	// so no redundant calls are needed below.
	if sess.sctx != nil {
		func() {
			defer logRecover("cleanup.scanctx.close")
			scanctx.Deactivate(sess.sctx.ID)
			sess.sctx.Close()
		}()
	}

	// Clean up tool-level context stores to prevent unbounded memory growth.
	// Each tool package maintains a map[contextID]→store that must be cleared.
	if sess.sctx != nil {
		// Wildcard vuln accumulation: merge this session's vulns into the parent
		// reporting context BEFORE we delete this session's reporting store.
		if sess.parentReportingCtxID != "" {
			func() {
				defer logRecover("cleanup.reporting.merge")
				merged := reporting.MergeVulnsToContext(sess.sctx.ID, sess.parentReportingCtxID)
				if merged > 0 {
					log.Printf("[wildcard] Merged %d vulns from session %s into parent context %s", merged, sess.sctx.ID, sess.parentReportingCtxID)
				}
			}()
		}

		func() {
			defer logRecover("cleanup.reporting.cleanup")
			reporting.CleanupContext(sess.sctx.ID)
		}()
		if !sess.skipNotesCleanup {
			func() {
				defer logRecover("cleanup.notes.cleanup")
				notes.CleanupContext(sess.sctx.ID)
			}()
		} else {
			log.Printf("[wildcard] Skipping notes cleanup for discovery session %s (notes preserved for subdomain collection)", sess.sctx.ID)
		}
		func() {
			defer logRecover("cleanup.terminal.cleanup")
			terminal.CleanupContext(sess.sctx.ID)
		}()
		func() {
			defer logRecover("cleanup.browser.cleanup")
			browser.CleanupContext(sess.sctx.ID)
		}()
	}

	// Fallback process kill if sctx was never initialized
	if sess.sctx == nil {
		func() {
			defer logRecover("cleanup.terminal.killAll")
			terminal.KillAllProcesses()
		}()
	}

	// Stop agent if still running
	if sess.agent != nil {
		func() {
			defer logRecover("cleanup.agent.stop")
			sess.agent.Stop()
		}()
	}

	// Clear sub-agent state to prevent memory/goroutine leaks across scans.
	// Only safe when this is the sole running scan — global reset would corrupt
	// concurrent sessions.
	sess.server.instancesMu.RLock()
	runningCount := 0
	for _, inst := range sess.server.instances {
		// BUG FIX: Must hold inst.mu.RLock() when reading inst.Status
		// to avoid data race with goroutines mutating it under inst.mu.Lock().
		inst.mu.RLock()
		if inst.Status == "running" {
			runningCount++
		}
		inst.mu.RUnlock()
	}
	sess.server.instancesMu.RUnlock()
	if runningCount <= 1 {
		func() {
			defer logRecover("cleanup.agentsgraph.reset")
			agentsgraph.Reset()
		}()
	}

	// Clear terminal working directory to prevent stale workdir leaking to next session
	func() {
		defer logRecover("cleanup.terminal.setWorkDir")
		if sess.sctx != nil && sess.sctx.Terminal != nil {
			sess.sctx.Terminal.SetWorkDir("")
		} else {
			terminal.SetWorkDir("") // fallback if sctx not initialized
		}
	}()

	// Clear server references under lock
	sess.server.mu.Lock()
	delete(sess.server.currentAgents, sess.id)
	sess.server.mu.Unlock()
}

// executeScanSession runs a single scan in complete isolation.
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeScanSession(sess *scanSession) {
	// IRONCLAD: This function NEVER panics upward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] scanSession %s panicked: %v\n%s", sess.id, r, debug.Stack())
			if sess.instanceID != "" {
				s.broadcastToInstance(sess.instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			} else {
				s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
			}
		}
		// ALWAYS clean up, whether normal exit or panic
		sess.cleanup()
	}()

	// 0. Create and activate a per-session ScanContext for isolation.
	//    This must happen BEFORE any tool state is touched.
	sctx := scanctx.New(sess.id, sess.scanDir)
	scanctx.Activate(sctx)
	sess.sctx = sctx
	log.Printf("[scanctx] Activated context %s for target %s (dir=%s)", sctx.ID, sess.target, sess.scanDir)

	// Propagate ScanContext to parent instance (if multi-instance mode)
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.sctx = sctx
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 1. Reset per-context state if requested (context-aware)
	if sess.resetState {
		func() {
			defer logRecover("session.resetContextState")
			reporting.ResetVulnerabilitiesForContext(sctx.ID)
			notes.ResetNotesForContext(sctx.ID)
		}()
	}

	// 1b. Configure notes disk persistence → saves notes.json in scan directory
	notes.SetPersistPathForContext(sctx.ID, sess.scanDir)
	if !sess.resetState {
		// Resume scenario: load previously saved notes from disk
		notes.LoadFromDiskForContext(sctx.ID)
	}

	// 2. Set working directory (context-aware)
	sctx.Terminal.SetWorkDir(sess.scanDir)
	sctx.Browser.SetSessionPath(sess.scanDir)

	// 3. Create agent with session's config AND ScanContext
	events := make(chan agent.Event, 512)
	sess.events = events
	agnt := agent.NewAgent(sess.cfg, "XalgorixAgent", events, sctx)
	if sess.discoveryMode {
		agnt.SetDiscoveryMode(true)
	}
	sess.agent = agnt

	// Store agent ref on server for handleStop/handleChat (under lock)
	s.mu.Lock()
	s.currentScanDir = sess.scanDir
	s.currentScanID = sess.id
	s.currentAgents[sess.id] = agnt
	s.mu.Unlock()

	// Register agent with parent instance if applicable
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.agent = agnt
			inst.scanDir = sess.scanDir
			inst.lastSessionTokens = 0 // reset token delta for this new session/phase
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 4. Initialize scan record
	sess.record = &ScanRecord{
		ID:           sess.id,
		Target:       sess.target,
		ParentTarget: sess.parentTarget,
		ScanMode:     sess.scanMode,
		StartedAt:    time.Now().Format(time.RFC3339),
		Status:       "running",
		Events:       []WSEvent{},
		Vulns:        []VulnSummary{},
		CompanyName:  sess.companyName,
		LogoPath:     sess.logoPath,
		Phases:       sess.phases,
	}
	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 5. Event processing goroutine — drains events and broadcasts to WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Event processor panicked: %v — continuing\n%s", r, debug.Stack())
			}
		}() // never let panic escape event processor
		for evt := range events {
			s.processEvent(evt, sess)
		}
	}()

	// 6. Build instruction with severity filter
	instruction := sess.instruction
	if len(sess.severityFilter) > 0 {
		instruction = buildSeverityPrefix(sess.severityFilter) + "\n\n" + instruction
	}

	// 7. Run agent (blocks until finished or stopped)
	agnt.Run([]string{sess.target}, instruction)

	// 8. Close events channel and wait for event processor to drain
	close(events)
	<-done

	// 9. Finalize record
	sess.record.Status = "finished"
	sess.record.FinishedAt = time.Now().Format(time.RFC3339)

	// Refresh vulns from reporting module
	sess.record.Vulns = nil
	for _, v := range reporting.GetVulnerabilitiesForContext(sess.sctx.ID) {
		sess.record.Vulns = append(sess.record.Vulns, vulnToSummary(v))
	}

	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 10. Generate report if requested
	if sess.genReport && len(sess.record.Vulns) > 0 {
		if p, err := s.generateReportAt(sess.record, sess.scanDir); err == nil {
			log.Printf("PDF report saved: %s", p)
			desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s",
				sess.target, len(sess.record.Vulns), time.Now().Format("15:04:05 MST"))
			s.sendDiscordWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
			if sess.instanceID != "" {
				s.broadcastToInstance(sess.instanceID, WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
			} else {
				s.broadcast(WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
			}
		} else {
			log.Printf("Failed to generate PDF report: %v", err)
		}
	}
}

// processEvent handles a single agent event — forwards to WebSocket, updates scan record, sends Discord.
func (s *Server) processEvent(evt agent.Event, sess *scanSession) {
	wsEvt := WSEvent{
		Type:        evt.Type,
		Content:     evt.Content,
		ToolName:    evt.ToolName,
		ToolArgs:    evt.ToolArgs,
		AgentID:     evt.AgentID,
		Timestamp:   evt.Timestamp.Format(time.RFC3339),
		TotalTokens: evt.TotalTokens,
	}

	if evt.Type == "tool_result" {
		wsEvt.Output = evt.ToolResult.Output
		wsEvt.Error = evt.ToolResult.Error

		// Push vuln to UI in real-time when report_vulnerability succeeds
		if evt.ToolName == "report_vulnerability" && evt.ToolResult.Error == "" {
			vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
			log.Printf("[VULN] report_vulnerability tool succeeded, vulns in list: %d", len(vulns))
			if len(vulns) > 0 {
				latest := vulns[len(vulns)-1]
				vs := vulnToSummary(latest)
				log.Printf("[VULN] Latest vuln: %s %s (CVSS %.1f)", vs.Severity, vs.Title, vs.CVSS)

				// Severity filter enforcement strictly at the UI layer
				allowed := true
				if len(sess.severityFilter) > 0 {
					allowed = false
					for _, sev := range sess.severityFilter {
						if strings.EqualFold(sev, vs.Severity) {
							allowed = true
							break
						}
					}
					log.Printf("[VULN] Severity filter active: filter=%v, allowed=%v", sess.severityFilter, allowed)
				}

				if allowed {
					wsEvt.Vulns = []VulnSummary{vs}
					sess.record.Vulns = append(sess.record.Vulns, vs)
					log.Printf("[VULN] Vuln broadcast real-time: %s %s", vs.Severity, vs.Title)

					// Discord: vulnerability found (respects XALGORIX_DISCORD_MIN_SEVERITY)
					sevColor := 0xef4444 // red for critical/high
					switch vs.Severity {
					case "medium":
						sevColor = 0xd97706
					case "low", "info":
						sevColor = 0x3b82f6
					}
					var details strings.Builder
					details.WriteString(fmt.Sprintf("**%s**\n\n", vs.Title))
					if vs.Description != "" {
						details.WriteString(fmt.Sprintf("📝 **Description:**\n%s\n\n", vs.Description))
					}
					if vs.Endpoint != "" {
						details.WriteString(fmt.Sprintf("🔗 **Endpoint:** `%s`\n", vs.Endpoint))
					}
					if vs.Method != "" {
						details.WriteString(fmt.Sprintf("📡 **Method:** `%s`\n", vs.Method))
					}
					if vs.CVE != "" {
						details.WriteString(fmt.Sprintf("🏷️ **CVE:** `%s`\n", vs.CVE))
					}
					details.WriteString(fmt.Sprintf("📊 **CVSS:** `%.1f` | **Severity:** `%s`\n\n", vs.CVSS, strings.ToUpper(vs.Severity)))
					if vs.Impact != "" {
						details.WriteString(fmt.Sprintf("💥 **Impact:**\n%s\n\n", vs.Impact))
					}
					if vs.TechnicalAnalysis != "" {
						details.WriteString(fmt.Sprintf("🔬 **Technical Analysis:**\n%s\n\n", vs.TechnicalAnalysis))
					}
					if vs.PoCDescription != "" {
						details.WriteString(fmt.Sprintf("🧪 **PoC:**\n%s\n", vs.PoCDescription))
					}
					if vs.PoCScript != "" {
						poc := vs.PoCScript
						if len(poc) > 800 {
							poc = poc[:800] + "\n... (truncated)"
						}
						details.WriteString(fmt.Sprintf("```\n%s\n```\n\n", poc))
					}
					if vs.Remediation != "" {
						details.WriteString(fmt.Sprintf("🛡️ **Remediation:**\n%s", vs.Remediation))
					}
					// Apply Discord minimum severity filter
					if severityMeetsThreshold(vs.Severity, s.discordMinSeverity) {
						s.sendDiscord(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
					} else {
						log.Printf("[DISCORD] Skipping %s vuln notification (min severity: %s)", vs.Severity, s.discordMinSeverity)
					}
				} else {
					log.Printf("[VULN] Vuln filtered out by severity: %s (filter: %v)", vs.Severity, sess.severityFilter)
				}
			}
		}
	}

	if evt.Type == "finished" {
		// Build set of vulns already broadcast in real-time to avoid duplicates
		seen := make(map[string]bool)
		for _, v := range sess.record.Vulns {
			seen[v.ID] = true
		}
		vulns := reporting.GetVulnerabilitiesForContext(sess.sctx.ID)
		log.Printf("[VULN] Finished event: total vulns in system: %d, already broadcast: %d", len(vulns), len(seen))
		for _, v := range vulns {
			if seen[v.ID] {
				log.Printf("[VULN] Finished: skipping already-broadcast vuln: %s %s", v.ID, v.Title)
				continue
			}
			vs := vulnToSummary(v)
			allowed := true
			if len(sess.severityFilter) > 0 {
				allowed = false
				for _, sev := range sess.severityFilter {
					if strings.EqualFold(sev, vs.Severity) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				wsEvt.Vulns = append(wsEvt.Vulns, vs)
				log.Printf("[VULN] Finished: adding new vuln to final broadcast: %s %s", vs.Severity, vs.Title)
			} else {
				log.Printf("[VULN] Finished: filtered vuln (not added to broadcast): %s (filter: %v)", vs.Severity, sess.severityFilter)
			}
		}
		log.Printf("[VULN] Finished: total vulns in final broadcast: %d", len(wsEvt.Vulns))
	}

	// Track stats on per-session record
	if evt.Type == "thinking" {
		sess.record.Iterations++
	}
	if evt.Type == "tool_call" {
		sess.record.ToolCalls++
	}
	if evt.TotalTokens > 0 {
		sess.record.TotalTokens = evt.TotalTokens
	}

	// Update parent instance stats — ACCUMULATE across sessions (phases/subdomains),
	// don't overwrite. Each subdomain scan creates a fresh scanSession with zeroed
	// counters, so we increment the instance counters on each event.
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			if evt.Type == "thinking" {
				inst.Iterations++
			}
			if evt.Type == "tool_call" {
				inst.ToolCalls++
			}
			if evt.TotalTokens > 0 {
				// Tokens are cumulative within a session but reset between sessions,
				// so we track the delta
				inst.TotalTokens += evt.TotalTokens - inst.lastSessionTokens
				inst.lastSessionTokens = evt.TotalTokens
			}
			// Vulns: use parent reporting context in wildcard mode,
			// otherwise use session-specific context
			if sess.parentReportingCtxID != "" {
				inst.VulnCount = len(reporting.GetVulnerabilitiesForContext(sess.parentReportingCtxID))
			} else {
				inst.VulnCount = len(reporting.GetVulnerabilitiesForContext(sess.sctx.ID))
			}
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// Accumulate events for persistence (limit stored output size)
	savedEvt := wsEvt
	if len(savedEvt.Output) > 500 {
		savedEvt.Output = savedEvt.Output[:500] + "..."
	}
	sess.record.Events = append(sess.record.Events, savedEvt)

	// Periodically save scan record (every 10 events)
	if len(sess.record.Events)%10 == 0 {
		s.saveScanRecordTo(sess.record, sess.scanDir)
	}

	// Use instance-scoped broadcasting
	log.Printf("[VULN] Broadcasting: type=%s, instanceID=%s, vulns=%d", evt.Type, sess.instanceID, len(wsEvt.Vulns))
	if sess.instanceID != "" {
		s.broadcastToInstance(sess.instanceID, wsEvt)
	} else {
		s.broadcast(wsEvt)
	}
}

// buildSeverityPrefix creates the severity filter instruction prefix.
func buildSeverityPrefix(severityFilter []string) string {
	severityText := "CRITICAL INSTRUCTION: You MUST ONLY look for and report "
	severities := make([]string, len(severityFilter))
	copy(severities, severityFilter)
	severityText += strings.Join(severities, " and ") + " severity vulnerabilities. "
	severityText += "DO NOT report, investigate, or mention any LOW severity, INFORMATIONAL, or INFO findings. "
	severityText += "Ignore any potential LOW/INFO issues - they are out of scope for this engagement. "
	severityText += "Focus ONLY on: " + strings.Join(severities, ", ") + "."
	return severityText
}

// ────────────────────────────────────────────────────────
// runMultiScan — orchestrates scanning across all targets
// ────────────────────────────────────────────────────────

// runMultiScan processes targets sequentially, one at a time.
// Each target is scanned in a fully isolated scanSession.
func (s *Server) runMultiScan(req ScanRequest, scanCfg *config.Config, instanceIDs ...string) {
	// Defensively flatten req.Targets in case the frontend or API sent them as a comma-separated mega string
	var cleanTargets []string
	for _, raw := range req.Targets {
		fields := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
		})
		for _, f := range fields {
			if f != "" {
				cleanTargets = append(cleanTargets, f)
			}
		}
	}

	// Filter out local/internal targets to prevent self-scanning
	var safeTargets []string
	for _, t := range cleanTargets {
		if isBlockedTarget(t) {
			log.Printf("[BLOCKLIST] Skipping blocked target: %s (local/internal IP)", t)
		} else {
			safeTargets = append(safeTargets, t)
		}
	}
	if len(safeTargets) < len(cleanTargets) {
		log.Printf("[BLOCKLIST] Filtered %d blocked targets, %d remaining", len(cleanTargets)-len(safeTargets), len(safeTargets))
	}
	req.Targets = safeTargets

	// Create instance ID immediately
	var instanceID string
	if len(instanceIDs) > 0 && instanceIDs[0] != "" {
		instanceID = instanceIDs[0]
	} else {
		instanceID = randomSlug()
	}

	// Register instance as pending initially
	instance := &ScanInstance{
		ID:             instanceID,
		Name:           req.Name,
		Targets:        strings.Join(req.Targets, ", "),
		Status:         "pending",
		StartedAt:      time.Now().Format(time.RFC3339Nano),
		ScanMode:       req.ScanMode,
		Instruction:    req.Instruction,
		SeverityFilter: req.SeverityFilter,
		Phases:         req.Phases,
		CompanyName:    req.CompanyName,
		LogoPath:       req.LogoPath,
		DiscordWebhook: req.DiscordWebhook,
	}
	s.instancesMu.Lock()
	s.instances[instanceID] = instance
	s.instancesMu.Unlock()

	// Broadcast to dashboard
	s.broadcastDashboard(WSEvent{Type: "instance_started", Content: instanceID})

	// BUG 1 FIX (CRITICAL): The defer cleanup MUST be registered BEFORE the queue
	// wait loop. Previously, early returns from the loop (stopped-while-pending)
	// bypassed cleanup entirely, leaking the instance in s.instances forever and
	// leaving stale state in currentAgents, s.running, etc.
	//
	// The `ranScan` flag distinguishes between:
	//   false → instance was stopped while pending (lightweight cleanup only)
	//   true  → instance ran and needs full post-scan cleanup
	ranScan := false
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] runMultiScan goroutine panicked: %v\n%s", r, debug.Stack())
			s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan goroutine crashed: %v — cleaning up", r)})
		}

		// Mark instance as finished (if still running)
		instance.mu.Lock()
		if instance.Status == "running" {
			instance.Status = "finished"
		}
		instance.FinishedAt = time.Now().Format(time.RFC3339)
		instance.mu.Unlock()

		// Full post-scan cleanup only when the scan actually ran.
		// Pending→stopped instances skip queue/agent teardown since
		// they never acquired resources.
		if ranScan {
			// Only clear queue state if scan finished normally (not from signal).
			// Signal-stopped scans preserve queue state so auto-resume works on restart.
			preserveQueue := false
			instance.mu.RLock()
			if strings.HasPrefix(instance.StopReason, "signal_") {
				preserveQueue = true
			}
			instance.mu.RUnlock()
			if !preserveQueue {
				s.clearQueueState()
			} else {
				log.Printf("[SHUTDOWN] Preserving queue state for auto-resume after signal stop")
			}
		}

		// Always clean up server references (safe even if never set)
		s.mu.Lock()
		if s.currentScanID == instanceID {
			s.cancelScan = nil
			delete(s.currentAgents, instanceID)
		}
		s.mu.Unlock()

		s.broadcastToInstance(instanceID, WSEvent{Type: "queue_finished", Content: "Scan queue ended"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		time.Sleep(500 * time.Millisecond)

		// Only set running=false if no other instances are running
		s.instancesMu.RLock()
		stillRunning := false
		for _, inst := range s.instances {
			inst.mu.RLock()
			isRunning := inst.Status == "running" && inst.ID != instanceID
			inst.mu.RUnlock()
			if isRunning {
				stillRunning = true
				break
			}
		}
		s.instancesMu.RUnlock()
		if !stillRunning {
			s.running.Store(false)
		}
		log.Printf("[INFO] runMultiScan instance %s exited (ranScan=%v)", instanceID, ranScan)
	}()

	// Wait in queue until slot is available.
	// CRITICAL: The slot check + status transition MUST be atomic under a single
	// Lock to prevent a TOCTOU race where two goroutines both see runningCount=0
	// and start simultaneously, causing mutual process kills.
	for {
		// Check if THIS instance was stopped (via per-instance stop API)
		instance.mu.RLock()
		stopped := instance.Status == "stopped"
		instance.mu.RUnlock()
		if stopped {
			// Early return — defer is already registered and will clean up
			return
		}

		// Also check global stop (user clicked "stop all")
		if s.stopReq.Load() {
			instance.mu.Lock()
			if instance.Status == "pending" {
				instance.Status = "stopped"
				instance.StopReason = "user_stopped"
				instance.FinishedAt = time.Now().Format(time.RFC3339)
			}
			instance.mu.Unlock()
			// Early return — defer is already registered and will clean up
			return
		}

		// ATOMIC: Check resource availability AND transition to running under a single lock.
		// This eliminates the TOCTOU race window between resource check and status update.
		gotSlot := false
		s.instancesMu.Lock()
		runningCount := 0
		for _, inst := range s.instances {
			inst.mu.RLock()
			if inst.Status == "running" {
				runningCount++
			}
			inst.mu.RUnlock()
		}
		canAdmit, reason := resources.CanAdmitScan(runningCount)
		if canAdmit && instance.Status == "pending" {
			instance.Status = "running"
			instance.StartedAt = time.Now().Format(time.RFC3339)
			gotSlot = true
			log.Printf("[ADMIT] Scan %s started (running: %d) — %s", instanceID, runningCount+1, reason)
		}
		s.instancesMu.Unlock()

		if gotSlot {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Instance got a slot — mark that the scan ran for full cleanup
	ranScan = true

	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

	// ── PRE-SESSION CLEANUP ──
	// IMPORTANT: This runs AFTER the queue wait, so we only clean up global
	// state once this instance has acquired a slot. This prevents a queued
	// scan from destroying a running scan's processes and state.
	s.clearQueueState()
	s.running.Store(true)
	s.stopReq.Store(false)      // clear global stop so this scan isn't immediately aborted
	req.InstanceID = instanceID // thread instance ID to all target handlers
	if req.DiscordWebhook != "" {
		s.discordWebhook = req.DiscordWebhook
	}

	if req.IsResume {
		log.Printf("[AUTO-RESUME] Skipping state reset — preserving vulns, notes, and recon files from previous session")
		// NOTE: Do NOT call terminal.KillAllProcesses() here — it kills ALL
		// processes globally, which would destroy a running instance's tools.
		// Per-context cleanup handles process termination on session boundaries.
	} else {
		// Fresh scan — only clean per-instance state, NOT global state.
		// Global resets (reporting.ResetVulnerabilities, notes.ResetNotes,
		// terminal.KillAllProcesses) would destroy another queued instance's
		// methodology workflow. Per-context resets happen in executeScanSession.
		func() {
			defer logRecover("multiScan.cleanTmpSubdomainFiles")
			cleanTmpSubdomainFiles()
		}()
	}
	totalTargets := len(req.Targets)

	// Save queue state for persistence
	s.saveQueueState(req.Targets, 0, req.Instruction, req.ScanMode)

	s.broadcastToInstance(instanceID, WSEvent{
		Type:         "queue_started",
		Content:      fmt.Sprintf("Starting scan queue: %d target(s)", totalTargets),
		TotalTargets: totalTargets,
	})

	// Discord: scan started
	s.sendDiscord(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))

	for i, target := range req.Targets {
		// Check both global stop and per-instance stop
		instance.mu.RLock()
		instStopped := instance.Status == "stopped"
		instance.mu.RUnlock()
		if s.stopReq.Load() || instStopped {
			s.broadcastToInstance(instanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			break
		}

		// Update queue state after each target
		s.saveQueueState(req.Targets, i, req.Instruction, req.ScanMode)

		// No per-target timeout — let scans run indefinitely; user uses stop button
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.cancelScan = cancel
		s.mu.Unlock()

		// Store cancel on the instance so per-instance stop can cancel the scan context
		instance.mu.Lock()
		instance.cancel = cancel
		instance.mu.Unlock()

		switch req.ScanMode {
		case "wildcard":
			// Each target gets full wildcard treatment: Phase 1 subdomain discovery + Phase 2 per-subdomain scan.
			// This applies whether the user provides 1 or 300+ root domains.
			s.runWildcardTarget(ctx, scanCfg, req, target, i, totalTargets)
		case "dast":
			s.runDASTTarget(ctx, scanCfg, req, target, i, totalTargets)
		default:
			s.runSingleTarget(ctx, scanCfg, req, target, i, totalTargets)
		}

		instance.mu.RLock()
		instStoppedAfterTarget := instance.Status == "stopped"
		instance.mu.RUnlock()
		if !s.stopReq.Load() && !instStoppedAfterTarget {
			s.saveQueueState(req.Targets, i+1, req.Instruction, req.ScanMode)
		}

		cancel() // always cancel context after target is done
	}

	// Clear queue state when done
	s.clearQueueState()

	// Discord: scan finished — use instance's accumulated vuln count
	// (don't read from inst.sctx.ID — it may point to a cleaned-up session context)
	vulnCount := 0
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.RLock()
		vulnCount = inst.VulnCount
		inst.mu.RUnlock()
	}
	s.instancesMu.RUnlock()
	if vulnCount > 0 {
		desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, vulnCount, time.Now().Format("15:04:05 MST"))
		s.sendDiscord(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
	} else {
		s.sendDiscord(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
	}

	log.Printf("[INFO] runMultiScan main body complete")
}

// ────────────────────────────────────────────────────────
// Mode-specific target handlers
// ────────────────────────────────────────────────────────

// makeScanDir creates a per-target scan directory with nested structure: target/date/randomslug
func (s *Server) makeScanDir(target string) string {
	dateDir := time.Now().Format("2006-01-02")
	scanDirName := fmt.Sprintf("%s_%s", sanitizeTarget(target), randomSlug())
	scanDir := filepath.Join(s.dataDir, target, dateDir, scanDirName)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create scan directory %s: %v", scanDir, err)
	}
	return scanDir
}

// runSingleTarget handles a single-site mode scan for one target.
func (s *Server) runSingleTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir := s.makeScanDir(target)

	instruction := "This is a SINGLE TARGET scan. Do NOT enumerate subdomains or perform wildcard discovery. Only test the exact target URL provided. Focus on the main domain/IP only. " + req.Instruction

	// Inject phase filter if the user selected specific phases
	instruction += buildPhaseFilterInstruction(req.Phases)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("Scanning target %d/%d: %s", idx+1, total, target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	sess := &scanSession{
		id:             filepath.Base(scanDir),
		target:         target,
		scanDir:        scanDir,
		cfg:            scanCfg,
		server:         s,
		instruction:    buildAutonomousInstruction(target, instruction),
		severityFilter: req.SeverityFilter,
		discoveryMode:  false,
		genReport:      true,
		resetState:     true,
		instanceID:     req.InstanceID,
		scanMode:       "single",
		companyName:    req.CompanyName,
		logoPath:       req.LogoPath,
		phases:         req.Phases,
	}
	s.executeScanSession(sess)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("Target %d/%d completed: %s", idx+1, total, target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runDASTTarget handles a DAST mode scan for one target URL.
func (s *Server) runDASTTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir := s.makeScanDir(target)

	dastInstruction := buildDASTInstruction(target)
	if req.Instruction != "" {
		dastInstruction += "\n\n" + req.Instruction
	}
	dastInstruction += buildPhaseFilterInstruction(req.Phases)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[DAST] Scanning URL: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	sess := &scanSession{
		id:             filepath.Base(scanDir),
		target:         target,
		scanDir:        scanDir,
		cfg:            scanCfg,
		server:         s,
		instruction:    dastInstruction,
		severityFilter: req.SeverityFilter,
		discoveryMode:  false,
		genReport:      true,
		resetState:     true,
		instanceID:     req.InstanceID,
		scanMode:       "dast",
		companyName:    req.CompanyName,
		logoPath:       req.LogoPath,
		phases:         req.Phases,
	}
	s.executeScanSession(sess)

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[DAST] Completed: %s", target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runWildcardTarget handles wildcard mode: Phase 1 subdomain discovery, then Phase 2 per-subdomain scanning.
func (s *Server) runWildcardTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	// ── Stable parent reporting context for vuln accumulation ──
	// All subdomain sessions merge their vulns into this context.
	// It persists across the entire wildcard scan and is cleaned up at the end.
	parentReportingCtxID := fmt.Sprintf("wc-%s-%s", req.InstanceID, sanitizeTarget(target))
	reporting.ResetVulnerabilitiesForContext(parentReportingCtxID) // start clean
	defer func() {
		// Final cleanup of the parent reporting context
		reporting.CleanupContext(parentReportingCtxID)
		log.Printf("[wildcard] Cleaned up parent reporting context: %s", parentReportingCtxID)
	}()

	// ── PHASE 1: Subdomain Discovery ──
	scanDir := s.makeScanDir(target)

	discoveryInstruction := buildDiscoveryInstruction(target)
	if req.Instruction != "" {
		discoveryInstruction += "\n\n" + req.Instruction
	}

	s.broadcastToInstance(req.InstanceID, WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[PHASE 1] Discovering subdomains for: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	// Save the discovery session's context ID so we can read notes after cleanup.
	// skipNotesCleanup=true prevents cleanup() from deleting the notes store,
	// keeping them available for collectSubdomains' Layer 3 (notes fallback).
	discoverySess := &scanSession{
		id:               filepath.Base(scanDir),
		target:           target,
		scanDir:          scanDir,
		cfg:              scanCfg,
		server:           s,
		instruction:      discoveryInstruction,
		severityFilter:   req.SeverityFilter,
		discoveryMode:    true,
		genReport:        false,
		resetState:       true,
		instanceID:       req.InstanceID,
		scanMode:         "wildcard",
		skipNotesCleanup: true, // preserve notes for subdomain collection
	}
	s.executeScanSession(discoverySess)

	// Capture the discovery session's context ID for notes lookup.
	// The sctx was set during executeScanSession and its notes were preserved.
	discoveryCtxID := ""
	if discoverySess.sctx != nil {
		discoveryCtxID = discoverySess.sctx.ID
	}

	// Read discovered subdomains — use discovery context ID for notes fallback
	subdomains := s.collectSubdomains(scanDir, target, discoveryCtxID)

	// Now clean up the discovery notes (deferred from skipNotesCleanup)
	if discoveryCtxID != "" {
		notes.CleanupContext(discoveryCtxID)
		log.Printf("[wildcard] Cleaned up discovery notes context: %s", discoveryCtxID)
	}

	log.Printf("[INFO] Total subdomains found for %s: %d", target, len(subdomains))

	// Fallback: if discovery found 0 subdomains, scan the root domain itself
	if len(subdomains) == 0 {
		log.Printf("[INFO] No subdomains discovered for %s — falling back to root domain scan", target)
		subdomains = []string{target}
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:         "target_completed",
			Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found 0 subdomains. Falling back to root domain scan of %s.", target),
			Target:       target,
			TargetIndex:  idx + 1,
			TotalTargets: total,
		})
	} else {
		s.broadcastToInstance(req.InstanceID, WSEvent{
			Type:         "target_completed",
			Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found %d subdomains. Now scanning each individually.", len(subdomains)),
			Target:       target,
			TargetIndex:  idx + 1,
			TotalTargets: total,
		})
	}

	// ── PHASE 2: Scan each subdomain individually ──
	for j, subdomain := range subdomains {
		// Check both global stop and per-instance stop
		var instStopped bool
		s.instancesMu.RLock()
		if inst, ok := s.instances[req.InstanceID]; ok {
			inst.mu.RLock()
			instStopped = inst.Status == "stopped"
			inst.mu.RUnlock()
		}
		s.instancesMu.RUnlock()
		if s.stopReq.Load() || instStopped {
			log.Printf("[INFO] Subdomain loop stopped by user at %d/%d for %s", j+1, len(subdomains), target)
			s.broadcastToInstance(req.InstanceID, WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			break
		}

		// Note: No parent context timeout check here. Each subdomain scan has its own
		// agent-level timeout (2h). We let the stop button handle manual cancellation.

		// ── Memory & goroutine health check between subdomain scans ──
		logMemStats(fmt.Sprintf("Before subdomain %d/%d: %s", j+1, len(subdomains), subdomain))

		// Force GC between subdomain scans to free accumulated memory
		runtime.GC()

		log.Printf("[INFO] Starting subdomain %d/%d: %s (parent: %s)", j+1, len(subdomains), subdomain, target)

		// Each subdomain gets its own isolated session wrapped in a panic guard
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] Subdomain %d/%d crashed (%s): %v — skipping to next\n%s", j+1, len(subdomains), subdomain, r, debug.Stack())
					s.broadcastToInstance(req.InstanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Subdomain %s crashed: %v — skipping", subdomain, r)})
				}
			}()

			subScanDir := s.makeScanDir(subdomain)
			scanInstruction := buildSubdomainScanInstruction(subdomain, target, req.Instruction)
			scanInstruction += buildPhaseFilterInstruction(req.Phases)

			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:           "target_started",
				Content:        fmt.Sprintf("[PHASE 2] Scanning subdomain %d/%d: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				AgentID:        filepath.Base(subScanDir),
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
			})

			// Track vulns BEFORE this subdomain scan using the stable parent context
			vulnCountBefore := len(reporting.GetVulnerabilitiesForContext(parentReportingCtxID))

			subSess := &scanSession{
				id:                   filepath.Base(subScanDir),
				target:               subdomain,
				parentTarget:         target,
				scanDir:              subScanDir,
				cfg:                  scanCfg,
				server:               s,
				instruction:          scanInstruction,
				severityFilter:       req.SeverityFilter,
				discoveryMode:        false,
				genReport:            false,
				resetState:           false, // accumulate vulns across subdomains
				instanceID:           req.InstanceID,
				scanMode:             "wildcard",
				parentReportingCtxID: parentReportingCtxID, // merge vulns into parent on cleanup
				companyName:          req.CompanyName,
				logoPath:             req.LogoPath,
				phases:               req.Phases,
			}
			s.executeScanSession(subSess)

			// Generate PDF for this subdomain if NEW vulnerabilities found
			// Read from the stable parent context — guaranteed to have all accumulated vulns
			allVulns := reporting.GetVulnerabilitiesForContext(parentReportingCtxID)
			if vulnCountBefore <= len(allVulns) {
				newVulns := allVulns[vulnCountBefore:]
				if len(newVulns) > 0 {
					subScanRecord := ScanRecord{
						ID:           filepath.Base(subScanDir),
						Target:       subdomain,
						ParentTarget: target,
						StartedAt:    time.Now().Format(time.RFC3339),
						Status:       "finished",
						FinishedAt:   time.Now().Format(time.RFC3339),
						Vulns:        []VulnSummary{},
					}
					for _, v := range newVulns {
						subScanRecord.Vulns = append(subScanRecord.Vulns, vulnToSummary(v))
					}
					reportPath, err := s.generateReportAt(&subScanRecord, subScanDir)
					if err == nil {
						desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found", subdomain, len(newVulns))
						s.sendDiscordWithFile(0x3b82f6, "🔴 Vulnerability Found - Report Ready", desc, reportPath)
					}
				}
			}

			s.broadcastToInstance(req.InstanceID, WSEvent{
				Type:           "target_completed",
				Content:        fmt.Sprintf("[PHASE 2] Subdomain %d/%d completed: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
			})
		}()

		// ── Cooldown between subdomain scans ──
		// Prevents LLM API rate-limiting and gives GC time to reclaim memory
		if j < len(subdomains)-1 && !s.stopReq.Load() && !instStopped {
			log.Printf("[INFO] Cooldown: 10s pause before next subdomain (memory recovery + rate limit prevention)")
			time.Sleep(10 * time.Second)
		}
	}

	log.Printf("[INFO] Wildcard scan complete for %s: scanned %d subdomains", target, len(subdomains))
	logMemStats(fmt.Sprintf("Wildcard scan complete for %s", target))
	// Clean up processes before next target — use instance's terminal if available
	s.instancesMu.RLock()
	if inst, ok := s.instances[req.InstanceID]; ok {
		inst.mu.RLock()
		if inst.sctx != nil && inst.sctx.Terminal != nil {
			inst.sctx.Terminal.KillAll()
		} else {
			terminal.KillAllProcesses() // fallback
		}
		inst.mu.RUnlock()
	} else {
		terminal.KillAllProcesses() // fallback
	}
	s.instancesMu.RUnlock()
}

// buildDiscoveryInstruction creates the Phase 1 subdomain enumeration instruction.
func buildDiscoveryInstruction(target string) string {
	instruction := `# PHASE 1: SUBDOMAIN ENUMERATION ONLY

## YOUR TASK: Find ALL subdomains of TARGET — NOTHING ELSE.

## STRICT RULES:
- You are ONLY allowed to enumerate subdomains in this phase.
- DO NOT run any vulnerability scanners (nuclei, sqlmap, ffuf, gobuster, nikto, etc.).
- DO NOT test for XSS, SQLi, SSRF, IDOR, or any other vulnerability.
- DO NOT analyze JavaScript files, test authentication, or probe endpoints.
- After collecting subdomains, you MUST call finish IMMEDIATELY.

## SAVE ALL FILES IN THE CURRENT DIRECTORY
Save all output files directly in the current working directory (not subdirectories).

## SUBDOMAIN ENUMERATION COMMANDS - RUN ALL:

# 1. subfinder (passive)
subfinder -d TARGET -recursive -silent -o ./passive_subfinder.txt
subfinder -d TARGET -all -recursive -silent -o ./passive_subfinder2.txt

# 2. Certificate Transparency (curl)
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt

# 3. findomain
findomain -t TARGET --unique-output ./passive_findomain.txt 2>/dev/null || true

# 4. assetfinder
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt 2>/dev/null || true

# 5. DNS Bufferover
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt

# 6. Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt

# 7. Active enumeration
subfinder -d TARGET -all -recursive -t 100 -o ./active_subfinder.txt

# 8. MERGE ALL RESULTS
cat ./passive_*.txt ./active_*.txt ./archive_subdomains.txt 2>/dev/null | grep -v '*' | grep -v '@' | sort -u > ./all_subdomains.txt
echo "Total unique subdomains found:"
wc -l ./all_subdomains.txt

# 9. RESOLVE TO FIND LIVE HOSTS
cat ./all_subdomains.txt | dnsx -silent -a -resp -threads 100 -o ./live_resolved.txt 2>/dev/null || true
cat ./live_resolved.txt | cut -d' ' -f1 | grep -v '^$' | sort -u > ./live_subdomains.txt
echo "Live subdomains:"
wc -l ./live_subdomains.txt

## FINAL STEP (MANDATORY):
1. Call add_note with the complete list of live subdomains from ./live_subdomains.txt
2. Call finish IMMEDIATELY after. The system will handle vulnerability scanning of each subdomain separately.

DO NOT continue past this point. DO NOT scan for vulnerabilities. Call finish NOW.`

	// Replace TARGET placeholder with actual target
	instruction = strings.ReplaceAll(instruction, "TARGET", target)
	return instruction
}

// collectSubdomains reads discovered subdomains from all known file locations and agent notes.
// contextID is used for context-aware notes lookup; if empty, falls back to global notes.
func (s *Server) collectSubdomains(scanDir, target, contextID string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// Normalize target to root domain — strip www. prefix so "www.zooptos.com" → "zooptos.com"
	// This ensures api.zooptos.com matches when user entered www.zooptos.com
	rootTarget := strings.TrimPrefix(target, "www.")

	// ansiRegex strips ANSI escape codes (color, cursor, etc.) from tool output.
	// Tools like dnsx emit sequences like \x1b[35m that corrupt domain matching.
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

	// Helper: extract valid subdomains from a file (must be subdomains of the target)
	extractFromFile := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Strip all ANSI escape codes before parsing
		clean := ansiRegex.ReplaceAllString(string(data), "")
		var found []string
		for _, line := range strings.Split(clean, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Total") || strings.HasPrefix(line, "wc") {
				continue
			}
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			line = strings.TrimPrefix(line, "http[s]://")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.TrimRight(parts[0], "/.,;:")
				domain = strings.ToLower(domain)
				// Accept: exact root domain OR any subdomain of root domain
				if strings.Contains(domain, ".") && (domain == rootTarget || strings.HasSuffix(domain, "."+rootTarget)) && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	// stripMarkdown removes common markdown formatting from a token
	stripMarkdown := func(s string) string {
		s = strings.ReplaceAll(s, "**", "") // bold
		s = strings.ReplaceAll(s, "__", "") // bold alt
		s = strings.ReplaceAll(s, "`", "")  // code
		s = strings.ReplaceAll(s, "*", "")  // italic
		s = strings.TrimRight(s, "/.,;:()[]{}\"'")
		s = strings.TrimLeft(s, "/.,;:()[]{}\"'")
		return s
	}

	// isDomainMatch checks if a cleaned string is a valid subdomain of rootTarget
	isDomainMatch := func(domain string) bool {
		domain = strings.ToLower(domain)
		return strings.Contains(domain, ".") &&
			(domain == rootTarget || strings.HasSuffix(domain, "."+rootTarget)) &&
			!seen[domain]
	}

	// domainRegex matches potential domain names in free-form text
	domainRegex := regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+` + regexp.QuoteMeta(rootTarget) + `\b`)

	// Helper: extract subdomains from a text blob (e.g., agent notes)
	// Handles: plain lines, markdown lists (- , * , 1. ), bold (**...**), URLs, etc.
	extractFromText := func(text string) []string {
		// Strip ANSI escape codes from text blobs too (terminal captures may contain them)
		text = ansiRegex.ReplaceAllString(text, "")
		var found []string

		// Pass 1: line-by-line parsing (handles structured lists)
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Strip common list prefixes: "- ", "* ", "1. ", "2) ", etc.
			line = strings.TrimPrefix(line, "- ")
			line = strings.TrimPrefix(line, "* ")
			// Strip numbered list prefixes: "1. ", "2. ", "10. ", etc.
			if len(line) > 2 {
				dotIdx := strings.Index(line, ". ")
				if dotIdx > 0 && dotIdx <= 4 {
					prefix := line[:dotIdx]
					allDigits := true
					for _, c := range prefix {
						if c < '0' || c > '9' {
							allDigits = false
							break
						}
					}
					if allDigits {
						line = strings.TrimSpace(line[dotIdx+2:])
					}
				}
			}

			// Try each whitespace-delimited token in the line
			for _, token := range strings.Fields(line) {
				token = strings.TrimPrefix(token, "http://")
				token = strings.TrimPrefix(token, "https://")
				token = strings.TrimPrefix(token, "http[s]://")
				// Strip path component
				if idx := strings.Index(token, "/"); idx > 0 {
					token = token[:idx]
				}
				domain := strings.ToLower(stripMarkdown(token))
				if isDomainMatch(domain) {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}

		// Pass 2: regex fallback — catches domains embedded in any format
		if len(found) == 0 {
			lowerText := strings.ToLower(text)
			if strings.Contains(lowerText, rootTarget) {
				// Try regex extraction for subdomains
				matches := domainRegex.FindAllString(lowerText, -1)
				for _, m := range matches {
					m = strings.TrimRight(m, "/.,;:")
					if isDomainMatch(m) {
						seen[m] = true
						found = append(found, m)
					}
				}
				// Also check bare rootTarget (e.g., "bild.tv" itself)
				if !seen[rootTarget] {
					seen[rootTarget] = true
					found = append(found, rootTarget)
				}
			}
		}

		return found
	}

	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Layer 1: Check exact files in scan directory
	for _, name := range subdomainFileNames {
		path := filepath.Join(scanDir, name)
		if found := extractFromFile(path); len(found) > 0 {
			subdomains = append(subdomains, found...)
			if name == "live_subdomains.txt" || name == "live_resolved.txt" {
				break
			}
		}
	}

	// Layer 1.25: Check workspace and terminal workdir — agents run commands here,
	// so ./passive_subfinder.txt etc. land in these directories, NOT in scanDir.
	if len(subdomains) == 0 {
		checkDirs := []string{}
		if wd := terminal.GetWorkDir(); wd != "" && wd != scanDir {
			checkDirs = append(checkDirs, wd)
		}
		if s.cfg.Workspace != "" && s.cfg.Workspace != scanDir {
			checkDirs = append(checkDirs, s.cfg.Workspace)
		}
		for _, dir := range checkDirs {
			for _, name := range subdomainFileNames {
				path := filepath.Join(dir, name)
				if found := extractFromFile(path); len(found) > 0 {
					log.Printf("[INFO] Found %d subdomains from %s/%s (agent workdir)", len(found), dir, name)
					subdomains = append(subdomains, found...)
				}
			}
			if len(subdomains) > 0 {
				break
			}
		}
	}

	// Layer 1.5: Check /tmp — agents often save recon files here
	if len(subdomains) == 0 {
		for _, name := range subdomainFileNames {
			path := filepath.Join("/tmp", name)
			if found := extractFromFile(path); len(found) > 0 {
				log.Printf("[INFO] Found %d subdomains from /tmp/%s", len(found), name)
				subdomains = append(subdomains, found...)
			}
		}
	}

	// Layer 1.75: Check home directory — some agents write to ~/
	if len(subdomains) == 0 {
		if homeDir, err := os.UserHomeDir(); err == nil && homeDir != scanDir {
			for _, name := range subdomainFileNames {
				path := filepath.Join(homeDir, name)
				if found := extractFromFile(path); len(found) > 0 {
					log.Printf("[INFO] Found %d subdomains from %s/%s (home dir)", len(found), homeDir, name)
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	// Layer 2: Walk scan directory tree for any matching files
	if len(subdomains) == 0 {
		filepath.WalkDir(scanDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			for _, name := range subdomainFileNames {
				if base == name {
					if found := extractFromFile(path); len(found) > 0 {
						subdomains = append(subdomains, found...)
						return nil
					}
				}
			}
			return nil
		})
	}

	// Layer 3: Parse agent notes for subdomain data (context-aware)
	if len(subdomains) == 0 {
		var allNotes map[string]string
		if contextID != "" {
			allNotes = notes.GetAllNotesForContext(contextID)
		} else {
			allNotes = notes.GetAllNotes()
		}
		for key, value := range allNotes {
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, "subdomain") || strings.Contains(lowerKey, "live") || strings.Contains(lowerKey, "discovered") || strings.Contains(lowerKey, "domain") {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
		if len(subdomains) == 0 {
			for _, value := range allNotes {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
		}
	}

	if len(subdomains) == 0 {
		log.Printf("[WARN] No subdomains found after all fallback layers for target: %s (rootTarget: %s)", target, rootTarget)
	}

	// Shuffle so scan order is randomized — avoids predictable patterns
	mathrand.Shuffle(len(subdomains), func(i, j int) {
		subdomains[i], subdomains[j] = subdomains[j], subdomains[i]
	})

	return subdomains
}

// cleanTmpSubdomainFiles removes stale subdomain-related files from /tmp
// that could contaminate subsequent scans with targets from previous runs.
func cleanTmpSubdomainFiles() {
	subdomainFileNames := []string{
		"live_subdomains.txt", "live_subdomains_clean.txt", "live_resolved.txt",
		"all_subdomains.txt", "all_discovered_subdomains.txt", "subdomains.txt",
		"live_hosts.txt", "passive_subfinder.txt", "passive_subfinder2.txt",
		"active_subfinder.txt", "passive_crt.txt", "passive_findomain.txt",
		"passive_assetfinder.txt", "passive_dnsbufferover.txt", "archive_subdomains.txt",
		"resolved_subdomains.txt", "httpx_output.txt", "dnsx_output.txt",
	}

	// Remove known subdomain file names from /tmp
	for _, name := range subdomainFileNames {
		path := filepath.Join("/tmp", name)
		if err := os.Remove(path); err == nil {
			log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
		}
	}

	// Also remove any .txt files in /tmp that contain "subdomain" or "live" in the name
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		log.Printf("[CLEANUP] Failed to read /tmp for cleanup: %v", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".txt") && (strings.Contains(name, "subdomain") || strings.Contains(name, "live_") || strings.Contains(name, "passive_") || strings.Contains(name, "active_")) {
			path := filepath.Join("/tmp", name)
			if err := os.Remove(path); err == nil {
				log.Printf("[CLEANUP] Removed stale /tmp file: %s", path)
			}
		}
	}
}

// handleUploadTargets parses a text file with one target per line.
func (s *Server) handleUploadTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	} // 10MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Failed to read uploaded targets file: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"targets": targets,
		"count":   len(targets),
	})
}

// handleUploadInstructions reads a text file and returns its content.
func (s *Server) handleUploadInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	} // 5MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"content": string(data),
	})
}

// handleUploadLogo accepts an image file upload and saves it to the logos directory.
func (s *Server) handleUploadLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil { // 5MB max
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowedExts := map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".svg": true, ".gif": true, ".webp": true}
	if !allowedExts[ext] {
		http.Error(w, "unsupported image format: "+ext+" (allowed: png, jpg, jpeg, svg, gif, webp)", http.StatusBadRequest)
		return
	}

	// Create logos directory
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.MkdirAll(logosDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create logos directory: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Generate unique filename: timestamp_originalname
	sanitized := strings.ReplaceAll(header.Filename, " ", "_")
	fileName := fmt.Sprintf("%d_%s", time.Now().UnixMilli(), sanitized)
	dstPath := filepath.Join(logosDir, fileName)

	dst, err := os.Create(dstPath)
	if err != nil {
		log.Printf("[ERROR] Failed to create logo file: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("[ERROR] Failed to write logo file: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Return the serving path
	servingPath := "/uploads/logos/" + fileName
	log.Printf("Logo uploaded: %s → %s", header.Filename, servingPath)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"path":     servingPath,
		"filename": header.Filename,
	})
}

// randomSlug generates a short random hex string for scan IDs.
func randomSlug() string {
	b := make([]byte, 4)
	if _, err := cryptorand.Read(b); err != nil {
		log.Printf("Warning: crypto/rand failed, falling back to time-based slug: %v", err)
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// sanitizeTarget creates a safe directory name from a target URL/domain.
func sanitizeTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	clean := re.ReplaceAllString(target, "_")
	clean = strings.TrimPrefix(clean, "https___")
	clean = strings.TrimPrefix(clean, "http___")
	clean = strings.Trim(clean, "_")
	if len(clean) > 60 {
		clean = clean[:60]
	}
	return clean
}

// saveScanRecordTo saves a scan record to a specific directory.
func (s *Server) saveScanRecordTo(rec *ScanRecord, scanDir string) {
	if scanDir == "" {
		return
	}

	// Check disk space before writing (50MB minimum)
	if avail := diskAvailable(scanDir); avail > 0 && avail < 50*1024*1024 {
		log.Printf("Warning: low disk space (%d MB available), scan record may fail to save", avail/1024/1024)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Low disk space: %d MB remaining. Scan data may not be saved.", avail/1024/1024)})
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal scan record: %v", err)
		return
	}
	if err := os.WriteFile(filepath.Join(scanDir, "scan.json"), data, 0644); err != nil {
		log.Printf("Error: failed to save scan record to %s: %v", scanDir, err)
		s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Failed to save scan data: %v", err)})
	}
}

// diskAvailable returns available bytes on the filesystem containing path, or 0 on error.
func diskAvailable(path string) uint64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	return stat.Bavail * uint64(stat.Bsize)
}

// vulnToSummary converts a reporting.Vulnerability to a VulnSummary with all fields.
func vulnToSummary(v reporting.Vulnerability) VulnSummary {
	return VulnSummary{
		ID:                 v.ID,
		Title:              v.Title,
		Severity:           v.Severity,
		Endpoint:           v.Endpoint,
		CVSS:               v.CVSS,
		CVSSVector:         v.CVSSVector,
		Description:        v.Description,
		Impact:             v.Impact,
		Method:             v.Method,
		CVE:                v.CVE,
		TechnicalAnalysis:  v.TechnicalAnalysis,
		PoCDescription:     v.PoCDescription,
		PoCScript:          v.PoCScript,
		Remediation:        v.Remediation,
		ExploitationProof:  v.ExploitationProof,
		VerificationMethod: v.VerificationMethod,
	}
}

// generateReportAt generates a PDF report, saving it to a specific directory.
func (s *Server) generateReportAt(scan *ScanRecord, scanDir string) (string, error) {
	// Temporarily set currentScanDir for the report generator,
	// then restore it. The report.go generateReport method reads s.currentScanDir.
	s.mu.Lock()
	prevDir := s.currentScanDir
	s.currentScanDir = scanDir
	s.mu.Unlock()

	reportPath, err := s.generateReport(scan)

	s.mu.Lock()
	s.currentScanDir = prevDir
	s.mu.Unlock()

	return reportPath, err
}

// scanEntry holds a discovered scan.json path and its parsed record.
type scanEntry struct {
	dir string     // directory containing scan.json
	rec ScanRecord // parsed record
}

// findAllScans recursively walks dataDir to find all scan.json files.
// Structure: dataDir/target/date/slug/scan.json
func (s *Server) findAllScans() []scanEntry {
	var results []scanEntry
	filepath.WalkDir(s.dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() != "scan.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var rec ScanRecord
		if json.Unmarshal(data, &rec) != nil {
			return nil
		}
		results = append(results, scanEntry{dir: filepath.Dir(path), rec: rec})
		return nil
	})
	return results
}

// findScanByID searches for a scan by its AgentID (the slug dir name).
func (s *Server) findScanByID(scanID string) (string, *ScanRecord) {
	// Sanitize: prevent path traversal via ../
	scanID = filepath.Base(scanID)
	if scanID == "" || scanID == "." || scanID == ".." {
		return "", nil
	}

	// First: walk the nested tree to find the scan by ID (dataDir/target/date/slug/scan.json)
	for _, entry := range s.findAllScans() {
		if entry.rec.ID == scanID || filepath.Base(entry.dir) == scanID {
			return entry.dir, &entry.rec
		}
	}
	// Second: try legacy flat path as fallback (dataDir/scanID/scan.json)
	direct := filepath.Join(s.dataDir, scanID, "scan.json")
	if data, err := os.ReadFile(direct); err == nil {
		var rec ScanRecord
		if json.Unmarshal(data, &rec) == nil {
			return filepath.Join(s.dataDir, scanID), &rec
		}
	}
	return "", nil
}

// rebuildInstancesFromDisk populates s.instances from all saved scan.json files on disk.
// This ensures the dashboard shows historical scans immediately after server restart.
// Skips subdomain scans (those with ParentTarget set) — those are shown under their parent.
// Running scans from a previous server instance are marked as "stopped" since the agent process is gone.
func (s *Server) rebuildInstancesFromDisk() {
	for _, entry := range s.findAllScans() {
		// Skip subdomain scans — they belong to their parent wildcard scan
		if entry.rec.ParentTarget != "" {
			continue
		}
		inst := &ScanInstance{
			ID:           entry.rec.ID,
			Targets:      entry.rec.Target,
			ParentTarget: entry.rec.ParentTarget,
			Status:       entry.rec.Status,
			StartedAt:    entry.rec.StartedAt,
			FinishedAt:   entry.rec.FinishedAt,
			StopReason:   entry.rec.StopReason,
			Iterations:   entry.rec.Iterations,
			ToolCalls:    entry.rec.ToolCalls,
			VulnCount:    len(entry.rec.Vulns),
			TotalTokens:  entry.rec.TotalTokens,
			ScanMode:     entry.rec.ScanMode,
		}
		// If scan was "running" from a previous server instance, it's no longer active
		if inst.Status == "running" {
			inst.Status = "stopped"
			inst.StopReason = "server_restart"
			inst.FinishedAt = time.Now().Format(time.RFC3339)
		}
		s.instances[entry.rec.ID] = inst
	}
}

// handleListScans returns a list of all saved scans (sorted newest first).
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	type scanInfo struct {
		ID          string `json:"id"`
		Target      string `json:"target"`
		StartedAt   string `json:"started_at"`
		Status      string `json:"status"`
		VulnCount   int    `json:"vuln_count"`
		TotalTokens int    `json:"total_tokens"`
	}

	var scans []scanInfo
	for _, entry := range s.findAllScans() {
		scans = append(scans, scanInfo{
			ID:          entry.rec.ID,
			Target:      entry.rec.Target,
			StartedAt:   entry.rec.StartedAt,
			Status:      entry.rec.Status,
			VulnCount:   len(entry.rec.Vulns),
			TotalTokens: entry.rec.TotalTokens,
		})
	}

	// Sort newest first
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt > scans[j].StartedAt
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

// handleDownloadReport serves the PDF report for a scan.
func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if scanID == "" {
		http.Error(w, "scan ID required", http.StatusBadRequest)
		return
	}

	scanDir, rec := s.findScanByID(scanID)
	if scanDir == "" || rec == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	reportPath := filepath.Join(scanDir, fmt.Sprintf("xalgorix_report_%s.pdf", scanID))

	// If report doesn't exist, try to generate it
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		if _, err := s.generateReportAt(rec, scanDir); err != nil {
			log.Printf("Report generation error: %v", err)
			http.Error(w, "failed to generate report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"xalgorix_report_%s.pdf\"", scanID))
	http.ServeFile(w, r, reportPath)
}

// handleRateLimit handles GET and POST for rate limit settings.
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current rate limit settings
		json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})

	case "POST":
		// Update rate limit settings
		var req struct {
			Requests int `json:"requests"`
			Window   int `json:"window"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Validate values
		if req.Requests < 1 {
			req.Requests = 1
		}
		if req.Requests > 1000 {
			req.Requests = 1000
		}
		if req.Window < 10 {
			req.Window = 10
		}
		if req.Window > 3600 {
			req.Window = 3600
		}

		// Update config
		s.cfg.RateLimitRequests = req.Requests
		s.cfg.RateLimitWindow = req.Window

		// Recreate rate limiter with new settings
		if s.rateLimiter != nil {
			s.rateLimiter.Stop()
		}
		s.rateLimiter = NewRateLimiter(req.Requests, time.Duration(req.Window)*time.Second)

		log.Printf("Rate limiting updated: %d requests/%ds per IP", req.Requests, req.Window)

		json.NewEncoder(w).Encode(map[string]int{
			"requests": req.Requests,
			"window":   req.Window,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func maskAgentMailKey(apiKey string) string {
	if len(apiKey) > 8 {
		return "****" + apiKey[len(apiKey)-8:]
	}
	if apiKey != "" {
		return "****"
	}
	return ""
}

func isMaskedAgentMailKey(apiKey string) bool {
	apiKey = strings.TrimSpace(apiKey)
	return strings.HasPrefix(apiKey, "****") || strings.Contains(apiKey, "••••")
}

// handleAgentMailSettings handles GET and POST for AgentMail settings.
func (s *Server) handleAgentMailSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		// Return current AgentMail settings (without exposing the full API key)
		json.NewEncoder(w).Encode(map[string]any{
			"pod":       s.cfg.AgentMailPod,
			"apiKey":    maskAgentMailKey(s.cfg.AgentMailAPIKey),
			"hasApiKey": s.cfg.AgentMailAPIKey != "",
		})

	case "POST":
		// Update AgentMail settings
		var req struct {
			Pod    string `json:"pod"`
			APIKey string `json:"apiKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		preserveKey := strings.TrimSpace(req.APIKey) == "" || isMaskedAgentMailKey(req.APIKey)
		effectiveAPIKey := req.APIKey
		if preserveKey {
			effectiveAPIKey = s.cfg.AgentMailAPIKey
		}

		// Update config
		s.cfg.AgentMailPod = req.Pod
		s.cfg.AgentMailAPIKey = effectiveAPIKey

		// Save to env file — read existing content and update only relevant keys
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			log.Printf("Error: failed to get home directory for env file: %v", homeErr)
			http.Error(w, "failed to determine home directory", http.StatusInternalServerError)
			return
		}
		envFile := filepath.Join(home, ".xalgorix.env")

		existing, _ := os.ReadFile(envFile) // OK to ignore — file may not exist yet
		lines := strings.Split(string(existing), "\n")
		var newLines []string
		podSet, keySet := false, false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "AGENTMAIL_POD=") {
				newLines = append(newLines, "AGENTMAIL_POD="+req.Pod)
				podSet = true
			} else if strings.HasPrefix(trimmed, "AGENTMAIL_API_KEY=") {
				if preserveKey {
					newLines = append(newLines, line)
				} else {
					newLines = append(newLines, "AGENTMAIL_API_KEY="+effectiveAPIKey)
				}
				keySet = true
			} else {
				newLines = append(newLines, line)
			}
		}
		if !podSet {
			newLines = append(newLines, "AGENTMAIL_POD="+req.Pod)
		}
		if !keySet && effectiveAPIKey != "" {
			newLines = append(newLines, "AGENTMAIL_API_KEY="+effectiveAPIKey)
		}

		if err := os.WriteFile(envFile, []byte(strings.Join(newLines, "\n")), 0o600); err != nil {
			log.Printf("Failed to save AgentMail settings: %v", err)
		} else {
			// os.WriteFile only honours the mode arg when *creating*; if the
			// file already existed with looser perms (e.g. user ran `nano`
			// and saved at the umask default of 0644) we must chmod it.
			if chmodErr := os.Chmod(envFile, 0o600); chmodErr != nil {
				log.Printf("Warning: could not chmod %s to 0600: %v", envFile, chmodErr)
			}
		}

		log.Printf("AgentMail settings updated: pod=%s", req.Pod)

		json.NewEncoder(w).Encode(map[string]any{
			"pod":       req.Pod,
			"apiKey":    maskAgentMailKey(effectiveAPIKey),
			"hasApiKey": effectiveAPIKey != "",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersion returns the current Xalgorix version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": Version,
	})
}

// handleStopNotify sends a stop notification to Discord if a scan was running
func (s *Server) handleStopNotify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Send Discord notification if webhook is configured
	if s.discordWebhook != "" {
		s.sendDiscord(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "notified"})
}

// handleChat allows users to send messages to the agent during a scan
type ChatRequest struct {
	Message    string `json:"message"`
	InstanceID string `json:"instance_id,omitempty"` // BUG FIX: Allow targeting a specific scan instance
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "message is required"})
		return
	}

	// BUG FIX: Use the explicitly provided instance_id to route chat messages
	// to the correct agent. Previously, `s.currentScanID` (a global) was always
	// used, so chat messages in multi-scan mode always went to the last-started
	// scan regardless of which instance the user was viewing.
	targetID := req.InstanceID
	if targetID == "" {
		// Fallback to global for single-instance backwards compatibility
		s.mu.RLock()
		targetID = s.currentScanID
		s.mu.RUnlock()
	}

	// Check if there's an active agent for the target instance
	s.mu.RLock()
	agnt := s.currentAgents[targetID]
	s.mu.RUnlock()
	if agnt == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "no active scan"})
		return
	}

	// Send the message to the agent
	response, err := agnt.SendMessage(req.Message)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"response": response,
	})
}

// handleQueueStatus returns the current queue state for recovery
func (s *Server) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if state, _ := s.validQueueState(true); state != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available":   true,
			"targets":     state.Targets,
			"current_idx": state.CurrentIdx,
			"remaining":   len(state.Targets) - state.CurrentIdx,
			"instruction": state.Instruction,
			"scan_mode":   state.ScanMode,
			"started_at":  state.StartedAt,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]any{"available": false})
	}
}

// handleQueueResume resumes an interrupted scan queue
func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.running.Load() {
		json.NewEncoder(w).Encode(map[string]string{"error": "A scan is already running"})
		return
	}

	state, _ := s.validQueueState(true)
	if state == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "No interrupted queue found"})
		return
	}

	// Resume from where we left off
	remaining := state.Targets[state.CurrentIdx:]
	req := ScanRequest{
		Targets:     remaining,
		Instruction: state.Instruction,
		ScanMode:    state.ScanMode,
	}

	// Start resume in background
	scanCfg := *s.cfg
	go s.runMultiScan(req, &scanCfg)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "resumed",
		"from_index":   state.CurrentIdx,
		"targets_left": len(remaining),
	})
}

// handleQueueClear clears an interrupted queue state
func (s *Server) handleQueueClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.clearQueueState()
	json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// handleGetScan returns a specific scan's full data.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL: /api/scans/{id}
	scanID := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	if scanID == "" || scanID == "latest" {
		// Find latest scan by StartedAt timestamp
		allScans := s.findAllScans()
		if len(allScans) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		sort.Slice(allScans, func(i, j int) bool {
			return allScans[i].rec.StartedAt > allScans[j].rec.StartedAt
		})
		data, _ := json.Marshal(allScans[0].rec)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	// DELETE /api/scans/{id} — delete scan from disk and in-memory instances
	// Handle this BEFORE findScanByID because instance IDs (from runMultiScan)
	// may differ from scan record IDs (directory slugs). We need to clean up both.
	if r.Method == http.MethodDelete {
		// Try to find and delete from disk
		dir, _ := s.findScanByID(scanID)
		if dir != "" {
			os.RemoveAll(dir)
		}
		// Always remove from in-memory instances map
		s.instancesMu.Lock()
		delete(s.instances, scanID)
		s.instancesMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted"}`))
		return
	}

	dir, rec := s.findScanByID(scanID)
	_ = dir
	if rec == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`null`))
		return
	}

	data, _ := json.Marshal(rec)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// logMemStats logs current memory usage and goroutine count.
// Called between subdomain scans to track memory growth and detect leaks.
func logMemStats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("[MEM] %s — HeapAlloc: %d MB, HeapInuse: %d MB, Sys: %d MB, NumGC: %d, Goroutines: %d",
		label,
		m.HeapAlloc/1024/1024,
		m.HeapInuse/1024/1024,
		m.Sys/1024/1024,
		m.NumGC,
		runtime.NumGoroutine(),
	)
}

func (s *Server) broadcast(evt WSEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		select {
		case client.send <- data:
			// queued successfully
		default:
			// client send buffer full — drop the client
			log.Printf("WebSocket client send buffer full, dropping client")
			go func(c *wsClient) {
				s.removeClient(c)
				c.conn.Close()
			}(client)
		}
	}
}

// broadcastToInstance sends an event only to clients subscribed to a specific instance.
// Also sends to unsubscribed clients (backward compatibility for single-scan workflow).
// Buffers events into the instance for replay.
func (s *Server) broadcastToInstance(instanceID string, evt WSEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	// Buffer event into instance for replay (cap at 500)
	s.instancesMu.RLock()
	if inst, ok := s.instances[instanceID]; ok {
		inst.mu.Lock()
		if len(inst.events) < 500 {
			inst.events = append(inst.events, evt)
		} else {
			// Keep last 400, drop oldest
			inst.events = append(inst.events[100:], evt)
		}
		// Also buffer vulns
		if len(evt.Vulns) > 0 {
			inst.Vulns = append(inst.Vulns, evt.Vulns...)
		}
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		// Send ONLY to clients explicitly subscribed to this instance.
		// Dashboard clients (instanceID=="") receive updates via broadcastDashboard.
		if client.instanceID == instanceID {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

// broadcastDashboard sends an event only to dashboard clients (no instance subscription).
func (s *Server) broadcastDashboard(evt WSEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		if client.instanceID == "" {
			select {
			case client.send <- data:
			default:
				go func(c *wsClient) {
					s.removeClient(c)
					c.conn.Close()
				}(client)
			}
		}
	}
}

// sendDiscord sends a rich embed message to the configured Discord webhook.
func (s *Server) sendDiscord(color int, title, description string) {
	s.sendDiscordWithFile(color, title, description, "")
}

// sendDiscordWithFile sends a rich embed message with an optional file attachment to Discord.
func (s *Server) sendDiscordWithFile(color int, title, description, filePath string) {
	if s.discordWebhook == "" {
		return
	}

	// If no file, send simple embed
	if filePath == "" {
		s.sendSimpleEmbed(color, title, description)
		return
	}

	// Check if file exists
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read PDF for Discord: %v", err)
		// Send embed without file
		s.sendSimpleEmbed(color, title, description+" (PDF generation failed)")
		return
	}

	// Create multipart form data
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// Add payload JSON
	embedPayload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}
	embedJSON, err := json.Marshal(embedPayload)
	if err != nil {
		log.Printf("Error: failed to marshal Discord embed payload: %v", err)
		return
	}
	if err := writer.WriteField("payload_json", string(embedJSON)); err != nil {
		log.Printf("Error: failed to write Discord payload field: %v", err)
		return
	}

	// Add file
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		log.Printf("Error: failed to create form file for Discord: %v", err)
		return
	}
	if _, err := part.Write(fileData); err != nil {
		log.Printf("Error: failed to write file data for Discord: %v", err)
		return
	}
	writer.Close()

	// Capture content type before goroutine to avoid fragile writer capture
	contentType := writer.FormDataContentType()

	// Send request
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Post(s.discordWebhook, contentType, &b)
		if err != nil {
			log.Printf("Discord webhook file upload error: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Printf("Warning: failed to read Discord error response: %v", readErr)
			}
			log.Printf("Discord webhook error: %d %s", resp.StatusCode, string(respBody))
		}
	}()
}

// sendSimpleEmbed sends a simple embed without file attachment
func (s *Server) sendSimpleEmbed(color int, title, description string) {
	payload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	go func() {
		resp, err := http.Post(s.discordWebhook, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("Discord webhook error: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// isBlockedTarget checks whether a target resolves to a local, loopback, or internal
// IP address. This prevents the agent from inadvertently scanning the host machine.
func isBlockedTarget(target string) bool {
	// Strip scheme if present (http://127.0.0.1 → 127.0.0.1)
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	// Also handle host:port without scheme
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Explicit textual matches (fast path)
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "[::1]" || lower == "::1" {
		return true
	}

	// Parse as IP
	ip := net.ParseIP(host)
	if ip == nil {
		// Try DNS resolution for hostnames that might resolve to local IPs
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false // can't resolve — let it through, will fail naturally
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return false
		}
	}

	// Check blocked ranges
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	// RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"::1/128",
		"fc00::/7", // IPv6 unique local
		"fe80::/10", // IPv6 link-local
	}
	for _, cidr := range privateCIDRs {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// severityMeetsThreshold returns true if the vuln severity is at or above the minimum
// threshold. Empty threshold means "send everything".
// Severity hierarchy: info < low < medium < high < critical
func severityMeetsThreshold(severity, minSeverity string) bool {
	if minSeverity == "" {
		return true // no threshold = send all
	}
	order := map[string]int{
		"info":     0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	vulnLevel, ok1 := order[strings.ToLower(severity)]
	minLevel, ok2 := order[strings.ToLower(minSeverity)]
	if !ok1 || !ok2 {
		return true // unknown severity = send it
	}
	return vulnLevel >= minLevel
}

// startCaidoProxy launches Caido proxy in background if it's installed and not already running.
func startCaidoProxy() {
	cfg := config.Get()
	port := cfg.CaidoPort
	if port == 0 {
		port = 8080
	}

	// Check if something is already listening on the Caido port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err == nil {
		conn.Close()
		log.Printf("Caido proxy already running on port %d", port)
		return
	}

	// Check if caido binary exists
	caidoPath, err := exec.LookPath("caido")
	if err != nil {
		log.Printf("Caido not installed — proxy features will use direct HTTP (install from https://caido.io)")
		return
	}

	// Start Caido in background with --no-open (headless)
	cmd := exec.Command(caidoPath, "--no-open", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Failed to start Caido proxy: %v", err)
		return
	}

	// Don't wait for the process — let it run in background
	go func() {
		cmd.Wait() // Reap zombie process
	}()

	log.Printf("✅ Caido proxy started on port %d (PID: %d)", port, cmd.Process.Pid)
}
