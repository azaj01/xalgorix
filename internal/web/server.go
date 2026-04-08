// Package web provides the Xalgorix web UI server.
package web

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xalgord/xalgorix/v3/internal/agent"
	"github.com/xalgord/xalgorix/v3/internal/config"
	"github.com/xalgord/xalgorix/v3/internal/tools/agentsgraph"
	"github.com/xalgord/xalgorix/v3/internal/tools/notes"
	"github.com/xalgord/xalgorix/v3/internal/tools/reporting"
	"github.com/xalgord/xalgorix/v3/internal/tools/terminal"
)

const version = "3.19.18"

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
			
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = strings.Split(forwarded, ",")[0]
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

// authSessions stores valid session tokens (token → expiry)
var (
	authSessions   = make(map[string]time.Time)
	authSessionsMu sync.RWMutex
)

const sessionCookieName = "xalgorix_session"
const sessionDuration = 24 * time.Hour

// generateSessionToken creates a cryptographically random session token
func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		// cryptorand should almost never fail; if it does, we can't produce
		// a secure token. Log fatal and return a best-effort token.
		log.Fatalf("[FATAL] cryptorand.Read failed: %v — cannot generate secure session token", err)
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
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

// authMiddleware protects routes when auth is configured
func authMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth if no credentials configured
			if cfg.Username == "" || cfg.Password == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Public routes that don't need auth
			path := r.URL.Path
			if path == "/api/auth/login" || path == "/api/auth/status" ||
				strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/assets/") {
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

	if creds.Username != s.cfg.Username || creds.Password != s.cfg.Password {
		// Rate-limit failed attempts
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	// Create session
	token := generateSessionToken()
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
	wsPingInterval  = 30 * time.Second
	wsPongWait      = 60 * time.Second
	wsWriteWait     = 10 * time.Second
	wsMaxMessageSize = 8192 // max incoming message from client
	wsMaxClients     = 50
	wsSendBufSize    = 512 // buffered channel size per client
)

// wsClient wraps a WebSocket connection with a buffered send channel.
type wsClient struct {
	conn       *websocket.Conn
	send       chan []byte
	server     *Server
	instanceID string // which instance this client is watching (empty = dashboard)
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
	Model          string   `json:"model"`            // e.g. "minimax/MiniMax-M2.5"
	APIKey         string   `json:"api_key"`          // provider API key
	APIBase        string   `json:"api_base"`         // provider API base URL
	DiscordWebhook string   `json:"discord_webhook"` // Discord webhook URL
	SeverityFilter []string `json:"severity_filter"` // e.g. ["critical", "high"]
	InstanceID     string   `json:"-"`               // internal: parent instance ID
}

// WSEvent is a WebSocket message sent to clients.
type WSEvent struct {
	Type            string            `json:"type"`
	Content         string            `json:"content,omitempty"`
	ToolName        string            `json:"tool_name,omitempty"`
	ToolArgs        map[string]string `json:"tool_args,omitempty"`
	Output          string            `json:"output,omitempty"`
	Error           string            `json:"error,omitempty"`
	AgentID         string            `json:"agent_id,omitempty"`
	Timestamp       string            `json:"timestamp,omitempty"`
	Vulns           []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex     int               `json:"target_index,omitempty"`
	TotalTargets    int               `json:"total_targets,omitempty"`
	Target          string            `json:"target,omitempty"`
	TotalTokens     int               `json:"total_tokens,omitempty"`
	SubTargetIndex  int               `json:"sub_target_index,omitempty"`  // subdomain index within a wildcard target
	SubTargetTotal  int               `json:"sub_target_total,omitempty"`  // total subdomains for current wildcard target
	ParentTarget    string            `json:"parent_target,omitempty"`     // parent domain for subdomain scans
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
	ID          string      `json:"id"`
	Target      string      `json:"target"`
	StartedAt   string      `json:"started_at"`
	FinishedAt  string      `json:"finished_at,omitempty"`
	Status      string      `json:"status"` // running, finished, stopped
	Events      []WSEvent   `json:"events"`
	Vulns       []VulnSummary `json:"vulns"`
	TotalTokens int         `json:"total_tokens"`
	Iterations  int         `json:"iterations"`
	ToolCalls   int         `json:"tool_calls"`
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
	ID          string             `json:"id"`
	Targets     string             `json:"targets"`
	Status      string             `json:"status"` // running, finished, stopped
	StartedAt   string             `json:"started_at"`
	FinishedAt  string             `json:"finished_at,omitempty"`
	Iterations  int                `json:"iterations"`
	ToolCalls   int                `json:"tool_calls"`
	VulnCount   int                `json:"vuln_count"`
	TotalTokens int                `json:"total_tokens"`
	ScanMode    string             `json:"scan_mode"`
	Vulns       []VulnSummary      `json:"vulns,omitempty"`
	agent       *agent.Agent
	cancel      context.CancelFunc
	scanDir     string
	events      []WSEvent // buffered events for replay
	mu          sync.RWMutex
}

const maxConcurrentInstances = 1

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
	if err := os.WriteFile(filepath.Join(s.dataDir, "queue_state.json"), data, 0644); err != nil {
		log.Printf("Error: failed to save queue state: %v", err)
	}
}

// loadQueueState loads queue state from disk if exists
func (s *Server) loadQueueState() *QueueState {
	data, err := os.ReadFile(filepath.Join(s.dataDir, "queue_state.json"))
	if err != nil {
		return nil
	}
	var state QueueState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	return &state
}

// clearQueueState removes the queue state file
func (s *Server) clearQueueState() {
	if err := os.Remove(filepath.Join(s.dataDir, "queue_state.json")); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove queue state file: %v", err)
	}
}

// Server is the web UI server.
type Server struct {
	cfg            *config.Config
	port           int
	clients        map[*wsClient]bool
	mu             sync.RWMutex
	currentAgent   *agent.Agent     // current agent for chat support
	cancelScan     context.CancelFunc // cancels the current scan session context
	running        atomic.Bool
	stopReq        atomic.Bool
	dataDir        string
	currentScanDir string
	currentScanID  string
	discordWebhook string
	rateLimiter    *RateLimiter
	instances      map[string]*ScanInstance // concurrent scan instances
	instancesMu    sync.RWMutex
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
	
	return &Server{
		cfg:            cfg,
		port:           port,
		clients:        make(map[*wsClient]bool),
		dataDir:        dataDir,
		discordWebhook: os.Getenv("XALGORIX_DISCORD_WEBHOOK"),
		rateLimiter:    rl,
		instances:      make(map[string]*ScanInstance),
	}
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	// Auto-start Caido proxy in background if available
	startCaidoProxy()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}


	mux := http.NewServeMux()
	// SPA handler: serve static files if they exist, otherwise serve index.html
	fileServer := http.FileServer(http.FS(staticFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the static file
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Check if it's a real static file - strip /static prefix since staticFS already points to static folder
		strippedPath := strings.TrimPrefix(path, "/static/")
		f, err := staticFS.(fs.ReadFileFS).ReadFile(strippedPath)
		if err == nil && f != nil {
			// Rewrite URL to serve from staticFS root (which is already "static")
			r.URL.Path = "/" + strippedPath
			fileServer.ServeHTTP(w, r)
			return
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
	return http.ListenAndServe(addr, authMw(rlMiddleware(mux)))
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

	// Check for interrupted queue and offer recovery
	if state := s.loadQueueState(); state != nil && state.Active {
		log.Printf("Found interrupted scan queue: %d targets remaining from index %d", 
			len(state.Targets)-state.CurrentIdx, state.CurrentIdx)
		// Queue will be offered for recovery via API
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

	instanceID := randomSlug()
	go s.runMultiScan(req, &scanCfg, instanceID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started", "instance_id": instanceID})
}


func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq.Store(true)

	// Cancel the current scan session context (interrupts LLM calls, tool execution)
	s.mu.Lock()
	cancel := s.cancelScan
	agnt := s.currentAgent
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if agnt != nil {
		agnt.Stop()
	}

	// Stop ALL running instances
	s.instancesMu.RLock()
	for _, inst := range s.instances {
		inst.mu.Lock()
		if inst.Status == "running" {
			inst.Status = "stopped"
			if inst.cancel != nil {
				inst.cancel()
			}
			if inst.agent != nil {
				inst.agent.Stop()
			}
		}
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()

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
		if inst.Status == "running" {
			runningCount++
		}
	}
	s.instancesMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]any{
		"running":           s.running.Load() || runningCount > 0,
		"scan_id":           scanID,
		"vulns":             len(reporting.GetVulnerabilities()),
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
			Targets:     inst.Targets,
			Status:      inst.Status,
			StartedAt:   inst.StartedAt,
			FinishedAt:  inst.FinishedAt,
			Iterations:  inst.Iterations,
			ToolCalls:   inst.ToolCalls,
			VulnCount:   inst.VulnCount,
			TotalTokens: inst.TotalTokens,
			ScanMode:    inst.ScanMode,
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

	json.NewEncoder(w).Encode(instances)
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
		if inst.Status == "running" {
			inst.Status = "stopped"
			inst.FinishedAt = time.Now().Format(time.RFC3339)
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
	instanceID     string // parent instance ID for multi-instance tracking
}

// cleanup tears down all per-session resources. Every sub-operation
// has its own panic guard so cleanup NEVER panics upward.
func (sess *scanSession) cleanup() {
	// Kill all processes spawned during this session
	func() {
		defer func() { recover() }()
		terminal.KillAllProcesses()
	}()

	// Stop agent if still running
	if sess.agent != nil {
		func() {
			defer func() { recover() }()
			sess.agent.Stop()
		}()
	}

	// Clear sub-agent state to prevent memory/goroutine leaks across scans
	func() {
		defer func() { recover() }()
		agentsgraph.Reset()
	}()

	// Clear terminal working directory to prevent stale workdir leaking to next session
	func() {
		defer func() { recover() }()
		terminal.SetWorkDir("")
	}()

	// Clear server references under lock
	sess.server.mu.Lock()
	if sess.server.currentAgent == sess.agent {
		sess.server.currentAgent = nil
	}
	sess.server.mu.Unlock()
}

// executeScanSession runs a single scan in complete isolation.
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeScanSession(sess *scanSession) {
	// IRONCLAD: This function NEVER panics upward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] scanSession %s panicked: %v", sess.id, r)
			s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
		}
		// ALWAYS clean up, whether normal exit or panic
		sess.cleanup()
	}()

	// 1. Reset global state if requested (with its own panic guard)
	if sess.resetState {
		func() {
			defer func() { recover() }()
			reporting.ResetVulnerabilities()
			notes.ResetNotes()
		}()
	}

	// 2. Set working directory
	terminal.SetWorkDir(sess.scanDir)

	// 3. Create agent with session's config
	events := make(chan agent.Event, 512)
	sess.events = events
	agnt := agent.NewAgent(sess.cfg, "XalgorixAgent", events)
	if sess.discoveryMode {
		agnt.SetDiscoveryMode(true)
	}
	sess.agent = agnt

	// Store agent ref on server for handleStop/handleChat (under lock)
	s.mu.Lock()
	s.currentScanDir = sess.scanDir
	s.currentScanID = sess.id
	s.currentAgent = agnt
	s.mu.Unlock()

	// Register agent with parent instance if applicable
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.agent = agnt
			inst.scanDir = sess.scanDir
			inst.mu.Unlock()
		}
		s.instancesMu.RUnlock()
	}

	// 4. Initialize scan record
	sess.record = &ScanRecord{
		ID:        sess.id,
		Target:    sess.target,
		StartedAt: time.Now().Format(time.RFC3339),
		Status:    "running",
		Events:    []WSEvent{},
		Vulns:     []VulnSummary{},
	}
	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 5. Event processing goroutine — drains events and broadcasts to WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recover() }() // never panic in event processor
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
	for _, v := range reporting.GetVulnerabilities() {
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
			s.broadcast(WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
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
			vulns := reporting.GetVulnerabilities()
			log.Printf("[VULN] report_vulnerability tool succeeded, vulns in list: %d", len(vulns))
			if len(vulns) > 0 {
				latest := vulns[len(vulns)-1]
				vs := vulnToSummary(latest)
				log.Printf("[VULN] Latest vuln: %s %s (CVSS %.1f)", vs.Severity, vs.Title, vs.CVSS)

				// Severity filter enforcement strictly at the UI layer
				allowed := true
				if len(sess.severityFilter) > 0 {
					allowed = false
					for _, s := range sess.severityFilter {
						if strings.EqualFold(s, vs.Severity) {
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

					// Discord: vulnerability found
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
					s.sendDiscord(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
				} else {
					log.Printf("[VULN] Vuln filtered out by severity: %s (filter: %v)", vs.Severity, sess.severityFilter)
				}
			}
		}
	}

	if evt.Type == "finished" {
		vulns := reporting.GetVulnerabilities()
		log.Printf("[VULN] Finished event: total vulns in system: %d", len(vulns))
		for _, v := range vulns {
			vs := vulnToSummary(v)
			allowed := true
			if len(sess.severityFilter) > 0 {
				allowed = false
				for _, s := range sess.severityFilter {
					if strings.EqualFold(s, vs.Severity) {
						allowed = true
						break
					}
				}
			}
			if allowed {
				wsEvt.Vulns = append(wsEvt.Vulns, vs)
				log.Printf("[VULN] Finished: adding vuln to final broadcast: %s %s", vs.Severity, vs.Title)
			} else {
				log.Printf("[VULN] Finished: filtered vuln (not added to broadcast): %s (filter: %v)", vs.Severity, sess.severityFilter)
			}
		}
		log.Printf("[VULN] Finished: total vulns in final broadcast: %d", len(wsEvt.Vulns))
	}

	// Track stats
	if evt.Type == "thinking" {
		sess.record.Iterations++
	}
	if evt.Type == "tool_call" {
		sess.record.ToolCalls++
	}
	if evt.TotalTokens > 0 {
		sess.record.TotalTokens = evt.TotalTokens
	}

	// Update parent instance stats
	if sess.instanceID != "" {
		s.instancesMu.RLock()
		if inst, ok := s.instances[sess.instanceID]; ok {
			inst.mu.Lock()
			inst.Iterations = sess.record.Iterations
			inst.ToolCalls = sess.record.ToolCalls
			inst.TotalTokens = sess.record.TotalTokens
			inst.VulnCount = len(sess.record.Vulns)
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
	req.Targets = cleanTargets

	// Create instance ID immediately
	var instanceID string
	if len(instanceIDs) > 0 && instanceIDs[0] != "" {
		instanceID = instanceIDs[0]
	} else {
		instanceID = randomSlug()
	}

	// Register instance as pending initially
	instance := &ScanInstance{
		ID:        instanceID,
		Targets:   strings.Join(req.Targets, ", "),
		Status:    "pending",
		StartedAt: time.Now().Format(time.RFC3339),
		ScanMode:  req.ScanMode,
	}
	s.instancesMu.Lock()
	s.instances[instanceID] = instance
	s.instancesMu.Unlock()

	// Broadcast to dashboard
	s.broadcastDashboard(WSEvent{Type: "instance_started", Content: instanceID})

	// Wait in queue until slot is available
	s.stopReq.Store(false) // clear global stop flag so new scans aren't immediately aborted
	for {
		if s.stopReq.Load() {
			// If cancelled while pending
			s.instancesMu.Lock()
			instance.Status = "stopped"
			instance.FinishedAt = time.Now().Format(time.RFC3339)
			s.instancesMu.Unlock()
			s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
			return
		}

		s.instancesMu.RLock()
		runningCount := 0
		for _, inst := range s.instances {
			if inst.Status == "running" {
				runningCount++
			}
		}
		s.instancesMu.RUnlock()

		if runningCount < maxConcurrentInstances {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Transition to running
	s.instancesMu.Lock()
	if instance.Status == "pending" {
		instance.Status = "running"
		instance.StartedAt = time.Now().Format(time.RFC3339)
	}
	s.instancesMu.Unlock()
	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})

	// Top-level panic recovery
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] runMultiScan goroutine panicked: %v", r)
			s.broadcastToInstance(instanceID, WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan goroutine crashed: %v — cleaning up", r)})
		}
		// Mark instance as finished
		instance.mu.Lock()
		if instance.Status == "running" {
			instance.Status = "finished"
		}
		instance.FinishedAt = time.Now().Format(time.RFC3339)
		instance.mu.Unlock()

		// ALWAYS clean up, whether we finished normally or crashed
		s.clearQueueState()
		s.mu.Lock()
		if s.currentScanID == instanceID {
			s.cancelScan = nil
			s.currentAgent = nil
		}
		s.mu.Unlock()
		s.broadcastToInstance(instanceID, WSEvent{Type: "queue_finished", Content: "Scan queue ended"})
		s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: instanceID})
		time.Sleep(500 * time.Millisecond)

		// Only set running=false if no other instances are running
		s.instancesMu.RLock()
		stillRunning := false
		for _, inst := range s.instances {
			if inst.Status == "running" && inst.ID != instanceID {
				stillRunning = true
				break
			}
		}
		s.instancesMu.RUnlock()
		if !stillRunning {
			s.running.Store(false)
		}
		log.Printf("[INFO] runMultiScan instance %s exited", instanceID)
	}()

	// Clear any previous queue state
	s.clearQueueState()
	s.running.Store(true)
	s.stopReq.Store(false)
	req.InstanceID = instanceID // thread instance ID to all target handlers
	if req.DiscordWebhook != "" {
		s.discordWebhook = req.DiscordWebhook
	}

	// ── GLOBAL STATE RESET: Prevent previous scan targets from leaking into current scan ──
	// This is the DEFINITIVE reset point — every new scan starts with a clean slate.
	func() {
		defer func() { recover() }()
		reporting.ResetVulnerabilities()
		notes.ResetNotes()
		terminal.SetWorkDir("") // clear stale working directory
		terminal.KillAllProcesses() // kill any orphaned processes from previous scans
		cleanTmpSubdomainFiles() // remove stale /tmp files from previous scans
	}()
	totalTargets := len(req.Targets)

	// Save queue state for persistence
	s.saveQueueState(req.Targets, 0, req.Instruction, req.ScanMode)

	s.broadcast(WSEvent{
		Type:         "queue_started",
		Content:      fmt.Sprintf("Starting scan queue: %d target(s)", totalTargets),
		TotalTargets: totalTargets,
	})

	// Discord: scan started
	s.sendDiscord(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))

	for i, target := range req.Targets {
		if s.stopReq.Load() {
			s.broadcast(WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			break
		}

		// Update queue state after each target
		s.saveQueueState(req.Targets, i, req.Instruction, req.ScanMode)

		// Per-target context with 2-hour timeout (use stop button for manual control)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		s.mu.Lock()
		s.cancelScan = cancel
		s.mu.Unlock()

		switch req.ScanMode {
		case "wildcard":
			s.runWildcardTarget(ctx, scanCfg, req, target, i, totalTargets)
		case "dast":
			s.runDASTTarget(ctx, scanCfg, req, target, i, totalTargets)
		default:
			s.runSingleTarget(ctx, scanCfg, req, target, i, totalTargets)
		}

		cancel() // always cancel context after target is done
	}

	// Clear queue state when done
	s.clearQueueState()

	// Discord: scan finished
	vulns := reporting.GetVulnerabilities()
	if len(vulns) > 0 {
		desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, len(vulns), time.Now().Format("15:04:05 MST"))
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

	s.broadcast(WSEvent{
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
	}
	s.executeScanSession(sess)

	s.broadcast(WSEvent{
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

	s.broadcast(WSEvent{
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
	}
	s.executeScanSession(sess)

	s.broadcast(WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[DAST] Completed: %s", target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runWildcardTarget handles wildcard mode: Phase 1 subdomain discovery, then Phase 2 per-subdomain scanning.
func (s *Server) runWildcardTarget(_ context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	// ── PHASE 1: Subdomain Discovery ──
	scanDir := s.makeScanDir(target)

	discoveryInstruction := buildDiscoveryInstruction(target)
	if req.Instruction != "" {
		discoveryInstruction += "\n\n" + req.Instruction
	}

	s.broadcast(WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[PHASE 1] Discovering subdomains for: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	discoverySess := &scanSession{
		id:             filepath.Base(scanDir),
		target:         target,
		scanDir:        scanDir,
		cfg:            scanCfg,
		server:         s,
		instruction:    discoveryInstruction,
		severityFilter: req.SeverityFilter,
		discoveryMode:  true,
		genReport:      false,
		resetState:     true,
		instanceID:     req.InstanceID,
	}
	s.executeScanSession(discoverySess)

	// Note: We do NOT check parentCtx here. Each subdomain scan has its own
	// agent-level timeout. The parent 2h timeout should not abort the entire
	// wildcard scan after just discovering subdomains.

	// Read discovered subdomains from file
	subdomains := s.collectSubdomains(scanDir, target)

	log.Printf("[INFO] Total subdomains found for %s: %d", target, len(subdomains))

	s.broadcast(WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found %d subdomains. Now scanning each individually.", len(subdomains)),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	// ── PHASE 2: Scan each subdomain individually ──
	for j, subdomain := range subdomains {
		if s.stopReq.Load() {
			log.Printf("[INFO] Subdomain loop stopped by user at %d/%d for %s", j+1, len(subdomains), target)
			s.broadcast(WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
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
					log.Printf("[PANIC] Subdomain %d/%d crashed (%s): %v — skipping to next", j+1, len(subdomains), subdomain, r)
					s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Subdomain %s crashed: %v — skipping", subdomain, r)})
				}
			}()

			subScanDir := s.makeScanDir(subdomain)
			scanInstruction := buildSubdomainScanInstruction(subdomain, target, req.Instruction)

			s.broadcast(WSEvent{
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

			// Track vulns BEFORE this subdomain scan to only count new ones
			vulnCountBefore := len(reporting.GetVulnerabilities())

			subSess := &scanSession{
				id:             filepath.Base(subScanDir),
				target:         subdomain,
				scanDir:        subScanDir,
				cfg:            scanCfg,
				server:         s,
				instruction:    scanInstruction,
				severityFilter: req.SeverityFilter,
				discoveryMode:  false,
				genReport:      false,
				resetState:     false, // accumulate vulns across subdomains
				instanceID:     req.InstanceID,
			}
			s.executeScanSession(subSess)

			// Generate PDF for this subdomain if NEW vulnerabilities found
			allVulns := reporting.GetVulnerabilities()
			if vulnCountBefore <= len(allVulns) {
				newVulns := allVulns[vulnCountBefore:]
				if len(newVulns) > 0 {
					subScanRecord := ScanRecord{
						ID:         filepath.Base(subScanDir),
						Target:     subdomain,
						StartedAt:  time.Now().Format(time.RFC3339),
						Status:     "finished",
						FinishedAt: time.Now().Format(time.RFC3339),
						Vulns:      []VulnSummary{},
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

			s.broadcast(WSEvent{
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
		if j < len(subdomains)-1 && !s.stopReq.Load() {
			log.Printf("[INFO] Cooldown: 10s pause before next subdomain (memory recovery + rate limit prevention)")
			time.Sleep(10 * time.Second)
		}
	}

	log.Printf("[INFO] Wildcard scan complete for %s: scanned %d subdomains", target, len(subdomains))
	logMemStats(fmt.Sprintf("Wildcard scan complete for %s", target))
	// Clean up processes before next target
	terminal.KillAllProcesses()
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
func (s *Server) collectSubdomains(scanDir, target string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// Helper: extract valid subdomains from a file
	extractFromFile := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var found []string
		for _, line := range strings.Split(string(data), "\n") {
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
				if strings.Contains(domain, ".") && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	// Helper: extract subdomains from a text blob (e.g., agent notes)
	extractFromText := func(text string) []string {
		var found []string
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			line = strings.TrimPrefix(line, "- ")
			line = strings.TrimPrefix(line, "* ")
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.TrimRight(parts[0], "/.,;:")
				if strings.Contains(domain, ".") && strings.Contains(domain, target) && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	subdomainFileNames := []string{
		"live_subdomains.txt", "live_resolved.txt", "all_subdomains.txt",
		"all_discovered_subdomains.txt", "subdomains.txt", "live_hosts.txt",
		"passive_subfinder.txt", "passive_subfinder2.txt", "active_subfinder.txt",
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

	// Layer 3: Parse agent notes for subdomain data
	if len(subdomains) == 0 {
		allNotes := notes.GetAllNotes()
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
		log.Printf("[WARN] No subdomains found after all fallback layers for target: %s", target)
	}

	return subdomains
}

// cleanTmpSubdomainFiles removes stale subdomain-related files from /tmp
// that could contaminate subsequent scans with targets from previous runs.
func cleanTmpSubdomainFiles() {
	subdomainFileNames := []string{
		"live_subdomains.txt", "live_resolved.txt", "all_subdomains.txt",
		"all_discovered_subdomains.txt", "subdomains.txt", "live_hosts.txt",
		"passive_subfinder.txt", "passive_subfinder2.txt", "active_subfinder.txt",
		"passive_crt.txt", "passive_findomain.txt", "passive_assetfinder.txt",
		"passive_dnsbufferover.txt", "archive_subdomains.txt",
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
	dir  string     // directory containing scan.json
	rec  ScanRecord // parsed record
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

	// First: try direct path (legacy flat structure)
	direct := filepath.Join(s.dataDir, scanID, "scan.json")
	if data, err := os.ReadFile(direct); err == nil {
		var rec ScanRecord
		if json.Unmarshal(data, &rec) == nil {
			return filepath.Join(s.dataDir, scanID), &rec
		}
	}
	// Second: walk the tree to find the scan by ID
	for _, entry := range s.findAllScans() {
		if entry.rec.ID == scanID || filepath.Base(entry.dir) == scanID {
			return entry.dir, &entry.rec
		}
	}
	return "", nil
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

// handleAgentMailSettings handles GET and POST for AgentMail settings.
func (s *Server) handleAgentMailSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	switch r.Method {
	case "GET":
		// Return current AgentMail settings (without exposing the full API key)
		apiKey := s.cfg.AgentMailAPIKey
		masked := ""
		if len(apiKey) > 8 {
			masked = "****" + apiKey[len(apiKey)-8:]
		} else if apiKey != "" {
			masked = "****"
		}
		json.NewEncoder(w).Encode(map[string]string{
			"pod":     s.cfg.AgentMailPod,
			"apiKey":  masked,
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
		
		// Update config
		s.cfg.AgentMailPod = req.Pod
		s.cfg.AgentMailAPIKey = req.APIKey
		
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
				newLines = append(newLines, "AGENTMAIL_API_KEY="+req.APIKey)
				keySet = true
			} else {
				newLines = append(newLines, line)
			}
		}
		if !podSet {
			newLines = append(newLines, "AGENTMAIL_POD="+req.Pod)
		}
		if !keySet {
			newLines = append(newLines, "AGENTMAIL_API_KEY="+req.APIKey)
		}
		
		if err := os.WriteFile(envFile, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
			log.Printf("Failed to save AgentMail settings: %v", err)
		}
		
		log.Printf("AgentMail settings updated: pod=%s", req.Pod)
		
		// Safe masking — handle short API keys
		maskedKey := "****"
		if len(req.APIKey) > 8 {
			maskedKey = "****" + req.APIKey[len(req.APIKey)-8:]
		}
		json.NewEncoder(w).Encode(map[string]string{
			"pod":    req.Pod,
			"apiKey": maskedKey,
		})
		
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersion returns the current Xalgorix version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": version,
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
	Message string `json:"message"`
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

	// Check if there's an active scan
	s.mu.RLock()
	agnt := s.currentAgent
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
	
	if state := s.loadQueueState(); state != nil && state.Active {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available":      true,
			"targets":        state.Targets,
			"current_idx":    state.CurrentIdx,
			"remaining":      len(state.Targets) - state.CurrentIdx,
			"instruction":    state.Instruction,
			"scan_mode":     state.ScanMode,
			"started_at":    state.StartedAt,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{"available": false})
	}
}

// handleQueueResume resumes an interrupted scan queue
func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if s.running.Load() {
		json.NewEncoder(w).Encode(map[string]string{"error": "A scan is already running"})
		return
	}
	
	state := s.loadQueueState()
	if state == nil || !state.Active {
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
		"targets_left":  len(remaining),
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

	_, rec := s.findScanByID(scanID)
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
		if evt.Type == "vuln" && len(evt.Vulns) > 0 {
			inst.Vulns = append(inst.Vulns, evt.Vulns...)
		}
		inst.mu.Unlock()
	}
	s.instancesMu.RUnlock()

	s.mu.RLock()
	defer s.mu.RUnlock()

	for client := range s.clients {
		// Send to clients watching this specific instance, or unsubscribed clients (legacy)
		if client.instanceID == instanceID || client.instanceID == "" {
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
