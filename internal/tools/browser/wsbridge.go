// Package browser – WebSocket bridge for extension ↔ agent communication.
//
// The bridge provides a WebSocket server on localhost:38401/ext that the
// embedded Chrome extension connects to.  Commands are dispatched as
// JSON messages with request IDs for correlation, with a configurable
// timeout (default 15s) per roundtrip.
package browser

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ── Types ─────────────────────────────────────────────────────────────

// ExtCommand is the JSON payload sent to the extension.
type ExtCommand struct {
	RequestID string      `json:"requestId"`
	Command   string      `json:"command"`
	Args      interface{} `json:"args,omitempty"`
}

// ExtResponse is the JSON payload received from the extension.
type ExtResponse struct {
	RequestID string          `json:"requestId"`
	Result    json.RawMessage `json:"result,omitempty"`
	Type      string          `json:"type,omitempty"` // "ext_hello", "keepalive", etc.
}

// WSBridge manages the WebSocket server and extension connection.
type WSBridge struct {
	mu       sync.Mutex
	conn     *websocket.Conn
	server   *http.Server
	addr     string
	pending  map[string]chan json.RawMessage
	reqIDSeq atomic.Int64
	running  bool
	// Extension capabilities reported in ext_hello
	extVersion      string
	extCapabilities []string
}

// ── Singleton ─────────────────────────────────────────────────────────

var (
	bridge   *WSBridge
	bridgeMu sync.Mutex
)

// GetBridge returns the singleton WSBridge instance.
// It does NOT start the server — call bridge.Start() explicitly.
func GetBridge() *WSBridge {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if bridge == nil {
		bridge = &WSBridge{
			addr:    "127.0.0.1:38401",
			pending: make(map[string]chan json.RawMessage),
		}
	}
	return bridge
}

// ── Server Lifecycle ──────────────────────────────────────────────────

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // Allow extension origin
}

// Start starts the WebSocket server if not already running.
func (b *WSBridge) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.running {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ext", b.handleExtWS)

	b.server = &http.Server{
		Addr:    b.addr,
		Handler: mux,
		// Bound header-read time to avoid a Slowloris-style hang on this
		// loopback control channel.
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("[wsbridge] Starting WebSocket server on %s", b.addr)
		if err := b.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[wsbridge] Server error: %v", err)
		}
	}()

	b.running = true
	return nil
}

// Stop shuts down the WebSocket server and closes connections.
func (b *WSBridge) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.running {
		return
	}

	if b.conn != nil {
		b.conn.Close()
		b.conn = nil
	}

	if b.server != nil {
		_ = b.server.Close()
	}

	// Cancel all pending requests
	for id, ch := range b.pending {
		close(ch)
		delete(b.pending, id)
	}

	b.running = false
	log.Printf("[wsbridge] Server stopped")
}

// IsConnected returns true if an extension is connected.
func (b *WSBridge) IsConnected() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn != nil
}

// ── WebSocket Handler ─────────────────────────────────────────────────

func (b *WSBridge) handleExtWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[wsbridge] Upgrade failed: %v", err)
		return
	}

	b.mu.Lock()
	// Close previous connection if any (extension reconnected)
	if b.conn != nil {
		b.conn.Close()
	}
	b.conn = conn
	b.mu.Unlock()

	log.Printf("[wsbridge] Extension connected from %s", r.RemoteAddr)

	// Read loop
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[wsbridge] Read error: %v", err)
			break
		}

		var resp ExtResponse
		if err := json.Unmarshal(msgBytes, &resp); err != nil {
			log.Printf("[wsbridge] Invalid JSON from extension: %s", string(msgBytes))
			continue
		}

		// Handle special messages
		switch resp.Type {
		case "ext_hello":
			log.Printf("[wsbridge] Extension hello: version=%s", resp.Result)
			// Parse capabilities
			var hello struct {
				Version      string   `json:"version"`
				Capabilities []string `json:"capabilities"`
			}
			if err := json.Unmarshal(msgBytes, &hello); err == nil {
				b.mu.Lock()
				b.extVersion = hello.Version
				b.extCapabilities = hello.Capabilities
				b.mu.Unlock()
			}
			continue
		case "keepalive":
			continue
		}

		// Dispatch response to waiting caller
		if resp.RequestID != "" {
			b.mu.Lock()
			ch, ok := b.pending[resp.RequestID]
			if ok {
				select {
				case ch <- resp.Result:
				default:
				}
				delete(b.pending, resp.RequestID)
			}
			b.mu.Unlock()
		}
	}

	// Connection closed
	b.mu.Lock()
	if b.conn == conn {
		b.conn = nil
	}
	b.mu.Unlock()
	log.Printf("[wsbridge] Extension disconnected")
}

// ── Command Execution ─────────────────────────────────────────────────

// SendCommand sends a command to the extension and waits for the response.
// Returns the result JSON or an error if the extension is not connected
// or the command times out.
func (b *WSBridge) SendCommand(command string, args interface{}) (json.RawMessage, error) {
	return b.SendCommandWithTimeout(command, args, 15*time.Second)
}

// SendCommandWithTimeout sends a command with a custom timeout.
func (b *WSBridge) SendCommandWithTimeout(command string, args interface{}, timeout time.Duration) (json.RawMessage, error) {
	b.mu.Lock()
	if b.conn == nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("extension not connected")
	}

	reqID := fmt.Sprintf("req_%d", b.reqIDSeq.Add(1))
	ch := make(chan json.RawMessage, 1)
	b.pending[reqID] = ch

	cmd := ExtCommand{
		RequestID: reqID,
		Command:   command,
		Args:      args,
	}

	msgBytes, err := json.Marshal(cmd)
	if err != nil {
		delete(b.pending, reqID)
		b.mu.Unlock()
		return nil, fmt.Errorf("marshal command: %w", err)
	}

	err = b.conn.WriteMessage(websocket.TextMessage, msgBytes)
	b.mu.Unlock()

	if err != nil {
		b.mu.Lock()
		delete(b.pending, reqID)
		b.mu.Unlock()
		return nil, fmt.Errorf("write command: %w", err)
	}

	// Wait for response
	select {
	case result, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("connection closed while waiting for response")
		}
		return result, nil
	case <-time.After(timeout):
		b.mu.Lock()
		delete(b.pending, reqID)
		b.mu.Unlock()
		return nil, fmt.Errorf("command %q timed out after %s", command, timeout)
	}
}
