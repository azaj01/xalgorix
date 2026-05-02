package browser

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// resetBridge clears the singleton bridge for test isolation.
func resetBridge() {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if bridge != nil && bridge.running {
		bridge.Stop()
	}
	bridge = nil
}

func TestBridge_Singleton(t *testing.T) {
	resetBridge()
	a := GetBridge()
	b := GetBridge()
	if a != b {
		t.Error("GetBridge should return the same instance")
	}
	resetBridge()
}

func TestBridge_Start(t *testing.T) {
	resetBridge()
	b := GetBridge()
	if err := b.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !b.running {
		t.Error("bridge should be running after Start")
	}
	b.Stop()
	resetBridge()
}

func TestBridge_StartIdempotent(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.Start()
	err := b.Start() // second call
	if err != nil {
		t.Errorf("second Start should not error: %v", err)
	}
	b.Stop()
	resetBridge()
}

func TestBridge_Stop(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.Start()
	b.Stop()
	if b.running {
		t.Error("bridge should not be running after Stop")
	}
	resetBridge()
}

func TestBridge_IsConnected_NoClient(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.Start()
	defer func() { b.Stop(); resetBridge() }()

	if b.IsConnected() {
		t.Error("should not be connected without a client")
	}
}

func TestBridge_SendCommand_NotConnected(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.Start()
	defer func() { b.Stop(); resetBridge() }()

	_, err := b.SendCommand("test", nil)
	if err == nil {
		t.Error("expected error when extension not connected")
	}
	if !strings.Contains(err.Error(), "extension not connected") {
		t.Errorf("error = %q, want 'extension not connected'", err.Error())
	}
}

// connectMockExtension dials the bridge WS server and returns the connection.
func connectMockExtension(t *testing.T, addr string) *websocket.Conn {
	t.Helper()
	url := "ws://" + addr + "/ext"
	var conn *websocket.Conn
	var err error
	for i := 0; i < 20; i++ {
		conn, _, err = websocket.DefaultDialer.Dial(url, http.Header{})
		if err == nil {
			return conn
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("failed to connect mock extension: %v", err)
	return nil
}

func TestBridge_SendCommand_Roundtrip(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.mu.Lock()
	b.addr = "127.0.0.1:38402"
	b.mu.Unlock()
	b.Start()
	defer func() { b.Stop(); resetBridge() }()

	// Connect mock extension
	conn := connectMockExtension(t, "127.0.0.1:38402")
	defer conn.Close()

	// Wait for connection to register
	time.Sleep(100 * time.Millisecond)

	if !b.IsConnected() {
		t.Fatal("bridge should be connected after mock client connects")
	}

	// Start a goroutine to respond to the command
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var cmd ExtCommand
		json.Unmarshal(msgBytes, &cmd)

		resp := ExtResponse{
			RequestID: cmd.RequestID,
			Result:    json.RawMessage(`"pong"`),
		}
		respBytes, _ := json.Marshal(resp)
		conn.WriteMessage(websocket.TextMessage, respBytes)
	}()

	result, err := b.SendCommandWithTimeout("ping", nil, 5*time.Second)
	if err != nil {
		t.Fatalf("SendCommand failed: %v", err)
	}
	if string(result) != `"pong"` {
		t.Errorf("result = %q, want '\"pong\"'", string(result))
	}
	wg.Wait()
}

func TestBridge_SendCommand_Timeout(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.mu.Lock()
	b.addr = "127.0.0.1:38403"
	b.mu.Unlock()
	b.Start()
	defer func() { b.Stop(); resetBridge() }()

	conn := connectMockExtension(t, "127.0.0.1:38403")
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)

	// Don't respond — should timeout
	_, err := b.SendCommandWithTimeout("slow", nil, 500*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want 'timed out'", err.Error())
	}
}

func TestBridge_ExtHello(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.mu.Lock()
	b.addr = "127.0.0.1:38404"
	b.mu.Unlock()
	b.Start()
	defer func() { b.Stop(); resetBridge() }()

	conn := connectMockExtension(t, "127.0.0.1:38404")
	defer conn.Close()

	// Send ext_hello
	hello := map[string]interface{}{
		"type":         "ext_hello",
		"version":      "1.0.0",
		"capabilities": []string{"screenshot", "dom"},
	}
	helloBytes, _ := json.Marshal(hello)
	conn.WriteMessage(websocket.TextMessage, helloBytes)

	time.Sleep(200 * time.Millisecond)

	b.mu.Lock()
	ver := b.extVersion
	b.mu.Unlock()

	if ver == "" {
		t.Error("ext_hello should have set extVersion")
	}
}

func TestBridge_Keepalive(t *testing.T) {
	resetBridge()
	b := GetBridge()
	b.mu.Lock()
	b.addr = "127.0.0.1:38405"
	b.mu.Unlock()
	b.Start()
	defer func() { b.Stop(); resetBridge() }()

	conn := connectMockExtension(t, "127.0.0.1:38405")
	defer conn.Close()

	// Send keepalive — should not crash
	ka := map[string]interface{}{"type": "keepalive"}
	kaBytes, _ := json.Marshal(ka)
	conn.WriteMessage(websocket.TextMessage, kaBytes)

	time.Sleep(100 * time.Millisecond)
	// No assertion needed — just verifying no panic
}
