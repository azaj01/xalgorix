package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

// startMini boots an in-memory Redis server and returns it together
// with a cleaned-up [Client] wrapper. Each test gets its own server so
// pubsub channels and stream entries cannot leak between cases.
func startMini(t *testing.T) (*miniredis.Miniredis, *Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	cli, err := New(t.Context(), Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("New(miniredis): %v", err)
	}
	t.Cleanup(func() {
		if cerr := cli.Close(); cerr != nil {
			t.Logf("client close: %v", cerr)
		}
	})
	return mr, cli
}

// TestNewRequiresAddrs ensures the wrapper rejects empty configs
// instead of silently constructing a client that can never reach
// Redis.
func TestNewRequiresAddrs(t *testing.T) {
	t.Parallel()
	_, err := New(t.Context(), Options{})
	if err == nil {
		t.Fatal("New(empty Options) must return an error")
	}
}

// TestNewPingFailureClosesClient asserts that a bad address surfaces
// a wrapped PING error rather than panicking and that no client is
// returned to leak its connection pool.
func TestNewPingFailureClosesClient(t *testing.T) {
	t.Parallel()
	// Use a port that should be unreachable to force a PING failure.
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	cli, err := New(ctx, Options{
		Addrs:       []string{"127.0.0.1:1"},
		DialTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		_ = cli.Close()
		t.Fatal("New must fail when the server is unreachable")
	}
	if cli != nil {
		t.Fatal("New must not return a client on failure")
	}
}

// TestPing is a smoke check that the wrapper round-trips the PING
// command through the underlying go-redis client.
func TestPing(t *testing.T) {
	t.Parallel()
	_, cli := startMini(t)
	if err := cli.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestXAddXRangeMaxLen exercises the per-scan replay primitives. It
// asserts that maxLen triggers approximate trimming and that XRange
// honours start/end + COUNT semantics, mirroring the WebSocket
// coalescer's reconnect path.
func TestXAddXRangeMaxLen(t *testing.T) {
	t.Parallel()
	_, cli := startMini(t)
	ctx := t.Context()

	const stream = "scans:replay:test"
	for i := 0; i < 5; i++ {
		if _, err := cli.XAdd(ctx, stream, 0, map[string]any{
			"seq":  i,
			"data": "ev",
		}); err != nil {
			t.Fatalf("XAdd: %v", err)
		}
	}

	msgs, err := cli.XRange(ctx, stream, "-", "+", 0)
	if err != nil {
		t.Fatalf("XRange (full): %v", err)
	}
	if len(msgs) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(msgs))
	}
	if msgs[0].Values["seq"] != "0" || msgs[4].Values["seq"] != "4" {
		t.Fatalf("entries arrived out of order: first=%v last=%v", msgs[0], msgs[4])
	}

	limited, err := cli.XRange(ctx, stream, "-", "+", 2)
	if err != nil {
		t.Fatalf("XRange COUNT 2: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected COUNT=2 to bound, got %d", len(limited))
	}

	// MAXLEN ~ 3 should leave at most ~3 entries (miniredis applies
	// the trim eagerly even for the approximate variant).
	if _, err := cli.XAdd(ctx, stream, 3, map[string]any{"seq": 5}); err != nil {
		t.Fatalf("XAdd with maxLen: %v", err)
	}
	trimmed, err := cli.XRange(ctx, stream, "-", "+", 0)
	if err != nil {
		t.Fatalf("XRange after trim: %v", err)
	}
	if len(trimmed) > 3 {
		t.Fatalf("MAXLEN trim ineffective: %d entries remain", len(trimmed))
	}
}

// TestXAddRejectsEmptyValues protects callers from accidentally
// publishing zero-field entries which redis would happily reject at
// runtime with a less actionable error message.
func TestXAddRejectsEmptyValues(t *testing.T) {
	t.Parallel()
	_, cli := startMini(t)
	if _, err := cli.XAdd(t.Context(), "s", 0, nil); err == nil {
		t.Fatal("XAdd with nil values must return an error")
	}
	if _, err := cli.XAdd(t.Context(), "", 0, map[string]any{"k": "v"}); err == nil {
		t.Fatal("XAdd with empty stream must return an error")
	}
}

// TestSetNX covers the single-use enforcement primitive used by the
// magic-link issuer: the first writer must win; subsequent attempts
// must be denied while the TTL is still in effect.
func TestSetNX(t *testing.T) {
	t.Parallel()
	mr, cli := startMini(t)
	ctx := t.Context()

	const key = "magic:abc"
	got, err := cli.SetNX(ctx, key, "1", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SetNX first: %v", err)
	}
	if !got {
		t.Fatal("first SetNX must acquire")
	}

	got, err = cli.SetNX(ctx, key, "2", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SetNX second: %v", err)
	}
	if got {
		t.Fatal("second SetNX must fail while key is live")
	}

	// Fast-forward miniredis past the TTL and confirm the slot frees.
	mr.FastForward(300 * time.Millisecond)

	got, err = cli.SetNX(ctx, key, "3", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("SetNX after expiry: %v", err)
	}
	if !got {
		t.Fatal("SetNX must succeed once TTL elapses")
	}

	if _, err := cli.SetNX(ctx, "", "v", time.Second); err == nil {
		t.Fatal("SetNX with empty key must return an error")
	}
}

// TestPublishSubscribe verifies the pub/sub fan-out the WebSocket
// coalescer relies on. Subscribe must return a usable channel after
// the handshake completes, Publish must deliver the payload, and
// Close must release the underlying connection.
func TestPublishSubscribe(t *testing.T) {
	t.Parallel()
	_, cli := startMini(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	const channel = "ws:org:42:scan:7"
	sub, err := cli.Subscribe(ctx, channel)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() {
		if cerr := sub.Close(); cerr != nil {
			t.Logf("sub close: %v", cerr)
		}
	}()

	if err := cli.Publish(ctx, channel, []byte("hello")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case msg := <-sub.Channel():
		if msg == nil {
			t.Fatal("nil message from subscription")
		}
		if msg.Channel != channel || msg.Payload != "hello" {
			t.Fatalf("unexpected message: %#v", msg)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for published message")
	}

	if err := cli.Publish(ctx, "", []byte("x")); err == nil {
		t.Fatal("Publish with empty channel must return an error")
	}
}

// TestSubscribeRejectsEmptyArgs guards the convenience checks that
// keep the wrapper's contract honest.
func TestSubscribeRejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	_, cli := startMini(t)
	if _, err := cli.Subscribe(t.Context()); err == nil {
		t.Fatal("Subscribe without channels must return an error")
	}
	if _, err := cli.Subscribe(t.Context(), ""); err == nil {
		t.Fatal("Subscribe with empty channel must return an error")
	}
}

// TestNewWithClientTypeAlias documents that callers may swap in their
// own `redis.UniversalClient` (e.g. for sharing a pool across packages
// or injecting fakes). It also exercises [Client.Underlying].
func TestNewWithClientTypeAlias(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	rdb := goredis.NewUniversalClient(&goredis.UniversalOptions{
		Addrs: []string{mr.Addr()},
	})
	t.Cleanup(func() { _ = rdb.Close() })

	cli := NewWithClient(rdb)
	if cli.Underlying() != rdb {
		t.Fatal("Underlying() must return the injected client")
	}
	if err := cli.Ping(t.Context()); err != nil {
		t.Fatalf("Ping via NewWithClient: %v", err)
	}
}

// TestCloseIdempotent ensures shutdown is forgiving: nil clients and
// repeat Close calls must not panic.
func TestCloseIdempotent(t *testing.T) {
	t.Parallel()
	var cli *Client
	if err := cli.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}

	_, real := startMini(t)
	if err := real.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// A second Close on go-redis returns ErrClosed; we accept any
	// non-panic outcome here.
	if err := real.Close(); err != nil && !errors.Is(err, goredis.ErrClosed) && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("second Close returned unexpected error: %v", err)
	}
}
