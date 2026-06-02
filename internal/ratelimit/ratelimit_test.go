package ratelimit_test

import (
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/ratelimit"
)

// TestBurstAllowedImmediately verifies that up to `burst` tokens are
// available instantly on a fresh limiter.
func TestBurstAllowedImmediately(t *testing.T) {
	l := ratelimit.New(10, 5)
	url := "https://example.com/path"

	for i := 0; i < 5; i++ {
		if !l.Allow(url) {
			t.Fatalf("expected token %d to be available immediately", i+1)
		}
	}
	// Burst exhausted — next Allow should return false.
	if l.Allow(url) {
		t.Fatal("expected Allow to return false after burst exhausted")
	}
}

// TestPerDomainIsolation verifies that two domains have independent buckets.
func TestPerDomainIsolation(t *testing.T) {
	l := ratelimit.New(10, 2)

	l.Allow("https://target-a.com")
	l.Allow("https://target-a.com")
	// target-a burst exhausted
	if l.Allow("https://target-a.com") {
		t.Fatal("target-a should be rate-limited")
	}
	// target-b bucket is independent — must still have tokens
	if !l.Allow("https://target-b.com") {
		t.Fatal("target-b should not be affected by target-a's rate limit")
	}
}

// TestDisabledPassthrough verifies rps=0 disables limiting.
func TestDisabledPassthrough(t *testing.T) {
	l := ratelimit.New(0, 1)
	for i := 0; i < 1000; i++ {
		if !l.Allow("https://example.com") {
			t.Fatalf("limiter should be disabled but blocked at iteration %d", i)
		}
	}
}

// TestReset verifies that Reset restores a full burst bucket.
func TestReset(t *testing.T) {
	l := ratelimit.New(10, 2)
	l.Allow("https://example.com")
	l.Allow("https://example.com")
	if l.Allow("https://example.com") {
		t.Fatal("expected burst to be exhausted before reset")
	}

	l.Reset()
	if !l.Allow("https://example.com") {
		t.Fatal("expected token to be available after reset")
	}
}

// TestWaitReturnsWithinReasonableTime verifies Wait does not block forever.
func TestWaitReturnsWithinReasonableTime(t *testing.T) {
	l := ratelimit.New(100, 1)     // 100 rps — each token arrives in ~10 ms
	l.Allow("https://example.com") // exhaust burst=1

	done := make(chan struct{})
	go func() {
		l.Wait("https://example.com")
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Wait blocked for more than 500 ms at 100 rps")
	}
}
