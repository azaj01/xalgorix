package proxy

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

// Manager is the central proxy manager used by the rest of the application.
// It is initialized once via Init() and then accessed through the package-level
// helpers GetClient() / GetProxy().
//
// FIX (Gemini HIGH): the Manager now holds a single shared *http.Client per
// proxy slot instead of creating a new Transport on every call. This allows
// Go's http.Transport to reuse idle TCP connections (Keep-Alive) and avoids
// socket exhaustion under load.
type Manager struct {
	enabled  bool
	pool     *Pool
	rotation string // "roundrobin" | "random"
	timeout  time.Duration
	client   *http.Client // shared client used when proxy routing is disabled
}

var defaultManager *Manager

// Init initializes the package-level Manager from explicit parameters.
// Call this once at startup (e.g. from main or server init).
//
//	useProxy   – enable proxy routing
//	proxyURL   – single proxy string (takes precedence over proxyFile)
//	proxyFile  – path to a file with one proxy per line
//	rotation   – "roundrobin" or "random"
//	timeout    – per-request timeout
func Init(useProxy bool, proxyURL, proxyFile, rotation string, timeout time.Duration) error {
	m := &Manager{
		enabled:  useProxy,
		rotation: rotation,
		timeout:  timeout,
	}

	if useProxy {
		switch {
		case proxyURL != "":
			m.pool = NewPool([]string{proxyURL})
		case proxyFile != "":
			pool, err := LoadFile(proxyFile)
			if err != nil {
				return fmt.Errorf("proxy manager: %w", err)
			}
			m.pool = pool
		default:
			fmt.Fprintf(os.Stderr, "[proxy] USE_PROXY=true but no PROXY_URL or PROXY_FILE set — running without proxy\n")
			m.enabled = false
		}

		if m.pool != nil && m.pool.Len() == 0 {
			fmt.Fprintf(os.Stderr, "[proxy] proxy list is empty — running without proxy\n")
			m.enabled = false
		}
	}

	// Pre-build a shared no-proxy client (inherits DefaultTransport).
	// Used when proxy routing is disabled so behavior is truly zero-impact.
	noProxyTransport, _ := NewTransport(nil)
	m.client = &http.Client{
		Transport: noProxyTransport,
		Timeout:   m.timeoutOrDefault(),
	}

	defaultManager = m
	return nil
}

// Enabled reports whether proxy routing is active.
func Enabled() bool {
	if defaultManager == nil {
		return false
	}
	return defaultManager.enabled
}

// GetProxy returns the next proxy according to the configured rotation strategy.
// Returns nil when proxy routing is disabled or the pool is empty.
func GetProxy() *Proxy {
	if defaultManager == nil || !defaultManager.enabled || defaultManager.pool == nil {
		return nil
	}
	if defaultManager.rotation == "random" {
		return defaultManager.pool.Random()
	}
	return defaultManager.pool.Next()
}

// GetClient returns an *http.Client ready to use for the next request.
//
// FIX (Gemini HIGH): instead of constructing a brand-new Transport on every
// call (which breaks TCP connection reuse), we now:
//   - Return the shared no-proxy client directly when proxying is disabled.
//   - Build one Transport per proxy entry (cached in the Proxy struct) when
//     proxying is enabled, so connections to the same proxy are reused.
func GetClient() (*http.Client, error) {
	if defaultManager == nil {
		return http.DefaultClient, nil
	}
	if !defaultManager.enabled {
		// Return the pre-built shared client — zero extra allocation.
		return defaultManager.client, nil
	}
	p := GetProxy()
	if p == nil {
		return defaultManager.client, nil
	}
	return NewClient(p, defaultManager.timeoutOrDefault())
}

// GetClientFor returns an *http.Client wired to the given proxy string.
// Useful when the caller wants to pin a specific proxy for a request sequence.
func GetClientFor(rawProxy string) (*http.Client, error) {
	p, err := Parse(rawProxy)
	if err != nil {
		return nil, err
	}
	return NewClient(p, defaultManager.timeoutOrDefault())
}

func (m *Manager) timeoutOrDefault() time.Duration {
	if m == nil || m.timeout == 0 {
		return 30 * time.Second
	}
	return m.timeout
}
