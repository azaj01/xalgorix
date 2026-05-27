// Package auth — exported helper that wires the four built-in
// OAuth drivers onto a Registry so the dashboard's NewServer can
// stand up the auth surface in one call.
//
// The per-driver constructors (newPKCEDriver, newDeviceCodeDriver,
// newSetupTokenDriver, newClaudeReuseDriver) are intentionally
// unexported — every legitimate construction site lives inside the
// auth package — so callers in internal/web cannot register a stub
// driver by reaching across the package boundary. RegisterDefaultDrivers
// is the single exported seam through which production code obtains
// the canonical four-driver registry.
//
// Validates: Requirements 6.x (pkce), 7.x (device_code), 8.x
// (setup_token), 9.x (claude_cli_reuse) — by ensuring every
// production registry has every flow handler attached.
package auth

// RegisterDefaultDrivers attaches the four built-in OAuth drivers
// (pkce, device_code, setup_token, claude_cli_reuse) to r. Each
// driver is constructed against r.Store() and r.HTTP(); the
// device_code driver additionally consumes a Clock so its poller
// can advance virtualized time in tests.
//
// The clock argument lets callers override the registry's stored
// clock without rebuilding the Registry — useful when test code
// has already constructed the Registry with a real clock and now
// wants to swap in a fake. When clock is nil the registry's own
// Clock (configured at NewRegistry time) is used so production
// callers can pass nil and get the expected wall-clock behavior.
//
// The function is idempotent in the limited sense that calling it
// twice on the same registry will overwrite the four registered
// drivers with fresh instances; tests that want to substitute a
// stub driver can call Register again afterward and rely on the
// last-write-wins semantics documented on Registry.Register.
func RegisterDefaultDrivers(r *Registry, clock Clock) {
	if r == nil {
		return
	}
	if clock == nil {
		clock = r.Clock()
	}
	r.Register(newPKCEDriver(r.Store(), r.HTTP()))
	r.Register(newDeviceCodeDriver(r.Store(), r.HTTP(), clock))
	r.Register(newSetupTokenDriver(r.Store(), r.HTTP()))
	r.Register(newClaudeReuseDriver(r.Store(), r.HTTP()))
}
