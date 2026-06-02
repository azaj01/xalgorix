// Package auth — OAuth driver registry and the Driver contract every
// per-flow handler implements.
//
// One Driver exists per Catalog_Entry.flow value the system supports:
//
//   - "pkce"             — driver_pkce.go        (Wave C task 3.4)
//   - "device_code"      — driver_device.go      (Wave C task 3.5)
//   - "setup_token"      — driver_setup.go       (Wave C task 3.6)
//   - "claude_cli_reuse" — driver_claude.go      (Wave C task 3.7)
//
// Every driver shares the same three-method shape (Start, Complete,
// Refresh) so the HTTP layer can dispatch a flow purely from the
// resolved Catalog_Entry — no per-flow switching in handlers
// (internal/web Wave E task 5.2 just calls Registry.Get(entry.Flow)
// and forwards the StartOptions / CompleteInput).
//
// This file owns the cross-driver glue: the Driver interface, the
// shared Start / Complete value shapes, the Clock seam used by the
// device-code driver to virtualize wall-time in tests, the Registry
// type wired into NewServer, and refreshWithSink — the canonical
// refresh protocol from Requirements 10.1–10.4 every driver delegates
// to. Per-driver constructors (newPKCEDriver, newDeviceCodeDriver,
// etc.) land in their respective files in tasks 3.4–3.7 and call
// Registry.Register(d) at construction time.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// Clock abstracts wall-clock reads so the device-code driver's
// poller (Wave C task 3.5, tests in Wave H task 9.5) can advance
// time deterministically. realClock is the production implementation
// that simply forwards to time.Now; tests substitute a fake clock
// via NewRegistry's clock parameter.
//
// The interface is intentionally minimal — only Now is needed today.
// If a future driver also needs After / NewTimer the surface can
// grow without a breaking change.
type Clock interface {
	Now() time.Time
}

// realClock is the production Clock used when callers do not pass a
// virtualized clock. It is unexported because every legitimate
// construction goes through NewRegistry, which substitutes a real
// clock when the caller passes nil.
type realClock struct{}

// Now returns time.Now in the local timezone — every consumer in
// auth converts to UTC at the persistence boundary (Profile.UpdatedAt
// is .UTC()'d in Store.Put), so this method does not pre-normalize.
func (realClock) Now() time.Time { return time.Now() }

// StartOptions carries per-request inputs the dashboard hands to a
// Driver.Start call. BindAddr is the dashboard's effective
// XALGORIX_BIND value — the PKCE driver inspects it at flow start
// and refuses to bind a non-loopback listener (Requirement 13.2),
// returning a paste-mode StartResult instead. PreferPaste lets the
// operator force the paste-fallback shape even on a loopback bind
// (e.g., remote-only operator over SSH-forwarded dashboard).
type StartOptions struct {
	BindAddr    string
	PreferPaste bool
}

// StartResult is the polymorphic shape every Driver.Start returns.
// Which fields are populated depends on Mode:
//
//   - "loopback" (PKCE happy path): AuthURL is the authorization
//     URL the dashboard should open in a new tab; the loopback
//     listener is already bound. UserCode / VerificationURI are
//     empty.
//   - "device" (device-code): UserCode + VerificationURI are
//     populated and the dashboard renders them; AuthURL is empty.
//   - "paste" (PKCE non-loopback fallback per R13.2): AuthURL is
//     populated; the operator pastes the resulting code through
//     POST /api/auth/profiles/oauth/complete.
//
// Submode disambiguates the three "paste" variants the dashboard
// renders differently:
//
//   - "" (empty)       — claude_cli_reuse: confirm-and-import UI
//     (no input field, the credential file is
//     already on disk).
//   - "paste_code"     — PKCE paste fallback: textarea for the
//     authorization code returned through OOB.
//   - "setup_token"    — setup_token driver: textarea for the
//     one-time vendor-issued token.
//
// The dashboard previously inferred this from "mode == paste &&
// !authURL", which conflated setup_token with claude_cli_reuse.
// H9 replaces the heuristic with this explicit field; older
// servers that don't populate Submode default to "" which still
// renders the claude_cli_reuse confirm-and-import UI as before.
//
// FlowID is the opaque correlation id the dashboard uses on the
// follow-up complete / status calls. ExpiresAt is the absolute UTC
// deadline at which the flow will be aborted (Requirements 6.5,
// 7.5).
type StartResult struct {
	FlowID          string
	Mode            string
	Submode         string `json:"submode,omitempty"`
	AuthURL         string
	UserCode        string
	VerificationURI string
	ExpiresAt       time.Time
}

// CompleteInput carries the fields the paste-fallback / setup-token
// completion endpoints submit. Each driver consumes a subset:
//
//   - PKCE paste-fallback (Requirement 6.6): FlowID, AuthorizationCode,
//     State.
//   - Setup-token (Requirement 8.1): SetupToken.
//   - Device-code and claude_cli_reuse: not used (those drivers
//     finalize through their Start path).
//
// Unused fields stay empty rather than being split into per-flow
// types so the HTTP handler can decode a single body shape.
type CompleteInput struct {
	FlowID            string
	AuthorizationCode string
	State             string
	SetupToken        string
}

// Driver is the per-flow handler contract. The Catalog_Entry argument
// supplies the upstream URLs (authorizationEndpoint, tokenEndpoint,
// deviceAuthorizationEndpoint), the client_id, scopes, and audience
// — drivers do not embed any provider-specific constants.
//
// Validates: the cross-flow surface declared by Requirements 6, 7,
// 8, 9, and 10.
type Driver interface {
	// Name returns the matching Catalog_Entry.flow value:
	// "pkce" | "device_code" | "setup_token" | "claude_cli_reuse".
	// Registry uses this value as the lookup key.
	Name() string

	// Start kicks off the flow and returns the polymorphic
	// StartResult. Side effects vary by flow (PKCE binds a
	// loopback listener; device-code spawns a poller goroutine;
	// setup-token / claude_cli_reuse return immediately).
	Start(ctx context.Context, e providers.Entry, opts StartOptions) (StartResult, error)

	// Complete finalizes the flow. Called by the loopback
	// callback handler / device poller for the in-driver path,
	// or by /api/auth/profiles/oauth/complete for the paste-
	// fallback / setup-token paths. Returns the persisted
	// Profile on success; the Store.Put inside the driver has
	// already committed it before this returns.
	Complete(ctx context.Context, e providers.Entry, in CompleteInput) (Profile, error)

	// Refresh rotates an OAuth_Profile's access token. Sink-
	// coalesced (Requirements 10.1–10.3) and ErrReauthRequired-
	// surfacing (Requirement 10.4) — every implementation
	// delegates to refreshWithSink to keep that protocol in one
	// place.
	Refresh(ctx context.Context, p Profile, e providers.Entry) (Profile, error)
}

// Revoker is an optional add-on contract a Driver may satisfy when
// its upstream supports RFC 7009 token revocation. Drivers that
// implement this interface get called from handleDeleteProfile
// before the profile is removed from disk so the upstream issuer
// has a chance to invalidate the access / refresh token. Failures
// are logged but never block the delete — the operator's intent is
// "remove this credential from xalgorix" and a flaky upstream
// must not strand a profile in the on-disk store.
//
// Implemented by: pkceDriver, deviceCodeDriver. Not implemented by
// claude_cli_reuse (no revocation endpoint — the operator regains
// control by re-running the upstream CLI) or setup_token (the
// vendor-specific token has no documented revocation surface).
//
// Validates: H1 (best-effort revoke on delete).
type Revoker interface {
	Revoke(ctx context.Context, e providers.Entry, p Profile) error
}

// Registry resolves drivers by Catalog_Entry.flow. NewRegistry
// constructs an empty registry and is the only legitimate
// construction site; per-driver tasks (3.4–3.7) call
// Registry.Register(d) inside their constructors so the wired-up
// registry returned from NewRegistry already contains every driver
// the build supports.
//
// The drivers map is unexported; callers go through Get / Register
// so the registry can grow concurrent-safety later (today it is
// single-threaded at construction; lookup is read-only after that).
type Registry struct {
	store *Store
	http  *http.Client
	clock Clock

	drivers map[string]Driver
}

// NewRegistry constructs an empty driver registry wired to the
// supplied Store, HTTP client, and Clock. Drivers register
// themselves at construction time via Register(d) — Wave C tasks
// 3.4–3.7 each add a constructor invocation here as they land.
//
// All three dependencies are required:
//
//   - store: every driver's Refresh / Complete persists through
//     this Store via Store.Put. The Store also owns the Token_Sink
//     refreshWithSink dereferences.
//   - http: the shared *http.Client every driver uses for outbound
//     requests (loopback callback exchanges, device-code polls,
//     setup-token exchanges). Injecting a single client lets tests
//     supply a roundtripper that asserts request shape.
//   - clock: the time source used by the device-code poller (and
//     any future driver that virtualizes wall time). nil is
//     accepted and substituted with realClock to keep simple
//     production wiring (NewRegistry(store, http, nil)) ergonomic.
func NewRegistry(store *Store, httpClient *http.Client, clock Clock) *Registry {
	if clock == nil {
		clock = realClock{}
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Registry{
		store:   store,
		http:    httpClient,
		clock:   clock,
		drivers: make(map[string]Driver),
	}
}

// Register adds d to the registry under d.Name(). Subsequent
// registrations with the same name overwrite — the driver ordering
// in NewServer's wiring picks the last-registered driver per name,
// which matches Go's map semantics and gives tests a clean way to
// substitute a stub driver.
//
// Register is intended to be called from driver constructors during
// NewRegistry's wiring sequence (Wave C tasks 3.4–3.7) and from
// test setup. It is safe to call before any Get because Get reads
// the same map without locking.
func (r *Registry) Register(d Driver) {
	if d == nil {
		return
	}
	r.drivers[d.Name()] = d
}

// Get returns the driver registered for flow, or (nil, false) when
// no driver matches. The HTTP layer (handleOAuthStart /
// handleOAuthComplete in Wave E task 5.2) maps !ok to HTTP 400
// with a "unknown flow" envelope so a Catalog_Entry referencing an
// unsupported flow surfaces cleanly instead of panicking.
func (r *Registry) Get(flow string) (Driver, bool) {
	d, ok := r.drivers[flow]
	return d, ok
}

// Store exposes the *Store the registry was constructed with.
// Driver constructors invoked by per-flow tasks (3.4–3.7) need a
// path to the same Store NewRegistry holds so they can call Put on
// the Profile after a successful Complete; this accessor avoids
// having every constructor accept the Store as a separate
// argument.
func (r *Registry) Store() *Store { return r.store }

// HTTP returns the shared *http.Client. Same rationale as Store —
// driver constructors pull the client from the registry rather than
// having NewServer pass it twice.
func (r *Registry) HTTP() *http.Client { return r.http }

// Clock returns the Clock dependency. The device-code driver
// (task 3.5) reads this to advance its poller deadline.
func (r *Registry) Clock() Clock { return r.clock }

// refreshWithSink is the canonical Driver.Refresh body: every
// per-flow Refresh delegates here so the Requirements 10.1–10.4
// protocol lives in exactly one place.
//
// The protocol:
//
//  1. Acquire the Token_Sink mutex for key. Concurrent in-process
//     callers of the same key serialize on the sink so only one
//     upstream refresh fires per profile (Requirement 10.1).
//  2. Re-read the profile from Store.Get. A previous holder may
//     have already refreshed and persisted while we were waiting,
//     in which case exchange's caller can short-circuit by
//     returning the input profile unchanged (Requirement 10.2).
//  3. Call exchange(currentProfile). The driver-supplied callback
//     POSTs the upstream token endpoint, parses the response, and
//     returns either the new Profile or an error.
//  4. If exchange returned ErrInvalidGrant (or wraps it), set
//     RequiresReauth=true, persist, and return ErrReauthRequired
//     so the HTTP layer can surface 401 (Requirement 10.4).
//  5. On any other exchange error, return the error unchanged —
//     transient upstream failures should be retryable by the
//     caller without flipping RequiresReauth.
//  6. On success, persist the returned Profile via Store.Put while
//     still holding the sink (Requirement 10.3) and return it.
//
// If the profile no longer exists at step 2 (operator deleted it
// during the wait), refreshWithSink returns ErrProfileNotFound so
// the caller fails fast rather than refreshing a phantom record.
//
// Validates: Requirements 10.1, 10.2, 10.3, 10.4.
func refreshWithSink(
	ctx context.Context,
	store *Store,
	key string,
	exchange func(Profile) (Profile, error),
) (Profile, error) {
	if store == nil {
		return Profile{}, fmt.Errorf("auth: refreshWithSink: nil store")
	}
	if store.sink == nil {
		// Defensive: NewStore always wires the sink, but a
		// future construction site that bypasses NewStore (or a
		// zero-value Store in a test) would otherwise panic on
		// the acquire call below. Surfacing the misuse as an
		// error rather than a nil-pointer panic makes the
		// failure mode debuggable.
		return Profile{}, fmt.Errorf("auth: refreshWithSink: store has no token sink")
	}

	// Step 1 — serialize concurrent in-process refreshes for this
	// key. The sink hand-off pattern is documented on
	// TokenSink.acquire; we hold m for the entire critical
	// section so step 6's Put completes before another caller
	// observes a stale UpdatedAt.
	m := store.sink.acquire(key)
	defer m.Unlock()

	// Step 2 — re-read under the sink. Another goroutine may have
	// already refreshed while we waited; exchange decides whether
	// to short-circuit by returning current unchanged.
	current, ok, err := store.Get(ctx, key)
	if err != nil {
		return Profile{}, err
	}
	if !ok {
		return Profile{}, fmt.Errorf("%w: %q", ErrProfileNotFound, key)
	}

	// Step 3 — driver-supplied upstream exchange. The callback is
	// expected to POST the token endpoint, parse the JSON
	// response, and return a Profile carrying the rotated
	// AccessToken / RefreshToken / ExpiresAt.
	next, err := exchange(current)
	if err != nil {
		// Step 4 — invalid_grant: mark requires_reauth and
		// surface ErrReauthRequired (Requirement 10.4).
		if errors.Is(err, ErrInvalidGrant) {
			current.RequiresReauth = true
			// Persist the marked profile so the dashboard
			// (and any concurrent caller that re-reads
			// after we release the sink) sees the
			// requires_reauth flag. A Put failure here is
			// non-fatal — we still want the caller to see
			// ErrReauthRequired — but we surface the Put
			// error wrapped so log readers can see why
			// the persistence failed.
			if perr := store.Put(ctx, current); perr != nil {
				return current, fmt.Errorf("auth: persist requires_reauth: %w (after %w)", perr, ErrReauthRequired)
			}
			return current, ErrReauthRequired
		}
		// Step 5 — any other error is returned unchanged. The
		// caller (typically the LLM client) decides whether to
		// retry; we do NOT flip RequiresReauth on transient
		// network failures.
		return current, err
	}

	// Step 6 — persist the rotated profile while still holding
	// the sink so a concurrent acquire that runs immediately
	// after our Unlock observes the new tokens via Store.Get
	// rather than racing another upstream refresh.
	if err := store.Put(ctx, next); err != nil {
		return next, fmt.Errorf("auth: persist refreshed profile: %w", err)
	}
	return next, nil
}
