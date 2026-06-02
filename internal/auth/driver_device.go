// Package auth — device_code OAuth driver implementing RFC 8628 on
// top of the cross-driver Driver contract.
//
// The device authorization grant has a two-step shape:
//
//  1. Start: POST e.DeviceAuthorizationEndpoint with client_id and
//     the joined scope list. The upstream returns
//     {device_code, user_code, verification_uri, expires_in,
//     interval}. The driver returns Mode="device" with the user-
//     facing user_code + verification_uri so the dashboard can
//     tell the operator "go to <uri> and enter <user_code>", and
//     kicks off a background poller goroutine.
//
//  2. Poll: every `interval` seconds (default 5s when the upstream
//     omits it — Requirement 7.2) the poller POSTs e.TokenEndpoint
//     with grant_type=urn:ietf:params:oauth:grant-type:device_code
//     and the device_code value. Three branches:
//
//     - 2xx with access_token → build OAuth_Profile, persist
//     via Store.Put (Requirement 7.4), signal done.
//     - 4xx body.error == "authorization_pending" → wait
//     interval and retry.
//     - 4xx body.error == "slow_down" → bump interval += 5s
//     and retry (Requirement 7.3).
//     - any other error → signal done with the wrapped error.
//
//     After expires_in elapses without a 2xx (per the catalog-
//     anchored deadline computed from clock.Now() at Start), the
//     poller stops and signals ErrFlowTimeout (Requirement 7.5).
//     The HTTP layer maps that sentinel to 408 "oauth flow timed
//     out".
//
// Cancellation: the poller honors ctx.Done() so a dashboard cancel
// (the request scope tied to /api/auth/profiles/oauth/start) can
// abort polling cleanly without waiting for the next tick.
//
// Refresh delegates to refreshWithSink with a standard
// grant_type=refresh_token exchange — same shape as the PKCE driver
// — so the Requirement 10.1–10.4 protocol stays in one place.
//
// The deviceCodeDriver accepts an injected Clock so tests can
// virtualize wall time when verifying the slow_down / expires_in
// timing properties (Wave H task 9.5). Production callers pass
// realClock (or nil → realClock) at construction.
//
// Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

const (
	// deviceCodeFlowName is the Catalog_Entry.flow value the
	// registry keys this driver under. Declared as a constant so
	// the value lives in exactly one place — Name() — and any
	// rename by the design team flows through a single edit.
	deviceCodeFlowName = "device_code"

	// deviceCodeGrantType is the RFC 8628 grant_type value the
	// poller submits to the token endpoint. Long form is fixed
	// by the spec; we keep it as a constant to avoid repeating
	// the magic string.
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// deviceCodeDefaultInterval is the fallback poll interval
	// when the device-authorization response omits `interval`
	// or returns a zero / negative value. Matches Requirement
	// 7.2's "defaulting to 5 seconds when no interval is
	// provided" clause.
	deviceCodeDefaultInterval = 5 * time.Second

	// deviceCodeSlowDownDelta is the additive bump applied to
	// the effective poll interval when the token endpoint
	// returns body.error == "slow_down" per Requirement 7.3.
	deviceCodeSlowDownDelta = 5 * time.Second

	// deviceCodeDefaultProfileID is the placeholder profileId
	// assigned to the OAuth_Profile persisted at the end of a
	// successful flow. Mirrors driver_pkce.go's
	// pkceDefaultProfileID — the dashboard renames the
	// resulting profile after persistence; this constant only
	// avoids collisions in Profile.Key on the initial Put.
	deviceCodeDefaultProfileID = "default"
)

// deviceCodeDriver is the per-flow handler for
// Catalog_Entry.flow="device_code".
//
// flows is keyed by FlowID and owns every in-flight deviceFlow
// value; entries are inserted in Start and removed by stopFlow on
// completion / timeout / cancel. sync.Map is used for the same
// read-mostly reasons as in pkceDriver.
type deviceCodeDriver struct {
	store *Store
	http  *http.Client
	clock Clock
	flows sync.Map // flowID → *deviceFlow
}

// deviceFlow captures the state the poller goroutine needs to
// finalize a single device-code authorization. Field meanings:
//
//   - deviceCode: the upstream-issued device_code submitted on
//     every poll. Held only in memory — never persisted.
//   - interval: the EFFECTIVE current poll interval. Updated in
//     place when the token endpoint returns slow_down so the
//     poller observes the bumped value on the next tick.
//   - expiresAt: the absolute deadline at which the poller stops
//     and signals ErrFlowTimeout. Computed from clock.Now() +
//     response.expires_in at Start, so a virtualized clock in
//     tests advances the deadline deterministically.
//   - done: capacity-1 channel signalfor "the flow finalized". The
//     value sent is nil on success, ErrFlowTimeout on the
//     deadline, or the wrapped exchange error otherwise. Buffered
//     so the goroutine does not block on send when no one is
//     waiting.
//   - profile: the persisted Profile when the flow succeeded.
//     Zero-valued otherwise. Held on the struct so a future
//     Complete-style "wait for flow" surface can return the
//     profile to the dashboard.
//   - cancel: the CancelFunc tied to the poller's lifetime. The
//     stopFlow path calls it so a Stop racing with a slow
//     network exchange doesn't wait the full interval.
//   - cleanup: ensures the goroutine teardown (cancel, channel
//     close, map delete) runs at most once even when both the
//     deadline and a Stop call race to expire the same flow.
//   - flowID: kept on the struct so the poller can identify the
//     entry without piping the id through every closure.
type deviceFlow struct {
	deviceCode string
	interval   time.Duration
	expiresAt  time.Time
	done       chan error
	profile    Profile

	cancel  context.CancelFunc
	cleanup sync.Once
	flowID  string
}

// deviceAuthorizationResponse models the RFC 8628 §3.2 device-
// authorization response body. Field-level json tags follow the
// spec spelling. We accept verification_uri_complete (provider
// extension common in modern OAuth servers) but do not surface
// it on StartResult — the dashboard renders user_code +
// verification_uri verbatim.
type deviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// deviceTokenResponse models the OAuth 2.0 token-endpoint success
// response (RFC 6749 §5.1). Identical in shape to the response
// the PKCE driver expects — declared separately so the device
// driver does not depend on pkceTokenResponse and can evolve
// independently.
type deviceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// expiresAt converts the relative expires_in into an absolute UTC
// timestamp anchored to wall-clock now (using the driver's
// injected Clock so tests can virtualize). Returns zero Time when
// expires_in is unspecified — Profile.ExpiresAt's omitempty json
// tag elides the field in that case.
func (t deviceTokenResponse) expiresAt(now time.Time) time.Time {
	if t.ExpiresIn <= 0 {
		return time.Time{}
	}
	return now.UTC().Add(time.Duration(t.ExpiresIn) * time.Second)
}

// deviceTokenError models the RFC 6749 §5.2 error response body.
// We branch on Error to detect authorization_pending, slow_down,
// and invalid_grant; ErrorDescription is captured for log
// readability only.
type deviceTokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// newDeviceCodeDriver constructs a deviceCodeDriver bound to the
// supplied Profile_Store, *http.Client, and Clock. Per the task
// brief, drivers are constructed standalone (not via NewRegistry)
// so the constructor accepts the Clock as an explicit parameter
// instead of pulling it from a registry.
//
// nil httpClient defaults to http.DefaultClient and nil clock
// defaults to realClock so a minimal test harness can construct
// the driver with newDeviceCodeDriver(store, nil, nil) without
// preassembling either dependency.
func newDeviceCodeDriver(store *Store, httpClient *http.Client, clock Clock) *deviceCodeDriver {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if clock == nil {
		clock = realClock{}
	}
	return &deviceCodeDriver{
		store: store,
		http:  httpClient,
		clock: clock,
	}
}

// Name returns the matching Catalog_Entry.flow value. Registry
// uses this string as the lookup key.
func (d *deviceCodeDriver) Name() string { return deviceCodeFlowName }

// Start kicks off a device-code flow. Steps:
//
//  1. POST e.DeviceAuthorizationEndpoint with client_id, scope,
//     and audience (when set). RFC 8628 §3.1 specifies form-
//     encoded params on the device-authorization endpoint.
//  2. Decode the response. Default Interval to 5s when zero or
//     missing (Requirement 7.2).
//  3. Compute the absolute deadline = clock.Now() + expires_in.
//  4. Spawn the poller goroutine, register the flow, and return
//     Mode="device" with UserCode + VerificationURI (Requirement
//     7.1).
//
// Honors ctx (the request scope) by deriving a child cancel
// context for the poller — when the request scope is canceled
// (dashboard cancel), the poller observes ctx.Done() on its
// next tick and stops cleanly.
//
// Validates: Requirements 7.1, 7.2.
func (d *deviceCodeDriver) Start(ctx context.Context, e providers.Entry, opts StartOptions) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	if e.DeviceAuthorizationEndpoint == "" {
		return StartResult{}, fmt.Errorf("auth: device_code: catalog entry %q has no deviceAuthorizationEndpoint", e.ID)
	}
	if e.TokenEndpoint == "" {
		return StartResult{}, fmt.Errorf("auth: device_code: catalog entry %q has no tokenEndpoint", e.ID)
	}

	flowID, err := newDeviceFlowID()
	if err != nil {
		return StartResult{}, fmt.Errorf("auth: device_code: generate flow id for entry %q: %w", e.ID, err)
	}

	devResp, err := d.requestDeviceCode(ctx, e)
	if err != nil {
		return StartResult{}, err
	}

	// Default the poll interval per Requirement 7.2. Negative
	// values from a misbehaving upstream are also coerced to
	// the default — a non-positive interval would otherwise
	// busy-loop the poller.
	interval := time.Duration(devResp.Interval) * time.Second
	if interval <= 0 {
		interval = deviceCodeDefaultInterval
	}

	// Compute the absolute deadline using the injected Clock so
	// test code can advance virtualized time and observe the
	// timeout deterministically. expires_in <= 0 is treated as
	// "no upper bound advertised" — fall back to a generous 30
	// minutes so a misbehaving upstream cannot pin a flow
	// forever; in practice every conforming RFC 8628 server
	// returns a positive expires_in.
	expiresIn := time.Duration(devResp.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 30 * time.Minute
	}
	expiresAt := d.clock.Now().UTC().Add(expiresIn)

	// Derive a cancel context for the poller. The poller
	// observes both the request scope (ctx) AND its own
	// internal cancel (driven by stopFlow). We do NOT inherit
	// ctx directly because the request scope is typically the
	// HTTP handler's scope, which is canceled when the
	// response is flushed — the poller must outlive that.
	// Instead the poller respects ctx.Done() at each tick so a
	// long-lived dashboard scope can still cancel polling.
	pollerCtx, cancel := context.WithCancel(context.Background())

	flow := &deviceFlow{
		deviceCode: devResp.DeviceCode,
		interval:   interval,
		expiresAt:  expiresAt,
		done:       make(chan error, 1),
		cancel:     cancel,
		flowID:     flowID,
	}
	d.flows.Store(flowID, flow)

	// Spawn the poller. The goroutine owns flow's mutable
	// fields after Start returns — only the poller writes to
	// flow.interval / flow.profile, so no further locking is
	// needed inside the goroutine. Concurrent readers (the
	// stopFlow path) only inspect immutable fields (flowID,
	// done, cancel) plus the cleanup sync.Once which is
	// inherently safe.
	go d.poll(pollerCtx, ctx, e, flow)

	return StartResult{
		FlowID:          flowID,
		Mode:            "device",
		UserCode:        devResp.UserCode,
		VerificationURI: devResp.VerificationURI,
		ExpiresAt:       expiresAt,
	}, nil
}

// Complete is not used by the device-code flow — finalization
// happens in the background poller spawned at Start. The HTTP
// layer (Wave E task 5.2) does not route device-code completions
// through this method. Returning a clear error keeps the Driver
// contract uniform: any code path that mistakenly invokes
// Complete on a device-code flow gets an actionable message
// rather than a silent no-op.
//
// The error is intentionally not one of the shared sentinels
// (ErrFlowTimeout / ErrInvalidGrant / etc.) — those denote
// upstream-condition failures, while this is a programmer-error
// surface. A future task that wants to add a "wait for status"
// surface to device-code can replace this with a select on
// flow.done.
func (d *deviceCodeDriver) Complete(ctx context.Context, e providers.Entry, in CompleteInput) (Profile, error) {
	return Profile{}, fmt.Errorf("auth: device_code: Complete not supported; check Start status (flow %q)", in.FlowID)
}

// Refresh rotates the access token via refreshWithSink, mirroring
// the PKCE driver's exchangeRefresh shape. The exchange callback
// POSTs grant_type=refresh_token at e.TokenEndpoint and translates
// invalid_grant into ErrInvalidGrant so the shared helper can
// apply the Requirement 10.4 protocol (RequiresReauth=true +
// ErrReauthRequired surfaced to the caller).
//
// Validates: Requirements 10.1, 10.2, 10.3, 10.4.
func (d *deviceCodeDriver) Refresh(ctx context.Context, p Profile, e providers.Entry) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	return refreshWithSink(ctx, d.store, p.Key(), func(current Profile) (Profile, error) {
		if current.RefreshToken == "" {
			// No refresh token issued at flow start — the
			// operator must run the device-code flow again.
			// Surface as invalid_grant so refreshWithSink
			// applies the standard re-auth translation.
			return Profile{}, ErrInvalidGrant
		}
		if e.TokenEndpoint == "" {
			return Profile{}, fmt.Errorf("auth: device_code: catalog entry %q has no tokenEndpoint", e.ID)
		}

		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", current.RefreshToken)
		if e.ClientID != "" {
			form.Set("client_id", e.ClientID)
		}

		tok, err := d.postTokenForm(ctx, e.TokenEndpoint, form)
		if err != nil {
			return Profile{}, err
		}

		next := current
		next.AccessToken = tok.AccessToken
		if tok.RefreshToken != "" {
			next.RefreshToken = tok.RefreshToken
		}
		if tok.TokenType != "" {
			next.TokenType = tok.TokenType
		}
		if tok.ExpiresIn > 0 {
			next.ExpiresAt = d.clock.Now().UTC().Add(time.Duration(tok.ExpiresIn) * time.Second)
		}
		if tok.Scope != "" {
			next.Scopes = strings.Fields(tok.Scope)
		}
		// Successful refresh clears any previously-set
		// requires_reauth flag — the credential is good again.
		next.RequiresReauth = false
		return next, nil
	})
}

// poll drives the RFC 8628 polling loop. It runs as a single
// goroutine spawned by Start and exits in one of three cases:
//
//   - success: token endpoint returned a 2xx with access_token.
//     The poller persists the profile via Store.Put and signals
//     done with nil.
//   - timeout: clock.Now() crossed flow.expiresAt before any 2xx
//     was observed. Signals done with ErrFlowTimeout
//     (Requirement 7.5).
//   - error: any non-pending / non-slow_down upstream error or a
//     cancel from pollerCtx / reqCtx. Signals done with the
//     wrapped error.
//
// Between ticks the poller blocks on a select over the timer,
// reqCtx.Done(), and pollerCtx.Done() so cancellation observes
// at most one interval of latency.
//
// Validates: Requirements 7.2, 7.3, 7.4, 7.5.
func (d *deviceCodeDriver) poll(pollerCtx, reqCtx context.Context, e providers.Entry, flow *deviceFlow) {
	// First, an immediate sleep before the first poll: RFC 8628
	// recommends waiting `interval` seconds before the very
	// first request to avoid hammering the upstream while the
	// operator is still navigating to the verification URI.
	for {
		// Compute the remaining time before the deadline. If
		// the next tick would land after the deadline, clamp
		// the wait so we observe the timeout precisely.
		now := d.clock.Now()
		if !now.Before(flow.expiresAt) {
			d.finishFlow(flow, ErrFlowTimeout)
			return
		}
		wait := flow.interval
		if remaining := flow.expiresAt.Sub(now); remaining < wait {
			wait = remaining
		}

		// Block until either the wait elapses, the request
		// scope is canceled (dashboard cancel — Requirement
		// 7.x cancellation clause), or the poller context is
		// canceled (stopFlow). time.NewTimer over time.After
		// so we can Stop() the timer on early exit and avoid
		// leaking a goroutine when the test clock advances
		// rapidly. M9: a tiny helper guarantees timer.Stop()
		// runs on every exit (success path included) via
		// defer; previously the timer.C branch leaked the
		// timer's underlying entry until the runtime GC ran.
		event := awaitDevicePollWait(reqCtx, pollerCtx, wait)
		switch event.kind {
		case devicePollWaitElapsed:
			// fall through to the poll below.
		case devicePollWaitReqDone:
			d.finishFlow(flow, reqCtx.Err())
			return
		case devicePollWaitPollerDone:
			// stopFlow already finalized the cleanup — just
			// exit. finishFlow is idempotent via sync.Once
			// but calling it here would race with the
			// stopFlow caller, so we trust the cancel
			// signal and return without touching done.
			return
		}

		// Re-check the deadline after waking — clock could
		// have advanced past it during the sleep.
		if !d.clock.Now().Before(flow.expiresAt) {
			d.finishFlow(flow, ErrFlowTimeout)
			return
		}

		tok, action, err := d.pollOnce(pollerCtx, e, flow.deviceCode)
		switch action {
		case devicePollSuccess:
			prof, perr := d.persistProfile(pollerCtx, e, tok)
			if perr != nil {
				d.finishFlow(flow, perr)
				return
			}
			flow.profile = prof
			d.finishFlow(flow, nil)
			return
		case devicePollPending:
			// Authorization is still pending — the operator
			// has not completed the consent screen yet.
			// Loop and wait the next interval.
			continue
		case devicePollSlowDown:
			// Upstream asked us to back off. Bump the
			// effective interval and loop. Per RFC 8628
			// §3.5, slow_down callers should add 5 seconds
			// to the polling interval (Requirement 7.3).
			flow.interval += deviceCodeSlowDownDelta
			continue
		case devicePollExpired:
			// Upstream signaled expired_token. Treat the
			// same as the local deadline timeout so the
			// HTTP layer surfaces a single 408 envelope.
			d.finishFlow(flow, ErrFlowTimeout)
			return
		default: // devicePollError
			d.finishFlow(flow, err)
			return
		}
	}
}

// devicePollAction enumerates the possible outcomes of a single
// poll iteration. Used to drive the switch in poll() without
// passing a sentinel error for every branch — pending and
// slow_down are not errors so much as control signals.
type devicePollAction int

const (
	devicePollError    devicePollAction = iota // err carries the cause
	devicePollSuccess                          // tok is populated
	devicePollPending                          // wait interval and retry
	devicePollSlowDown                         // bump interval, then retry
	devicePollExpired                          // upstream-side deadline hit
)

// pollOnce performs a single token-endpoint POST and classifies
// the response into a devicePollAction. Returning the action
// rather than encoding pending/slow_down as errors keeps the poll
// loop readable: each branch in the caller's switch corresponds
// to a single named control flow.
func (d *deviceCodeDriver) pollOnce(ctx context.Context, e providers.Entry, deviceCode string) (deviceTokenResponse, devicePollAction, error) {
	form := url.Values{}
	form.Set("grant_type", deviceCodeGrantType)
	form.Set("device_code", deviceCode)
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}

	tok, err := d.postTokenForm(ctx, e.TokenEndpoint, form)
	if err == nil {
		return tok, devicePollSuccess, nil
	}

	// Detect the RFC 8628 control errors. authorization_pending
	// and slow_down are wrapped in a typed deviceControlError
	// returned by postTokenForm so we can branch without
	// re-parsing the upstream body.
	var ctrl *deviceControlError
	if errors.As(err, &ctrl) {
		switch ctrl.code {
		case "authorization_pending":
			return deviceTokenResponse{}, devicePollPending, nil
		case "slow_down":
			return deviceTokenResponse{}, devicePollSlowDown, nil
		case "expired_token":
			return deviceTokenResponse{}, devicePollExpired, nil
		}
	}
	return deviceTokenResponse{}, devicePollError, err
}

// deviceControlError wraps the RFC 8628 control responses
// (authorization_pending, slow_down, expired_token, access_denied)
// so pollOnce can branch via errors.As without re-parsing the
// body. Other token-endpoint errors are returned as plain
// fmt.Errorf-wrapped values.
type deviceControlError struct {
	code        string
	description string
	statusCode  int
}

func (e *deviceControlError) Error() string {
	if e.description != "" {
		return fmt.Sprintf("auth: device_code: token endpoint status %d: %s (%s)", e.statusCode, e.code, e.description)
	}
	return fmt.Sprintf("auth: device_code: token endpoint status %d: %s", e.statusCode, e.code)
}

// requestDeviceCode performs the RFC 8628 §3.1 device-
// authorization request and decodes the response. Form fields
// per the spec: client_id (required), scope (when the catalog
// entry advertises any scopes). audience is included when set
// since some vendors (Auth0, Keycloak) require it on the device
// endpoint, not just the token endpoint.
//
// Non-2xx responses are wrapped with the upstream status — there
// is no RFC 8628 control-error shape at this stage (those only
// apply to the token-endpoint poll), so any non-2xx is a hard
// failure that aborts Start.
func (d *deviceCodeDriver) requestDeviceCode(ctx context.Context, e providers.Entry) (deviceAuthorizationResponse, error) {
	form := url.Values{}
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}
	if len(e.Scopes) > 0 {
		form.Set("scope", strings.Join(e.Scopes, " "))
	}
	if e.Audience != "" {
		form.Set("audience", e.Audience)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: build device-auth request for entry %q: %w", e.ID, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: device-auth POST for entry %q: %w", e.ID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: read device-auth response for entry %q: %w", e.ID, err)
	}

	if resp.StatusCode/100 != 2 {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: device-auth endpoint for entry %q returned status %d: %s", e.ID, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var dr deviceAuthorizationResponse
	if jerr := json.Unmarshal(body, &dr); jerr != nil {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: decode device-auth response for entry %q: %w", e.ID, jerr)
	}
	if dr.DeviceCode == "" {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: device-auth response for entry %q missing device_code", e.ID)
	}
	if dr.UserCode == "" || dr.VerificationURI == "" {
		return deviceAuthorizationResponse{}, fmt.Errorf("auth: device_code: device-auth response for entry %q missing user_code or verification_uri", e.ID)
	}
	return dr, nil
}

// postTokenForm POSTs the form-encoded body to endpoint and
// decodes the response. The non-2xx classification is:
//
//   - body.error in {authorization_pending, slow_down,
//     expired_token, access_denied} → return *deviceControlError
//     so callers can branch via errors.As.
//   - body.error == "invalid_grant" → return ErrInvalidGrant so
//     refreshWithSink can apply the Requirement 10.4 protocol on
//     the Refresh path.
//   - any other non-2xx → wrap with the upstream status code and
//     return a plain error.
//
// The 1MiB cap on response body reads is defensive — token
// endpoints return a few hundred bytes at most; capping protects
// xalgorix from a misbehaving upstream that streams unbounded
// data.
func (d *deviceCodeDriver) postTokenForm(ctx context.Context, endpoint string, form url.Values) (deviceTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return deviceTokenResponse{}, fmt.Errorf("auth: device_code: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return deviceTokenResponse{}, fmt.Errorf("auth: device_code: token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return deviceTokenResponse{}, fmt.Errorf("auth: device_code: read token response: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		var te deviceTokenError
		_ = json.Unmarshal(body, &te)
		switch te.Error {
		case "authorization_pending", "slow_down", "expired_token", "access_denied":
			return deviceTokenResponse{}, &deviceControlError{
				code:        te.Error,
				description: te.ErrorDescription,
				statusCode:  resp.StatusCode,
			}
		case "invalid_grant":
			return deviceTokenResponse{}, ErrInvalidGrant
		}
		if te.Error != "" {
			return deviceTokenResponse{}, fmt.Errorf("auth: device_code: token endpoint status %d: %s (%s)", resp.StatusCode, te.Error, te.ErrorDescription)
		}
		return deviceTokenResponse{}, fmt.Errorf("auth: device_code: token endpoint status %d", resp.StatusCode)
	}

	var tok deviceTokenResponse
	if jerr := json.Unmarshal(body, &tok); jerr != nil {
		return deviceTokenResponse{}, fmt.Errorf("auth: device_code: decode token response: %w", jerr)
	}
	if tok.AccessToken == "" {
		return deviceTokenResponse{}, fmt.Errorf("auth: device_code: token response missing access_token")
	}
	return tok, nil
}

// persistProfile builds the OAuth_Profile from a successful token
// response and commits it through Store.Put. The returned Profile
// is re-read from the store so its UpdatedAt reflects the on-disk
// timestamp; on a (theoretically impossible) re-read miss we fall
// back to the in-memory value rather than panicking.
//
// Validates: Requirement 7.4.
func (d *deviceCodeDriver) persistProfile(ctx context.Context, e providers.Entry, tok deviceTokenResponse) (Profile, error) {
	scopes := append([]string(nil), e.Scopes...)
	if tok.Scope != "" {
		scopes = strings.Fields(tok.Scope)
	}
	p := Profile{
		Provider:     e.ID,
		ProfileID:    deviceCodeDefaultProfileID,
		Type:         OAuth,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    tok.expiresAt(d.clock.Now()),
		Scopes:       scopes,
		TokenType:    tok.TokenType,
	}
	if err := d.store.Put(ctx, p); err != nil {
		return Profile{}, fmt.Errorf("auth: device_code: persist profile %s for entry %q: %w", p.Key(), e.ID, err)
	}
	fresh, ok, err := d.store.Get(ctx, p.Key())
	if err != nil {
		return Profile{}, fmt.Errorf("auth: device_code: re-read persisted profile: %w", err)
	}
	if !ok {
		return p, nil
	}
	log.Printf("auth: device_code persisted profile %s for entry %q", p.Key(), e.ID)
	return fresh, nil
}

// finishFlow signals the per-flow done channel and runs cleanup
// exactly once via sync.Once. The signal value is the supplied
// err (nil on success). Subsequent calls are no-ops, which is
// the desired behavior when both the deadline timer and a
// successful poll race to finalize the same flow.
//
// finishFlow does NOT delete the flow from d.flows. The flow
// stays registered until stopFlow is called by the HTTP layer
// (after it observes done) so that a late status query can still
// inspect flow.profile. A future "auto-reap" task can extend
// finishFlow to schedule a delayed delete; today the flow lives
// for the process lifetime once finalized, which is acceptable
// given the tiny per-flow footprint.
func (d *deviceCodeDriver) finishFlow(flow *deviceFlow, err error) {
	flow.cleanup.Do(func() {
		select {
		case flow.done <- err:
		default:
		}
		close(flow.done)
	})
}

// stopFlow is the cancel side: it cancels the poller's context
// (which unblocks any in-flight HTTP exchange) and runs cleanup.
// Used by tests and by a future HTTP-layer cancel surface.
//
// stopFlow is safe to call concurrently with the poller's
// finishFlow — the underlying sync.Once guarantees at most one
// signal on done, and the cancel is idempotent.
func (d *deviceCodeDriver) stopFlow(flowID string, reason error) {
	raw, ok := d.flows.LoadAndDelete(flowID)
	if !ok {
		return
	}
	flow, ok := raw.(*deviceFlow)
	if !ok {
		return
	}
	if flow.cancel != nil {
		flow.cancel()
	}
	d.finishFlow(flow, reason)
}

// newDeviceFlowID returns an opaque correlation id for a device-
// code flow. The "dev-" prefix lets log readers see at a glance
// which driver issued the id; the trailing 12-byte URL-safe
// base64 segment supplies ~72 bits of entropy, plenty for
// uniqueness within a dashboard session.
func newDeviceFlowID() (string, error) {
	var b [9]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "dev-" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Revoke implements auth.Revoker by POSTing the stored token to the
// catalog entry's RevocationEndpoint per RFC 7009. The fallback
// rules and error-tolerance are identical to pkceDriver.Revoke —
// see that method for the rationale; the device-code flow's tokens
// are otherwise indistinguishable from PKCE tokens at the wire
// level (RFC 6749 §5 success shape).
//
// Validates: H1 (best-effort revoke on delete).
func (d *deviceCodeDriver) Revoke(ctx context.Context, e providers.Entry, p Profile) error {
	endpoint := pkceRevocationEndpoint(e)
	if endpoint == "" {
		return nil
	}
	tokenHint := "refresh_token"
	token := p.RefreshToken
	if token == "" {
		token = p.AccessToken
		tokenHint = "access_token"
	}
	if token == "" {
		return nil
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", tokenHint)
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("auth: device_code: build revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("auth: device_code: revoke endpoint: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("auth: device_code: revoke endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// devicePollWaitOutcome enumerates the three ways the device-code
// poller's between-tick wait can resolve. The kind field selects
// the action poll() takes after the wait returns. Wrapping the
// select in a helper guarantees the timer's Stop() runs on every
// exit path (M9) — previously the timer.C branch leaked the
// underlying timer entry until the runtime GC reaped it.
type devicePollWaitOutcome struct {
	kind devicePollWaitKind
}

type devicePollWaitKind int

const (
	devicePollWaitElapsed devicePollWaitKind = iota
	devicePollWaitReqDone
	devicePollWaitPollerDone
)

// awaitDevicePollWait blocks for at most `wait` or until either
// scope is canceled, returning the outcome the caller can branch
// on. The defer'd timer.Stop releases the timer even on the
// elapsed branch.
func awaitDevicePollWait(reqCtx, pollerCtx context.Context, wait time.Duration) devicePollWaitOutcome {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return devicePollWaitOutcome{kind: devicePollWaitElapsed}
	case <-reqCtx.Done():
		return devicePollWaitOutcome{kind: devicePollWaitReqDone}
	case <-pollerCtx.Done():
		return devicePollWaitOutcome{kind: devicePollWaitPollerDone}
	}
}

// Compile-time assertion that *deviceCodeDriver satisfies the
// Driver interface. Mirrors the iface_check_test.go pattern used
// for the CatalogResolver assertion.
var _ Driver = (*deviceCodeDriver)(nil)
var _ Revoker = (*deviceCodeDriver)(nil)
