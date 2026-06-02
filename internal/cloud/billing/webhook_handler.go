package billing

// File webhook_handler.go implements task 4.5 of the xalgorix-saas spec —
// a Dodo Payments webhook endpoint with HMAC-SHA256 signature
// verification and an idempotency ledger keyed on `event.id`.
//
// Endpoint: POST /api/internal/billing/webhook (no auth — Dodo posts here)
//
// Behaviour mirrors design.md → "Billing Integration → Webhook handler":
//
//   1. Read the raw body up to 1 MiB.
//   2. Pull the `webhook-signature` header and verify HMAC-SHA256 over the
//      raw body using DODO_PAYMENTS_WEBHOOK_KEY (Config.WebhookKey).
//   3. On signature mismatch return HTTP 401, emit a structured
//      `webhook_signature_mismatch` log line, and DO NOT mutate state.
//   4. Decode the envelope JSON; reject payloads with no `event.id`.
//   5. Insert into `dodo_webhook_events (event_id, event_type, payload)`
//      with `ON CONFLICT (event_id) DO NOTHING RETURNING event_id`.
//      Only the row that wins the insert race applies the state mutation.
//      `received_at` falls back to the column DEFAULT (now()) so concurrent
//      inserts always get a sane timestamp without us racing the clock.
//   6. When the insert returns a row, dispatch to `applyEvent(ctx, event)`.
//      The dispatcher is a function field so the (still-stub) state
//      machine in task 4.6 can plug in without touching this file.
//   7. Return HTTP 204 on success — either the apply path or the
//      idempotent replay path (so Dodo stops retrying).
//
// Requirements: 5.3, 5.4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// maxWebhookBodyBytes caps inbound webhook bodies. Real Dodo events
// comfortably fit in a few KiB; 1 MiB matches the body limit applied
// by the API_Server middleware stack (design.md → "API surface").
const maxWebhookBodyBytes = 1 << 20

// signatureHeaderName is the header Dodo Payments uses to carry the
// HMAC-SHA256 digest. The case spelling matches the standardwebhooks
// convention used by the JS SDK in `BugReportly/lib/dodoPayments.js`.
const signatureHeaderName = "webhook-signature"

// Sentinel errors for webhook handler construction. Wrapped with %w so
// callers can errors.Is them.
var (
	// ErrWebhookKeyMissing is returned by NewWebhookHandler when
	// Config.WebhookKey is empty post-trim. Distinct from
	// ErrAPIKeyMissing because the operator may legitimately deploy
	// the API_Server without a webhook key (for outbound-only
	// environments) yet still want to fail hard at the moment a
	// webhook handler is constructed.
	ErrWebhookKeyMissing = errors.New("billing: DODO_PAYMENTS_WEBHOOK_KEY is not configured")
	// ErrWebhookQuerierMissing is returned when Config supplies no
	// database querier — the idempotency ledger cannot function
	// without one.
	ErrWebhookQuerierMissing = errors.New("billing: webhook querier is required")
	// ErrWebhookSignatureMismatch is the error logged (not returned to
	// the client) when the HMAC verification fails. Exporting it lets
	// integration tests assert on the typed cause.
	ErrWebhookSignatureMismatch = errors.New("billing: webhook signature mismatch")
	// ErrWebhookEventIDMissing is returned by parseEvent when the
	// envelope decodes successfully but carries no `event.id`.
	ErrWebhookEventIDMissing = errors.New("billing: webhook payload is missing event.id")
	// ErrWebhookEventTypeMissing is returned by parseEvent when the
	// envelope decodes successfully but carries no `event.type`.
	ErrWebhookEventTypeMissing = errors.New("billing: webhook payload is missing event.type")
)

// Event is the Dodo webhook envelope. It mirrors the standardwebhooks
// shape used by Dodo's hosted API: `id`, `type`, and a typed `data`
// payload that downstream dispatchers (task 4.6 onwards) decode further.
//
// Raw is intentionally unexported through the JSON tag (`-`) so the
// struct can be re-encoded without doubling the payload; the handler
// fills it from the verified raw body so the dispatcher and the ledger
// row both see the byte-identical payload that was signed.
type Event struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`

	// Raw is the verified raw JSON body. Not serialized.
	Raw json.RawMessage `json:"-"`
}

// EventDispatcher applies a single, verified, freshly-claimed Dodo
// webhook event to local state. It runs after the idempotency ledger
// has already accepted the event_id, so it MUST be called at most once
// per (event_id, replica) pair across the deployment.
//
// Returning a non-nil error causes the handler to respond with HTTP 500
// so Dodo retries the delivery. Because the ledger row was committed
// before the dispatcher ran, the retry will land on the replay path and
// will NOT re-invoke the dispatcher unless callers compensate (e.g. by
// deleting the ledger row on dispatcher failure). Tasks 4.6+ replace the
// stub dispatcher with the real subscription state machine, which is
// where any "delete-on-error" compensation belongs.
type EventDispatcher func(ctx context.Context, event Event) error

// WebhookQuerier is the subset of pgx required by the webhook handler.
// Both *pgxpool.Pool and pgx.Tx satisfy it, so the same handler can run
// against the raw pool (production wiring) or against a per-test fake
// (unit-test wiring) without an extra adapter type.
type WebhookQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// WebhookHandlerConfig wires NewWebhookHandler. Every field except
// Apply is required.
type WebhookHandlerConfig struct {
	// WebhookKey is the DODO_PAYMENTS_WEBHOOK_KEY used to verify
	// HMAC-SHA256 signatures. Trimmed of surrounding whitespace.
	WebhookKey string
	// Querier is the database handle the idempotency ledger writes
	// through. Production wiring passes a *pgxpool.Pool; tests pass a
	// fake.
	Querier WebhookQuerier
	// Apply is the dispatcher invoked on the row that wins the insert
	// race. When nil, NewWebhookHandler installs a no-op so the
	// handler is still functional during the Phase-4 stub period
	// before task 4.6 lands.
	Apply EventDispatcher
	// Logger is the zerolog instance to write structured audit-style
	// log lines to. When nil, NewWebhookHandler reads the per-request
	// logger from the request context (zerolog.Ctx).
	Logger *zerolog.Logger
}

// WebhookHandler is the http.Handler that processes inbound Dodo
// webhooks. It is safe for concurrent use; every method is read-only
// after NewWebhookHandler returns.
type WebhookHandler struct {
	webhookKey []byte
	querier    WebhookQuerier
	apply      EventDispatcher
	logger     *zerolog.Logger
}

// NewWebhookHandler validates cfg and returns a ready-to-mount handler.
// It rejects empty webhook keys and missing queriers eagerly so
// misconfiguration fails at boot instead of on the first webhook.
func NewWebhookHandler(cfg WebhookHandlerConfig) (*WebhookHandler, error) {
	key := strings.TrimSpace(cfg.WebhookKey)
	if key == "" {
		return nil, ErrWebhookKeyMissing
	}
	if cfg.Querier == nil {
		return nil, ErrWebhookQuerierMissing
	}
	apply := cfg.Apply
	if apply == nil {
		// Default no-op dispatcher. Task 4.6 replaces this with the
		// trialing → active → past_due → grace → downgraded state
		// machine.
		apply = func(context.Context, Event) error { return nil }
	}
	return &WebhookHandler{
		webhookKey: []byte(key),
		querier:    cfg.Querier,
		apply:      apply,
		logger:     cfg.Logger,
	}, nil
}

// NewWebhookHandlerFromPool is a convenience constructor for the
// production wiring in cmd/xalgorix-cloud. It binds a billing.Config and
// a *pgxpool.Pool to a WebhookHandler in one call, so the API_Server
// boot sequence does not need to know the WebhookHandlerConfig shape.
func NewWebhookHandlerFromPool(cfg Config, pool *pgxpool.Pool, apply EventDispatcher) (*WebhookHandler, error) {
	if pool == nil {
		return nil, errors.New("billing: pool must not be nil")
	}
	return NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: cfg.WebhookKey,
		Querier:    pool,
		Apply:      apply,
	})
}

// ServeHTTP implements http.Handler. The path is intended to be mounted
// at POST /api/internal/billing/webhook by the API_Server router (task
// 8.1); only POST is accepted.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBodyBytes))
	if err != nil {
		h.log(r.Context()).Warn().
			Err(err).
			Str("event", "webhook_body_read_failed").
			Msg("dodo webhook")
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}

	sig := r.Header.Get(signatureHeaderName)
	if !verifyDodoSignature(body, sig, h.webhookKey) {
		// Signature mismatch is the only path Requirement 5.4 names
		// explicitly: HTTP 401 with no state mutation, audit-style
		// log so the admin back-office can surface it.
		h.log(r.Context()).Warn().
			Str("event", "webhook_signature_mismatch").
			Int("body_bytes", len(body)).
			Msg("dodo webhook")
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}

	event, err := parseEvent(body)
	if err != nil {
		h.log(r.Context()).Warn().
			Err(err).
			Str("event", "webhook_payload_invalid").
			Msg("dodo webhook")
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}

	inserted, err := h.insertEvent(r.Context(), event)
	if err != nil {
		h.log(r.Context()).Error().
			Err(err).
			Str("event", "webhook_insert_failed").
			Str("event_id", event.ID).
			Msg("dodo webhook")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !inserted {
		// Idempotent replay path: another request already won the
		// insert race for this event_id. Per design.md ("Dodo webhook
		// ingestion") we still answer success so Dodo stops retrying.
		h.log(r.Context()).Info().
			Str("event", "webhook_replayed").
			Str("event_id", event.ID).
			Str("event_type", event.Type).
			Msg("dodo webhook")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.apply(r.Context(), event); err != nil {
		h.log(r.Context()).Error().
			Err(err).
			Str("event", "webhook_apply_failed").
			Str("event_id", event.ID).
			Str("event_type", event.Type).
			Msg("dodo webhook")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.log(r.Context()).Info().
		Str("event", "webhook_applied").
		Str("event_id", event.ID).
		Str("event_type", event.Type).
		Msg("dodo webhook")
	w.WriteHeader(http.StatusNoContent)
}

// insertEvent stamps the idempotency ledger row. Returns (true, nil)
// when this call won the insert race, (false, nil) when a row with the
// same event_id already exists, and (false, err) on any other database
// failure.
//
// We rely on `RETURNING event_id` together with the `ON CONFLICT … DO
// NOTHING` pattern: pgx surfaces "no row returned" as pgx.ErrNoRows on
// the Scan call, which is the unambiguous signal that the conflict
// branch fired.
func (h *WebhookHandler) insertEvent(ctx context.Context, ev Event) (bool, error) {
	const sqlInsert = `INSERT INTO dodo_webhook_events (event_id, event_type, payload)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING event_id`

	var got string
	err := h.querier.QueryRow(ctx, sqlInsert, ev.ID, ev.Type, []byte(ev.Raw)).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("billing: insert dodo_webhook_events: %w", err)
	}
	return true, nil
}

// log returns the logger to use for the current request: the explicit
// handler logger when set, otherwise the per-request logger threaded
// through the context by observability.LoggerMiddleware.
func (h *WebhookHandler) log(ctx context.Context) *zerolog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return zerolog.Ctx(ctx)
}

// parseEvent decodes the Dodo envelope and validates that both `id` and
// `type` are present. The raw body is preserved on the returned Event
// so insertEvent can persist it byte-identically to what was signed.
func parseEvent(raw []byte) (Event, error) {
	var ev Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return Event{}, fmt.Errorf("billing: decode webhook envelope: %w", err)
	}
	if strings.TrimSpace(ev.ID) == "" {
		return Event{}, ErrWebhookEventIDMissing
	}
	if strings.TrimSpace(ev.Type) == "" {
		return Event{}, ErrWebhookEventTypeMissing
	}
	// Take a defensive copy of raw so callers cannot mutate the slice
	// the handler later writes to the database.
	raw2 := make([]byte, len(raw))
	copy(raw2, raw)
	ev.Raw = raw2
	return ev, nil
}

// verifyDodoSignature checks an HMAC-SHA256 signature over body against
// the supplied header value, using key as the secret.
//
// The Dodo Payments hosted API has historically emitted the signature
// in any of these forms (the JS SDK in `BugReportly/lib/dodoPayments.js`
// hides this behind `client.webhooks.unwrap`):
//
//   - a lowercase hex digest of HMAC-SHA256(key, body)
//   - a base64 (standard or URL-safe, padded or not) digest
//   - a standardwebhooks-style "v1,<base64-digest>" form, possibly with
//     several space-separated values for key rotation
//
// To stay forward-compatible without taking a dependency on a
// third-party SDK we accept any of those shapes and treat the digest
// as valid as long as one of them constant-time-matches the HMAC of
// the body. Empty inputs always reject.
func verifyDodoSignature(body []byte, header string, key []byte) bool {
	header = strings.TrimSpace(header)
	if len(key) == 0 || header == "" {
		return false
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	sum := mac.Sum(nil)

	expectedHex := hex.EncodeToString(sum)
	expectedB64 := base64.StdEncoding.EncodeToString(sum)
	expectedRawB64 := base64.RawStdEncoding.EncodeToString(sum)
	expectedURLB64 := base64.URLEncoding.EncodeToString(sum)
	expectedRawURLB64 := base64.RawURLEncoding.EncodeToString(sum)

	for _, candidate := range strings.Fields(header) {
		// Strip a "v1," (or any "<scheme>,") prefix before comparing.
		// Only "v1" is recognised so attackers cannot smuggle a
		// future scheme name we do not support.
		if i := strings.IndexByte(candidate, ','); i >= 0 {
			scheme := strings.TrimSpace(candidate[:i])
			value := strings.TrimSpace(candidate[i+1:])
			if !strings.EqualFold(scheme, "v1") {
				continue
			}
			candidate = value
		}
		if constantTimeEqualString(candidate, expectedHex) ||
			constantTimeEqualString(candidate, expectedB64) ||
			constantTimeEqualString(candidate, expectedRawB64) ||
			constantTimeEqualString(candidate, expectedURLB64) ||
			constantTimeEqualString(candidate, expectedRawURLB64) {
			return true
		}
	}
	return false
}

// constantTimeEqualString compares a and b without leaking length-
// dependent timing differences once the lengths match. The early length
// check is fine because every candidate-vs-expected pair in
// verifyDodoSignature has a fixed expected length (HMAC-SHA256 output
// is 32 bytes); a length mismatch unambiguously means "not this
// encoding", not "this is the right encoding but with one wrong bit".
func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
