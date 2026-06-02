package billing

// File webhook_handler_test.go covers the public surface of task 4.5
// without booting Postgres: the WebhookQuerier interface lets tests
// supply an in-memory ledger that mimics the
// `INSERT … ON CONFLICT (event_id) DO NOTHING RETURNING event_id` shape
// the production wiring relies on.
//
// Coverage matrix (Requirements 5.3, 5.4):
//
//   - good signature  → insert wins → applyEvent called once → 204
//   - bad signature   → 401, no insert, no applyEvent
//   - replayed event  → 204, applyEvent NOT called the second time
//   - missing event.id → 400, no insert, no applyEvent
//   - constructor validation: empty webhook key, nil querier
//   - signature helper accepts hex / base64 / standardwebhooks "v1,<b64>"
//
// Validates: Requirements 5.3, 5.4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
)

// fakeRow implements pgx.Row by replaying a fixed set of column values
// (or returning pgx.ErrNoRows). The handler only ever requests one
// column from `RETURNING event_id`, so we only need to support a single
// string destination.
type fakeRow struct {
	value string
	err   error
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("fakeRow: expected exactly one destination")
	}
	p, ok := dest[0].(*string)
	if !ok {
		return errors.New("fakeRow: expected *string destination")
	}
	*p = r.value
	return nil
}

// fakeQuerier is an in-memory analogue of the dodo_webhook_events
// ledger keyed on event_id. It records every write in order so tests
// can assert the exact wire shape the handler used.
type fakeQuerier struct {
	mu     sync.Mutex
	rows   map[string][]byte // event_id -> raw payload
	calls  []fakeQuery
	failOn string // when set, QueryRow returns a row that Scans this error
	failErr error
}

type fakeQuery struct {
	sql       string
	eventID   string
	eventType string
	payload   []byte
}

func newFakeQuerier() *fakeQuerier {
	return &fakeQuerier{rows: make(map[string][]byte)}
}

func (f *fakeQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(args) != 3 {
		return &fakeRow{err: errors.New("fakeQuerier: expected 3 args")}
	}
	id, _ := args[0].(string)
	typ, _ := args[1].(string)
	payload, _ := args[2].([]byte)

	f.calls = append(f.calls, fakeQuery{
		sql:       sql,
		eventID:   id,
		eventType: typ,
		payload:   append([]byte(nil), payload...),
	})

	if f.failOn != "" && id == f.failOn {
		return &fakeRow{err: f.failErr}
	}

	if _, exists := f.rows[id]; exists {
		// Mirrors `ON CONFLICT (event_id) DO NOTHING RETURNING event_id`:
		// no row is returned, so Scan reports pgx.ErrNoRows.
		return &fakeRow{err: pgx.ErrNoRows}
	}
	f.rows[id] = append([]byte(nil), payload...)
	return &fakeRow{value: id}
}

// signBody signs body with the shared HMAC key and returns the
// hex-encoded digest, which is the simplest accepted form per
// verifyDodoSignature.
func signBody(t *testing.T, key, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestNewWebhookHandler_ValidatesConfig(t *testing.T) {
	t.Parallel()

	t.Run("empty webhook key", func(t *testing.T) {
		t.Parallel()
		_, err := NewWebhookHandler(WebhookHandlerConfig{
			WebhookKey: "  ",
			Querier:    newFakeQuerier(),
		})
		if !errors.Is(err, ErrWebhookKeyMissing) {
			t.Fatalf("err = %v, want errors.Is ErrWebhookKeyMissing", err)
		}
	})

	t.Run("nil querier", func(t *testing.T) {
		t.Parallel()
		_, err := NewWebhookHandler(WebhookHandlerConfig{
			WebhookKey: "secret",
		})
		if !errors.Is(err, ErrWebhookQuerierMissing) {
			t.Fatalf("err = %v, want errors.Is ErrWebhookQuerierMissing", err)
		}
	})
}

func TestWebhookHandler_GoodSignature_CallsApplyOnce(t *testing.T) {
	t.Parallel()

	key := []byte("dodo-test-key")
	q := newFakeQuerier()

	var applies int32
	var seenID string
	apply := func(_ context.Context, ev Event) error {
		atomic.AddInt32(&applies, 1)
		seenID = ev.ID
		if ev.Type == "" {
			t.Errorf("apply received empty event type")
		}
		if len(ev.Raw) == 0 {
			t.Errorf("apply received empty raw payload")
		}
		return nil
	}

	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: string(key),
		Querier:    q,
		Apply:      apply,
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	body := []byte(`{"id":"evt_001","type":"subscription.active","data":{"id":"sub_42"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/billing/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeaderName, signBody(t, key, body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := atomic.LoadInt32(&applies); got != 1 {
		t.Fatalf("apply call count = %d, want 1", got)
	}
	if seenID != "evt_001" {
		t.Fatalf("apply saw event id %q, want evt_001", seenID)
	}
	if len(q.calls) != 1 {
		t.Fatalf("ledger insert calls = %d, want 1", len(q.calls))
	}
	if q.calls[0].eventID != "evt_001" || q.calls[0].eventType != "subscription.active" {
		t.Fatalf("ledger row = %+v", q.calls[0])
	}
	if string(q.calls[0].payload) != string(body) {
		t.Fatalf("ledger payload = %q, want %q", q.calls[0].payload, body)
	}
}

func TestWebhookHandler_BadSignature_Returns401AndDoesNotInsert(t *testing.T) {
	t.Parallel()

	key := []byte("dodo-test-key")
	q := newFakeQuerier()

	var applies int32
	apply := func(context.Context, Event) error {
		atomic.AddInt32(&applies, 1)
		return nil
	}

	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: string(key),
		Querier:    q,
		Apply:      apply,
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	body := []byte(`{"id":"evt_002","type":"subscription.canceled"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/billing/webhook", strings.NewReader(string(body)))
	// Sign with the WRONG key.
	req.Header.Set(signatureHeaderName, signBody(t, []byte("attacker-key"), body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := atomic.LoadInt32(&applies); got != 0 {
		t.Fatalf("apply call count = %d, want 0", got)
	}
	if len(q.calls) != 0 {
		t.Fatalf("ledger insert calls = %d, want 0", len(q.calls))
	}
}

func TestWebhookHandler_MissingSignature_Returns401(t *testing.T) {
	t.Parallel()

	key := []byte("dodo-test-key")
	q := newFakeQuerier()

	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: string(key),
		Querier:    q,
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	body := []byte(`{"id":"evt_no_sig","type":"subscription.active"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/billing/webhook", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(q.calls) != 0 {
		t.Fatalf("ledger insert calls = %d, want 0", len(q.calls))
	}
}

func TestWebhookHandler_ReplayedEvent_AcksWithoutReapplying(t *testing.T) {
	t.Parallel()

	key := []byte("dodo-test-key")
	q := newFakeQuerier()

	var applies int32
	apply := func(context.Context, Event) error {
		atomic.AddInt32(&applies, 1)
		return nil
	}

	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: string(key),
		Querier:    q,
		Apply:      apply,
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	body := []byte(`{"id":"evt_replay","type":"invoice.paid"}`)
	sig := signBody(t, key, body)

	deliver := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/internal/billing/webhook", strings.NewReader(string(body)))
		req.Header.Set(signatureHeaderName, sig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := deliver()
	if first.Code != http.StatusNoContent {
		t.Fatalf("first delivery status = %d, want %d", first.Code, http.StatusNoContent)
	}

	second := deliver()
	if second.Code != http.StatusNoContent {
		t.Fatalf("replay status = %d, want %d", second.Code, http.StatusNoContent)
	}

	if got := atomic.LoadInt32(&applies); got != 1 {
		t.Fatalf("apply call count = %d, want 1 (replay must not re-apply)", got)
	}
	if len(q.calls) != 2 {
		t.Fatalf("ledger insert attempts = %d, want 2 (both deliveries try the insert)", len(q.calls))
	}
}

func TestWebhookHandler_MissingEventID_Returns400(t *testing.T) {
	t.Parallel()

	key := []byte("dodo-test-key")
	q := newFakeQuerier()

	var applies int32
	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: string(key),
		Querier:    q,
		Apply: func(context.Context, Event) error {
			atomic.AddInt32(&applies, 1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	body := []byte(`{"type":"subscription.active"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/billing/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeaderName, signBody(t, key, body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := atomic.LoadInt32(&applies); got != 0 {
		t.Fatalf("apply called on malformed payload (count=%d)", got)
	}
	if len(q.calls) != 0 {
		t.Fatalf("ledger insert calls = %d, want 0", len(q.calls))
	}
}

func TestWebhookHandler_RejectsNonPost(t *testing.T) {
	t.Parallel()

	q := newFakeQuerier()
	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: "secret",
		Querier:    q,
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/internal/billing/webhook", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow header = %q, want %q", got, http.MethodPost)
	}
}

func TestWebhookHandler_DispatcherFailure_Returns500(t *testing.T) {
	t.Parallel()

	key := []byte("dodo-test-key")
	q := newFakeQuerier()

	apply := func(context.Context, Event) error {
		return errors.New("downstream offline")
	}

	h, err := NewWebhookHandler(WebhookHandlerConfig{
		WebhookKey: string(key),
		Querier:    q,
		Apply:      apply,
	})
	if err != nil {
		t.Fatalf("NewWebhookHandler: %v", err)
	}

	body := []byte(`{"id":"evt_dispatch_fail","type":"subscription.active"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/billing/webhook", strings.NewReader(string(body)))
	req.Header.Set(signatureHeaderName, signBody(t, key, body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestVerifyDodoSignature_AcceptsCommonEncodings(t *testing.T) {
	t.Parallel()

	key := []byte("rotated-secret")
	body := []byte(`{"id":"evt_sig","type":"subscription.active"}`)
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	sum := mac.Sum(nil)

	cases := []struct {
		name   string
		header string
	}{
		{"hex", hex.EncodeToString(sum)},
		{"std base64", base64.StdEncoding.EncodeToString(sum)},
		{"raw std base64", base64.RawStdEncoding.EncodeToString(sum)},
		{"url base64", base64.URLEncoding.EncodeToString(sum)},
		{"raw url base64", base64.RawURLEncoding.EncodeToString(sum)},
		{"v1 prefix", "v1," + base64.StdEncoding.EncodeToString(sum)},
		{"rotation list", "v1,deadbeef v1," + base64.StdEncoding.EncodeToString(sum)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !verifyDodoSignature(body, tc.header, key) {
				t.Fatalf("signature %q rejected, want accepted", tc.header)
			}
		})
	}
}

func TestVerifyDodoSignature_RejectsMismatches(t *testing.T) {
	t.Parallel()

	key := []byte("real-key")
	body := []byte(`{"id":"evt","type":"x"}`)

	bad := []struct {
		name   string
		header string
	}{
		{"empty header", ""},
		{"junk hex", strings.Repeat("a", 64)},
		{"truncated", "abcd"},
		{"unknown scheme", "v2," + hex.EncodeToString(make([]byte, 32))},
	}

	for _, tc := range bad {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if verifyDodoSignature(body, tc.header, key) {
				t.Fatalf("signature %q accepted, want rejected", tc.header)
			}
		})
	}

	// Empty key always rejects, even when the digest math would line up.
	mac := hmac.New(sha256.New, []byte{})
	mac.Write(body)
	if verifyDodoSignature(body, hex.EncodeToString(mac.Sum(nil)), nil) {
		t.Fatalf("verifyDodoSignature accepted nil key")
	}
}
