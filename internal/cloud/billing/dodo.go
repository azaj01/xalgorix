package billing

// File dodo.go implements task 4.2 of the xalgorix-saas spec: a thin REST
// facade over the Dodo Payments API. The official Go SDK
// (github.com/dodopayments/dodopayments-go) is not yet on the public Go
// module registry, so per the task brief we ship a placeholder client that
// speaks plain net/http + encoding/json while exposing the same method
// groups (Customers, Subscriptions, Invoices, CheckoutSessions) the SDK
// would. Subsequent phases (4.4 checkout, 4.5 webhook, 4.6 state machine,
// 4.8 proration, 4.9 seats, 4.10 overage) call into these groups; when the
// upstream SDK ships we can replace the bodies of the *Service methods
// without touching their callers.
//
// Design references:
//   - "Components and Interfaces → internal/cloud/billing → dodo.go"
//   - "Billing Integration (Dodo Payments) → Configuration"
//
// Requirements: 5.1, 5.2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Hosted endpoints picked when Config.BaseURL is empty. The exact URLs
// mirror the dodopayments JS SDK's environment switch (test_mode →
// test.dodopayments.com, live_mode → live.dodopayments.com). They are
// only used as defaults; deployments can override via DODO_PAYMENTS_BASE_URL.
const (
	defaultTestModeBaseURL = "https://test.dodopayments.com"
	defaultLiveModeBaseURL = "https://live.dodopayments.com"

	// defaultUserAgent identifies cloud traffic to Dodo so they can
	// distinguish our calls from the JS SDK in their logs.
	defaultUserAgent = "xalgorix-cloud/1.0 (billing)"

	// defaultRequestTimeout caps end-to-end time for any single Dodo
	// REST call. Webhooks come in over a separate path and are not
	// bounded by this value.
	defaultRequestTimeout = 30 * time.Second

	// maxResponseBytes guards the JSON decoder against pathological
	// upstream payloads. Real Dodo responses comfortably fit in 1 MiB.
	maxResponseBytes = 1 << 20
)

// Sentinel errors. Wrapped with %w by callers so errors.Is keeps working
// across the API boundary.
var (
	// ErrInvalidBaseURL is returned by NewClient when Config.BaseURL is
	// non-empty but cannot be parsed as an absolute http(s) URL.
	ErrInvalidBaseURL = errors.New("billing: BaseURL is not a valid absolute URL")
	// ErrUnexpectedStatus is returned when Dodo answers with a non-2xx
	// HTTP status. The wrapped error string includes the status code
	// and a trimmed snippet of the response body for diagnostics.
	ErrUnexpectedStatus = errors.New("billing: unexpected HTTP status from Dodo Payments")
	// ErrMissingID is returned by Get/Update/Cancel methods when the
	// caller supplies an empty resource identifier.
	ErrMissingID = errors.New("billing: resource id is required")
)

// Client is the top-level Dodo Payments REST facade. It is safe for use by
// concurrent goroutines because *http.Client is concurrency-safe and the
// service fields are immutable after NewClient returns.
//
// The unexported http / baseURL / apiKey fields keep the wire concerns
// internal; tests that need to inspect the wire shape do so through an
// httptest.Server pointed at by Config.BaseURL.
type Client struct {
	http      *http.Client
	baseURL   string
	apiKey    string
	userAgent string

	// Method groups. Modelled as separate types so callers write
	// `client.Subscriptions.Update(ctx, id, params)` — the same shape
	// the dodopayments-go SDK is expected to use, which keeps the
	// migration mechanical when the SDK lands.
	Customers        *CustomersService
	Subscriptions    *SubscriptionsService
	Invoices         *InvoicesService
	CheckoutSessions *CheckoutSessionsService
}

// NewClient constructs a Client from the resolved billing.Config produced
// by LoadConfig (task 4.1). It validates inputs eagerly so misconfiguration
// surfaces at boot rather than on the first API call.
//
// Validation rules:
//
//   - cfg.APIKey must be non-empty post trim → otherwise ErrAPIKeyMissing
//     (re-used from config.go to keep a single sentinel for callers).
//   - cfg.BaseURL, when non-empty, must parse as an absolute URL with both
//     scheme and host → otherwise ErrInvalidBaseURL.
//   - cfg.Environment must be EnvTestMode, EnvLiveMode, or empty (which is
//     treated as EnvTestMode for parity with LoadConfig's default branch).
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, ErrAPIKeyMissing
	}
	baseURL, err := resolveBaseURL(cfg)
	if err != nil {
		return nil, err
	}

	c := &Client{
		// A bespoke http.Client with a finite Timeout protects against
		// upstream stalls; leaving Timeout at zero would let Dodo hang
		// the request goroutine indefinitely.
		http: &http.Client{
			Timeout: defaultRequestTimeout,
		},
		baseURL:   baseURL,
		apiKey:    strings.TrimSpace(cfg.APIKey),
		userAgent: defaultUserAgent,
	}
	c.Customers = &CustomersService{c: c}
	c.Subscriptions = &SubscriptionsService{c: c}
	c.Invoices = &InvoicesService{c: c}
	c.CheckoutSessions = &CheckoutSessionsService{c: c}
	return c, nil
}

// resolveBaseURL applies the precedence rule from BugReportly's JS SDK
// helper: explicit BaseURL wins, otherwise pick the hosted URL for the
// configured environment.
func resolveBaseURL(cfg Config) (string, error) {
	if base := strings.TrimSpace(cfg.BaseURL); base != "" {
		u, err := url.Parse(base)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", fmt.Errorf("%w: %q", ErrInvalidBaseURL, base)
		}
		// Strip trailing slashes so callers can prepend "/customers"
		// etc. without producing "//" in request URLs.
		return strings.TrimRight(base, "/"), nil
	}
	switch cfg.Environment {
	case EnvLiveMode:
		return defaultLiveModeBaseURL, nil
	case EnvTestMode, "":
		return defaultTestModeBaseURL, nil
	default:
		return "", fmt.Errorf("%w: got %q", ErrUnknownEnvironment, cfg.Environment)
	}
}

// do is the shared transport for every method on every service. It
// centralises bearer-auth signing, JSON encode/decode, and status checks
// so each service method stays a one-liner.
//
// body is JSON-encoded when non-nil; out is JSON-decoded into when non-nil
// and the response carries a body. Either may be nil for fire-and-forget
// or HEAD-style calls.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("billing: encode request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("billing: build %s %s: %w", method, path, err)
	}
	// Bearer auth is the request signing scheme Dodo's hosted API uses.
	// The `webhook-signature` header is a separate concern handled in
	// task 4.5 (inbound) — outbound calls only need the bearer token.
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("billing: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("billing: read %s %s response: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Trim the body so we do not log enormous HTML error pages
		// when Dodo's edge returns a Cloudflare-style failure.
		snippet := strings.TrimSpace(string(respBody))
		if len(snippet) > 512 {
			snippet = snippet[:512] + "..."
		}
		return fmt.Errorf("%w: %d %s %s: %s", ErrUnexpectedStatus, resp.StatusCode, method, path, snippet)
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("billing: decode %s %s response: %w", method, path, err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------
// Domain types
// -----------------------------------------------------------------------
//
// Every domain struct uses `omitempty` so the JSON wire payload only carries
// fields the caller explicitly populated. Metadata is modelled as
// map[string]string because Dodo's hosted API documents string-only metadata
// values, and the shape exactly matches the design's checkout flow note
// (`metadata = {org_id, account_id}`).

// Customer represents a Dodo customer record.
type Customer struct {
	ID       string            `json:"id,omitempty"`
	Email    string            `json:"email,omitempty"`
	Name     string            `json:"name,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CustomerCreateParams is the request body for Customers.Create.
type CustomerCreateParams struct {
	Email    string            `json:"email"`
	Name     string            `json:"name,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Subscription represents a Dodo subscription. Status mirrors the design
// state machine (`trialing → active → past_due → grace → downgraded`) but
// is stored as a free-form string so unknown upstream values pass through
// for logging.
type Subscription struct {
	ID         string            `json:"id,omitempty"`
	CustomerID string            `json:"customer_id,omitempty"`
	ProductID  string            `json:"product_id,omitempty"`
	Status     string            `json:"status,omitempty"`
	Quantity   int               `json:"quantity,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// SubscriptionCreateParams is the request body for Subscriptions.Create.
type SubscriptionCreateParams struct {
	CustomerID string            `json:"customer_id"`
	ProductID  string            `json:"product_id"`
	Quantity   int               `json:"quantity,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// SubscriptionUpdateParams is the request body for Subscriptions.Update.
// ProrationBehavior is the field the design's task 4.8 calls out as
// `proration_behavior=create_prorations` for upgrades.
type SubscriptionUpdateParams struct {
	ProductID         string            `json:"product_id,omitempty"`
	Quantity          int               `json:"quantity,omitempty"`
	ProrationBehavior string            `json:"proration_behavior,omitempty"`
	ScheduleAtPeriodEnd bool            `json:"schedule_at_period_end,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// Invoice represents a Dodo invoice.
type Invoice struct {
	ID         string `json:"id,omitempty"`
	CustomerID string `json:"customer_id,omitempty"`
	Amount     int64  `json:"amount,omitempty"`
	Currency   string `json:"currency,omitempty"`
	Status     string `json:"status,omitempty"`
	PDFURL     string `json:"pdf_url,omitempty"`
}

// InvoiceListParams expresses the supported filters for Invoices.List.
// CustomerID and Limit are the two filters the design requires
// ("next 3 upcoming + last 24 issued"); pagination cursors are punted to
// task 4.12 where the actual endpoint lands.
type InvoiceListParams struct {
	CustomerID string
	Limit      int
}

// InvoiceList is the JSON envelope Dodo returns for collection endpoints.
type InvoiceList struct {
	Data []Invoice `json:"data"`
}

// CheckoutSession represents a hosted-checkout session. URL is the field
// the Dashboard redirects the browser to per design's "Checkout flow".
// ExpiresAt is the (optional) deadline by which the hosted URL must be
// visited; Dodo returns it on session create and the API_Server passes it
// through verbatim so the Dashboard can disable the redirect once the
// session has aged out.
type CheckoutSession struct {
	ID        string            `json:"id,omitempty"`
	URL       string            `json:"url"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// CheckoutSessionCreateParams mirrors the design's checkout-flow snippet:
// `customer.email`, `metadata = {org_id, account_id}`, `success_url`,
// `cancel_url`. ProductID is the resolved Dodo product for the
// (plan, period) combination.
type CheckoutSessionCreateParams struct {
	CustomerEmail string            `json:"customer_email,omitempty"`
	ProductID     string            `json:"product_id"`
	SuccessURL    string            `json:"success_url"`
	CancelURL     string            `json:"cancel_url"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// -----------------------------------------------------------------------
// CustomersService
// -----------------------------------------------------------------------

// CustomersService groups operations on the /customers resource.
type CustomersService struct{ c *Client }

// Create issues POST /customers and returns the created Customer.
func (s *CustomersService) Create(ctx context.Context, params CustomerCreateParams) (*Customer, error) {
	out := &Customer{}
	if err := s.c.do(ctx, http.MethodPost, "/customers", params, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Get issues GET /customers/{id}.
func (s *CustomersService) Get(ctx context.Context, id string) (*Customer, error) {
	if id == "" {
		return nil, ErrMissingID
	}
	out := &Customer{}
	if err := s.c.do(ctx, http.MethodGet, "/customers/"+url.PathEscape(id), nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// -----------------------------------------------------------------------
// SubscriptionsService
// -----------------------------------------------------------------------

// SubscriptionsService groups operations on the /subscriptions resource.
type SubscriptionsService struct{ c *Client }

// Create issues POST /subscriptions.
func (s *SubscriptionsService) Create(ctx context.Context, params SubscriptionCreateParams) (*Subscription, error) {
	out := &Subscription{}
	if err := s.c.do(ctx, http.MethodPost, "/subscriptions", params, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Update issues PATCH /subscriptions/{id}. The design uses this for both
// proration on plan change (task 4.8) and seat-line-item edits (task 4.9).
func (s *SubscriptionsService) Update(ctx context.Context, id string, params SubscriptionUpdateParams) (*Subscription, error) {
	if id == "" {
		return nil, ErrMissingID
	}
	out := &Subscription{}
	if err := s.c.do(ctx, http.MethodPatch, "/subscriptions/"+url.PathEscape(id), params, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Get issues GET /subscriptions/{id}.
func (s *SubscriptionsService) Get(ctx context.Context, id string) (*Subscription, error) {
	if id == "" {
		return nil, ErrMissingID
	}
	out := &Subscription{}
	if err := s.c.do(ctx, http.MethodGet, "/subscriptions/"+url.PathEscape(id), nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Cancel issues POST /subscriptions/{id}/cancel and returns the updated
// Subscription. We send a POST rather than DELETE so subsequent attempts
// to read the row still work (Dodo keeps canceled rows for invoicing).
func (s *SubscriptionsService) Cancel(ctx context.Context, id string) (*Subscription, error) {
	if id == "" {
		return nil, ErrMissingID
	}
	out := &Subscription{}
	if err := s.c.do(ctx, http.MethodPost, "/subscriptions/"+url.PathEscape(id)+"/cancel", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// -----------------------------------------------------------------------
// InvoicesService
// -----------------------------------------------------------------------

// InvoicesService groups operations on the /invoices resource.
type InvoicesService struct{ c *Client }

// List issues GET /invoices?customer_id=...&limit=...
func (s *InvoicesService) List(ctx context.Context, params InvoiceListParams) (*InvoiceList, error) {
	q := url.Values{}
	if params.CustomerID != "" {
		q.Set("customer_id", params.CustomerID)
	}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	path := "/invoices"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	out := &InvoiceList{}
	if err := s.c.do(ctx, http.MethodGet, path, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Get issues GET /invoices/{id}.
func (s *InvoicesService) Get(ctx context.Context, id string) (*Invoice, error) {
	if id == "" {
		return nil, ErrMissingID
	}
	out := &Invoice{}
	if err := s.c.do(ctx, http.MethodGet, "/invoices/"+url.PathEscape(id), nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// -----------------------------------------------------------------------
// CheckoutSessionsService
// -----------------------------------------------------------------------

// CheckoutSessionsService groups operations on the /checkout/sessions
// resource. Only Create is needed for the Phase-4 happy path; later phases
// (admin re-issue, refunds) can extend this struct without breaking
// callers.
type CheckoutSessionsService struct{ c *Client }

// Create issues POST /checkout/sessions and returns {URL, Metadata, ...}
// as specified by task 4.2.
func (s *CheckoutSessionsService) Create(ctx context.Context, params CheckoutSessionCreateParams) (*CheckoutSession, error) {
	out := &CheckoutSession{}
	if err := s.c.do(ctx, http.MethodPost, "/checkout/sessions", params, out); err != nil {
		return nil, err
	}
	return out, nil
}
