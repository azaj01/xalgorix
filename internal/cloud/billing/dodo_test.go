package billing

// File dodo_test.go covers the public surface introduced by task 4.2:
//
//   - NewClient validation: missing API key, malformed BaseURL.
//   - resolveBaseURL precedence: explicit BaseURL beats Environment, hosted
//     defaults are picked correctly otherwise.
//   - One method per service against an httptest.Server, asserting the
//     wire shape the rest of Phase 4 will rely on (HTTP method, path,
//     bearer auth, JSON body, decoded response).
//   - One sad-path covering ErrUnexpectedStatus so callers can rely on the
//     wrapped sentinel.
//
// Requirements: 5.1, 5.2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestClient stands up an httptest.Server with the supplied handler and
// returns a Client wired to it. The handler is invoked exactly as Dodo's
// hosted API would invoke it; the server is t.Cleanup-closed.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := NewClient(Config{
		APIKey:      "sk_test_unit",
		Environment: EnvTestMode,
		BaseURL:     srv.URL,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// assertCommonHeaders fails the test if the bearer-token, Accept, or
// User-Agent headers do not match what dodo.go documents.
func assertCommonHeaders(t *testing.T, r *http.Request, withBody bool) {
	t.Helper()
	if got, want := r.Header.Get("Authorization"), "Bearer sk_test_unit"; got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept header = %q, want application/json", got)
	}
	if got := r.Header.Get("User-Agent"); got == "" {
		t.Error("User-Agent header is empty")
	}
	if withBody {
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type header = %q, want application/json", got)
		}
	}
}

func TestNewClient_RejectsMissingAPIKey(t *testing.T) {
	t.Parallel()
	if _, err := NewClient(Config{Environment: EnvTestMode}); !errors.Is(err, ErrAPIKeyMissing) {
		t.Fatalf("NewClient err = %v, want errors.Is ErrAPIKeyMissing", err)
	}
}

func TestNewClient_RejectsInvalidBaseURL(t *testing.T) {
	t.Parallel()
	_, err := NewClient(Config{
		APIKey:      "sk_test_abc",
		Environment: EnvTestMode,
		BaseURL:     "::not-a-url",
	})
	if !errors.Is(err, ErrInvalidBaseURL) {
		t.Fatalf("NewClient err = %v, want errors.Is ErrInvalidBaseURL", err)
	}
}

func TestNewClient_PicksHostedDefaultByEnvironment(t *testing.T) {
	t.Parallel()
	cases := []struct {
		env  string
		want string
	}{
		{env: "", want: defaultTestModeBaseURL},
		{env: EnvTestMode, want: defaultTestModeBaseURL},
		{env: EnvLiveMode, want: defaultLiveModeBaseURL},
	}
	for _, c := range cases {
		c := c
		t.Run(c.env, func(t *testing.T) {
			t.Parallel()
			cl, err := NewClient(Config{APIKey: "sk_test_abc", Environment: c.env})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if cl.baseURL != c.want {
				t.Fatalf("baseURL = %q, want %q", cl.baseURL, c.want)
			}
		})
	}
}

func TestNewClient_StripsTrailingSlashFromBaseURL(t *testing.T) {
	t.Parallel()
	cl, err := NewClient(Config{
		APIKey:  "sk_test_abc",
		BaseURL: "https://billing.example.com/v1/",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if cl.baseURL != "https://billing.example.com/v1" {
		t.Fatalf("baseURL = %q, want trimmed", cl.baseURL)
	}
}

func TestCustomersService_Create(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/customers" {
			t.Errorf("got %s %s, want POST /customers", r.Method, r.URL.Path)
		}
		assertCommonHeaders(t, r, true)

		var body CustomerCreateParams
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.Email != "owner@example.com" {
			t.Errorf("body.Email = %q, want owner@example.com", body.Email)
		}
		if body.Metadata["org_id"] != "org_1" {
			t.Errorf("body.Metadata[org_id] = %q, want org_1", body.Metadata["org_id"])
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cus_123","email":"owner@example.com"}`)
	})

	got, err := c.Customers.Create(context.Background(), CustomerCreateParams{
		Email:    "owner@example.com",
		Metadata: map[string]string{"org_id": "org_1"},
	})
	if err != nil {
		t.Fatalf("Customers.Create: %v", err)
	}
	if got.ID != "cus_123" || got.Email != "owner@example.com" {
		t.Fatalf("decoded customer = %+v", got)
	}
}

func TestSubscriptionsService_Update_SendsPatchAndProration(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/subscriptions/sub_42" {
			t.Errorf("got %s %s, want PATCH /subscriptions/sub_42", r.Method, r.URL.Path)
		}
		assertCommonHeaders(t, r, true)

		var body SubscriptionUpdateParams
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.ProrationBehavior != "create_prorations" {
			t.Errorf("body.ProrationBehavior = %q, want create_prorations", body.ProrationBehavior)
		}
		if body.Quantity != 5 {
			t.Errorf("body.Quantity = %d, want 5", body.Quantity)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"sub_42","status":"active","quantity":5}`)
	})

	got, err := c.Subscriptions.Update(context.Background(), "sub_42", SubscriptionUpdateParams{
		Quantity:          5,
		ProrationBehavior: "create_prorations",
	})
	if err != nil {
		t.Fatalf("Subscriptions.Update: %v", err)
	}
	if got.ID != "sub_42" || got.Quantity != 5 || got.Status != "active" {
		t.Fatalf("decoded subscription = %+v", got)
	}
}

func TestSubscriptionsService_Update_RejectsEmptyID(t *testing.T) {
	t.Parallel()
	// No httptest server is needed: validation runs before any network IO.
	c, err := NewClient(Config{APIKey: "sk_test_abc", Environment: EnvTestMode})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Subscriptions.Update(context.Background(), "", SubscriptionUpdateParams{}); !errors.Is(err, ErrMissingID) {
		t.Fatalf("Update err = %v, want errors.Is ErrMissingID", err)
	}
}

func TestInvoicesService_List_EncodesQueryAndDecodesEnvelope(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/invoices" {
			t.Errorf("got %s %s, want GET /invoices", r.Method, r.URL.Path)
		}
		assertCommonHeaders(t, r, false)

		if got, want := r.URL.Query().Get("customer_id"), "cus_99"; got != want {
			t.Errorf("query customer_id = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("limit"), "3"; got != want {
			t.Errorf("query limit = %q, want %q", got, want)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[{"id":"in_1","amount":1900,"currency":"usd","status":"paid"}]}`)
	})

	got, err := c.Invoices.List(context.Background(), InvoiceListParams{
		CustomerID: "cus_99",
		Limit:      3,
	})
	if err != nil {
		t.Fatalf("Invoices.List: %v", err)
	}
	if len(got.Data) != 1 || got.Data[0].ID != "in_1" || got.Data[0].Amount != 1900 {
		t.Fatalf("decoded invoice list = %+v", got)
	}
}

func TestCheckoutSessionsService_Create(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/checkout/sessions" {
			t.Errorf("got %s %s, want POST /checkout/sessions", r.Method, r.URL.Path)
		}
		assertCommonHeaders(t, r, true)

		var body CheckoutSessionCreateParams
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.ProductID != "prod_pro_monthly" {
			t.Errorf("body.ProductID = %q", body.ProductID)
		}
		if body.SuccessURL == "" || body.CancelURL == "" {
			t.Errorf("body must include success/cancel URLs, got %+v", body)
		}
		if body.Metadata["org_id"] != "org_1" || body.Metadata["account_id"] != "acc_1" {
			t.Errorf("body.Metadata = %+v, want {org_id, account_id} per design", body.Metadata)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"cs_1","url":"https://checkout.dodopayments.com/cs_1","metadata":{"org_id":"org_1","account_id":"acc_1"}}`)
	})

	got, err := c.CheckoutSessions.Create(context.Background(), CheckoutSessionCreateParams{
		CustomerEmail: "owner@example.com",
		ProductID:     "prod_pro_monthly",
		SuccessURL:    "https://app.xalgorix.com/billing/success",
		CancelURL:     "https://app.xalgorix.com/billing/cancel",
		Metadata: map[string]string{
			"org_id":     "org_1",
			"account_id": "acc_1",
		},
	})
	if err != nil {
		t.Fatalf("CheckoutSessions.Create: %v", err)
	}
	if got.URL == "" {
		t.Fatalf("CheckoutSession.URL is empty: %+v", got)
	}
	if !strings.HasPrefix(got.URL, "https://") {
		t.Fatalf("CheckoutSession.URL = %q, want https URL", got.URL)
	}
	if got.Metadata["org_id"] != "org_1" {
		t.Fatalf("CheckoutSession.Metadata = %+v", got.Metadata)
	}
}

func TestClient_WrapsUnexpectedStatus(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"plan_not_found"}`)
	})

	_, err := c.Customers.Get(context.Background(), "cus_404")
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("err = %v, want errors.Is ErrUnexpectedStatus", err)
	}
	if !strings.Contains(err.Error(), "plan_not_found") {
		t.Fatalf("err missing body snippet: %v", err)
	}
}
