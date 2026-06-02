package auth

// Tests for task 2.10 — "SAML 2.0 + OIDC SSO (Enterprise only)".
//
// Coverage targets called out by the task:
//
//   - Domain capture: when an account's email domain matches an Org's
//     `sso_required_domain`, the password / magic-link / oauth flow
//     MUST refuse the request and force a redirect to
//     `/auth/sso/{provider}/{org_slug}/login`.
//   - Basic redirect URL generation for both providers — the URL
//     shape is part of Requirement 4.7 and is also the public contract
//     consumed by the Phase 8 chi router.
//
// These tests use the in-memory [MemorySSOStore] so that no Postgres
// or live IdP is required. They are pure unit tests; the live SAML
// metadata fetch and OIDC discovery handshake are exercised by the
// integration suite in Phase 20.
//
// Validates: Requirements 4.7.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// newCapturedStore returns a store seeded with one Enterprise org
// that has captured "acme.com" via SAML SSO. Tests share this helper
// so the assertions stay focused on the behaviour under test.
func newCapturedStore(t *testing.T) *MemorySSOStore {
	t.Helper()
	store := NewMemorySSOStore()
	store.Put(&SSOConfig{
		OrgID:          "11111111-1111-1111-1111-111111111111",
		OrgSlug:        "acme",
		Provider:       SSOProviderSAML,
		IdPMetadataURL: "https://idp.example.com/metadata.xml",
		ACSURL:         "https://app.xalgorix.com/auth/sso/saml/acme/acs",
		EntityID:       "https://app.xalgorix.com/auth/sso/saml/acme/metadata",
		RequiredDomain: "acme.com",
	})
	return store
}

// TestDomainCaptureRefusesPasswordLoginForCapturedEmail is the
// headline assertion for Requirement 4.7: a user whose email matches
// a captured domain must be steered to SSO instead of allowed through
// the password flow.
func TestDomainCaptureRefusesPasswordLoginForCapturedEmail(t *testing.T) {
	t.Parallel()
	store := newCapturedStore(t)
	dc := NewDomainCapture(store, "https://app.xalgorix.com")

	// Two case variants and a leading-whitespace variant — all of
	// them MUST hit the captured row because Postgres `citext` is
	// case-insensitive and the form field commonly carries
	// stray whitespace from copy-paste.
	cases := []string{
		"alice@acme.com",
		"Alice@Acme.COM",
		"  bob@acme.com  ",
	}
	for _, email := range cases {
		email := email
		t.Run(strings.TrimSpace(email), func(t *testing.T) {
			t.Parallel()
			redirect, err := dc.Enforce(context.Background(), email)
			if !errors.Is(err, ErrSSORequired) {
				t.Fatalf("Enforce(%q) err = %v, want ErrSSORequired", email, err)
			}
			want := "https://app.xalgorix.com/auth/sso/saml/acme/login"
			if redirect != want {
				t.Fatalf("Enforce(%q) redirect = %q, want %q", email, redirect, want)
			}
		})
	}
}

// TestDomainCaptureAllowsUncapturedEmail covers the other side of the
// same rule: emails on a domain no Org has captured must NOT be
// refused, otherwise the entire password sign-in path breaks.
func TestDomainCaptureAllowsUncapturedEmail(t *testing.T) {
	t.Parallel()
	store := newCapturedStore(t)
	dc := NewDomainCapture(store, "https://app.xalgorix.com")

	cases := []string{
		"alice@example.com",
		"bob@personal.dev",
		"carol@subdomain.acme.com", // exact-domain match only — no fall-through
	}
	for _, email := range cases {
		email := email
		t.Run(email, func(t *testing.T) {
			t.Parallel()
			redirect, err := dc.Enforce(context.Background(), email)
			if err != nil {
				t.Fatalf("Enforce(%q) err = %v, want nil", email, err)
			}
			if redirect != "" {
				t.Fatalf("Enforce(%q) redirect = %q, want empty", email, redirect)
			}
		})
	}
}

// TestDomainCaptureRejectsMalformedEmails ensures the helper does not
// silently allow a request through when the email is structurally
// invalid; the password handler relies on this signal to surface a
// 422 rather than treating the input as un-captured.
func TestDomainCaptureRejectsMalformedEmails(t *testing.T) {
	t.Parallel()
	dc := NewDomainCapture(newCapturedStore(t), "https://app.xalgorix.com")

	for _, bad := range []string{"", "  ", "no-at-sign", "@no-local", "trailing@"} {
		bad := bad
		t.Run(bad, func(t *testing.T) {
			t.Parallel()
			redirect, err := dc.Enforce(context.Background(), bad)
			if !errors.Is(err, ErrSSOInvalidEmail) {
				t.Fatalf("Enforce(%q) err = %v, want ErrSSOInvalidEmail", bad, err)
			}
			if redirect != "" {
				t.Fatalf("Enforce(%q) redirect = %q, want empty", bad, redirect)
			}
		})
	}
}

// TestDomainCaptureNilStoreIsNoOp documents the contract used by
// configurations that do not have any SSO Orgs yet: a DomainCapture
// constructed with a nil store must always return (no redirect, nil)
// so the password flow stays open.
func TestDomainCaptureNilStoreIsNoOp(t *testing.T) {
	t.Parallel()
	dc := NewDomainCapture(nil, "https://app.xalgorix.com")
	redirect, err := dc.Enforce(context.Background(), "alice@anywhere.example")
	if err != nil {
		t.Fatalf("Enforce err = %v, want nil", err)
	}
	if redirect != "" {
		t.Fatalf("Enforce redirect = %q, want empty", redirect)
	}
}

// TestDomainCaptureBaseURLNormalisation makes sure the redirect URL
// is well-formed even when the base URL is configured with a
// trailing slash, as can happen when an admin pastes the dashboard
// origin from the browser.
func TestDomainCaptureBaseURLNormalisation(t *testing.T) {
	t.Parallel()
	store := newCapturedStore(t)

	for _, base := range []string{
		"https://app.xalgorix.com",
		"https://app.xalgorix.com/",
		"https://app.xalgorix.com////",
	} {
		base := base
		t.Run(base, func(t *testing.T) {
			t.Parallel()
			dc := NewDomainCapture(store, base)
			redirect, err := dc.Enforce(context.Background(), "alice@acme.com")
			if !errors.Is(err, ErrSSORequired) {
				t.Fatalf("Enforce err = %v, want ErrSSORequired", err)
			}
			const want = "https://app.xalgorix.com/auth/sso/saml/acme/login"
			if redirect != want {
				t.Fatalf("redirect = %q, want %q", redirect, want)
			}
		})
	}
}

// TestSAMLLoginURLShape pins the public route shape for SAML SSO so
// regressions in path construction are caught before they reach the
// chi router contract tests in Phase 8.
func TestSAMLLoginURLShape(t *testing.T) {
	t.Parallel()
	svc := NewSAMLService(newCapturedStore(t), nil, nil, nil)
	got := svc.LoginURL("https://app.xalgorix.com", "acme")
	const want = "https://app.xalgorix.com/auth/sso/saml/acme/login"
	if got != want {
		t.Fatalf("SAMLService.LoginURL = %q, want %q", got, want)
	}
}

// TestOIDCLoginURLShape pins the public route shape for OIDC SSO.
// Same rationale as TestSAMLLoginURLShape.
func TestOIDCLoginURLShape(t *testing.T) {
	t.Parallel()
	svc := NewOIDCService(NewMemorySSOStore(), nil)
	got := svc.LoginURL("https://app.xalgorix.com/", "globex")
	const want = "https://app.xalgorix.com/auth/sso/oidc/globex/login"
	if got != want {
		t.Fatalf("OIDCService.LoginURL = %q, want %q", got, want)
	}
}

// TestSSOConfigValidate exercises every Validate branch so the admin
// layer's "save SSO settings" form can rely on a tight error model
// when surfacing 422 responses.
func TestSSOConfigValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		cfg    *SSOConfig
		wantOK bool
	}{
		{
			name: "saml ok with metadata url",
			cfg: &SSOConfig{
				OrgID:          "id",
				OrgSlug:        "slug",
				Provider:       SSOProviderSAML,
				IdPMetadataURL: "https://idp/meta",
				ACSURL:         "https://app/acs",
			},
			wantOK: true,
		},
		{
			name: "saml ok with metadata xml",
			cfg: &SSOConfig{
				OrgID:          "id",
				OrgSlug:        "slug",
				Provider:       SSOProviderSAML,
				IdPMetadataXML: "<EntityDescriptor/>",
				ACSURL:         "https://app/acs",
			},
			wantOK: true,
		},
		{
			name: "saml missing acs",
			cfg: &SSOConfig{
				OrgID:          "id",
				OrgSlug:        "slug",
				Provider:       SSOProviderSAML,
				IdPMetadataURL: "https://idp/meta",
			},
		},
		{
			name: "saml missing metadata source",
			cfg: &SSOConfig{
				OrgID:    "id",
				OrgSlug:  "slug",
				Provider: SSOProviderSAML,
				ACSURL:   "https://app/acs",
			},
		},
		{
			name: "oidc ok",
			cfg: &SSOConfig{
				OrgID:        "id",
				OrgSlug:      "slug",
				Provider:     SSOProviderOIDC,
				OIDCIssuer:   "https://issuer.example",
				OIDCClientID: "client",
			},
			wantOK: true,
		},
		{
			name: "oidc missing issuer",
			cfg: &SSOConfig{
				OrgID:        "id",
				OrgSlug:      "slug",
				Provider:     SSOProviderOIDC,
				OIDCClientID: "client",
			},
		},
		{
			name: "oidc missing client id",
			cfg: &SSOConfig{
				OrgID:      "id",
				OrgSlug:    "slug",
				Provider:   SSOProviderOIDC,
				OIDCIssuer: "https://issuer.example",
			},
		},
		{
			name: "missing slug",
			cfg: &SSOConfig{
				OrgID:    "id",
				Provider: SSOProviderSAML,
				ACSURL:   "https://app/acs",
			},
		},
		{
			name: "unknown provider",
			cfg: &SSOConfig{
				OrgID:    "id",
				OrgSlug:  "slug",
				Provider: "ldap",
			},
		},
		{name: "nil receiver"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.cfg.Validate()
			gotOK := err == nil
			if gotOK != tc.wantOK {
				t.Fatalf("Validate() err = %v, wantOK = %v", err, tc.wantOK)
			}
			if !tc.wantOK && err != nil && !errors.Is(err, ErrSSOInvalidConfig) {
				t.Fatalf("Validate() err = %v, want ErrSSOInvalidConfig", err)
			}
		})
	}
}

// TestSAMLServiceProviderMismatch confirms the SAML wrapper refuses
// to build a middleware for an Org that selected OIDC. The router
// layer relies on this so it can return a clear error instead of a
// confusing samlsp panic.
func TestSAMLServiceProviderMismatch(t *testing.T) {
	t.Parallel()
	store := NewMemorySSOStore()
	store.Put(&SSOConfig{
		OrgID:        "id",
		OrgSlug:      "globex",
		Provider:     SSOProviderOIDC,
		OIDCIssuer:   "https://issuer.example",
		OIDCClientID: "client",
	})
	svc := NewSAMLService(store, nil, nil, nil)
	if _, _, err := svc.MiddlewareFor(context.Background(), "globex"); !errors.Is(err, ErrSSOProviderMismatch) {
		t.Fatalf("MiddlewareFor err = %v, want ErrSSOProviderMismatch", err)
	}
}

// TestOIDCServiceProviderMismatch is the symmetric check for OIDC.
func TestOIDCServiceProviderMismatch(t *testing.T) {
	t.Parallel()
	svc := NewOIDCService(newCapturedStore(t), nil)
	_, _, _, err := svc.ConfigFor(context.Background(), "acme", "https://app/cb")
	if !errors.Is(err, ErrSSOProviderMismatch) {
		t.Fatalf("ConfigFor err = %v, want ErrSSOProviderMismatch", err)
	}
}

// TestStoreReturnsNotConfiguredForUnknownSlug guarantees the lookup
// surface is a closed world: a request for an unknown slug must
// produce ErrSSONotConfigured rather than a nil/no-op response.
func TestStoreReturnsNotConfiguredForUnknownSlug(t *testing.T) {
	t.Parallel()
	store := NewMemorySSOStore()
	if _, err := store.LookupBySlug(context.Background(), "ghost"); !errors.Is(err, ErrSSONotConfigured) {
		t.Fatalf("LookupBySlug err = %v, want ErrSSONotConfigured", err)
	}
	if _, err := store.LookupByDomain(context.Background(), "ghost.example"); !errors.Is(err, ErrSSONotConfigured) {
		t.Fatalf("LookupByDomain err = %v, want ErrSSONotConfigured", err)
	}
}

// TestDomainCaptureProviderRoutesByConfig covers the OIDC variant of
// the redirect URL: the captured Org may have selected OIDC, in
// which case the redirect must point at /auth/sso/oidc/{slug}/login.
func TestDomainCaptureProviderRoutesByConfig(t *testing.T) {
	t.Parallel()
	store := NewMemorySSOStore()
	store.Put(&SSOConfig{
		OrgID:          "id",
		OrgSlug:        "globex",
		Provider:       SSOProviderOIDC,
		OIDCIssuer:     "https://issuer.example",
		OIDCClientID:   "client",
		RequiredDomain: "globex.example",
	})
	dc := NewDomainCapture(store, "https://app.xalgorix.com")
	redirect, err := dc.Enforce(context.Background(), "alice@globex.example")
	if !errors.Is(err, ErrSSORequired) {
		t.Fatalf("Enforce err = %v, want ErrSSORequired", err)
	}
	const want = "https://app.xalgorix.com/auth/sso/oidc/globex/login"
	if redirect != want {
		t.Fatalf("redirect = %q, want %q", redirect, want)
	}
}
