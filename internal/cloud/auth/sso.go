package auth

// File sso.go implements task 2.10 of the xalgorix-saas spec —
// "SAML 2.0 + OIDC SSO (Enterprise only)" — and the supporting
// "domain capture" behaviour required by Requirement 4.7:
//
//	WHERE the Organization is on the Enterprise Plan, THE API_Server
//	SHALL allow an Owner to configure SAML 2.0 or OIDC single sign-on
//	with a verified domain, after which all email addresses on that
//	domain SHALL be required to sign in through SSO.
//
// Scope of this file:
//
//   - [SSOConfig]:     per-Org SSO configuration row covering both SAML
//                      and OIDC, including the `RequiredDomain` (citext
//                      in Postgres, lower-cased here) used to capture
//                      every email on a verified domain.
//   - [SSOStore]:      lookup interface keyed on org slug and on the
//                      account email's domain. Production wires this
//                      to a pgx repository; the test suite supplies an
//                      in-memory implementation.
//   - [SAMLService]:   thin wrapper around `github.com/crewjam/saml/samlsp`
//                      that constructs a per-org [samlsp.Middleware] and
//                      exposes the three endpoint URLs required by the
//                      task description (`login`, `acs`, `metadata`).
//   - [OIDCService]:   wrapper around `github.com/coreos/go-oidc/v3/oidc`
//                      and `golang.org/x/oauth2` that builds a per-org
//                      [oauth2.Config] and the redirect URL that drives
//                      the OIDC code+state flow.
//   - [DomainCapture]: enforcement primitive used by the password,
//                      magic-link, and OAuth handlers. When an account's
//                      email domain matches an org's `sso_required_domain`,
//                      DomainCapture refuses the request with
//                      [ErrSSORequired] and returns the redirect URL the
//                      browser must follow to start the SSO flow at
//                      `/auth/sso/{provider}/{org_slug}/login`.
//
// Out of scope here:
//
//   - Just-in-time provisioning of accounts from a SAML/OIDC subject
//     (covered by task 4.x once members.go lands).
//   - Persisting SSO configuration through admin endpoints (Phase 12).
//   - Mounting these handlers on the chi router (Phase 8 task 8.1).
//
// The crewjam/saml dependency targets v0.5.1 because that is the
// latest release that builds on the project's pinned Go 1.24
// toolchain. coreos/go-oidc is pinned to v3.17.0 for the same reason
// (v3.18.0 requires Go >= 1.25). go.mod records both choices.
//
// Validates: Requirements 4.7.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/oauth2"
)

// SSOProvider names the SSO mechanism configured for an Organization.
// Exactly one provider is allowed per Org; switching providers is a
// destructive operation handled by the admin UI (out of scope here).
type SSOProvider string

const (
	// SSOProviderSAML uses SAML 2.0 via crewjam/saml.
	SSOProviderSAML SSOProvider = "saml"
	// SSOProviderOIDC uses OIDC discovery via coreos/go-oidc.
	SSOProviderOIDC SSOProvider = "oidc"
)

// Sentinel errors. Callers compare with errors.Is so the HTTP layer
// can map each cause to the right response code.
var (
	// ErrSSORequired is returned by [DomainCapture.Enforce] when the
	// supplied email matches an Organization with `sso_required_domain`
	// configured. The accompanying redirect URL is returned alongside
	// the error so the handler can issue an HTTP 303 response.
	ErrSSORequired = errors.New("auth: sso required for email domain")

	// ErrSSONotConfigured is returned when an SSO endpoint is invoked
	// for an org slug that has no SSO row, or whose row is missing the
	// fields the chosen provider needs (e.g. OIDC issuer + client id).
	ErrSSONotConfigured = errors.New("auth: sso not configured")

	// ErrSSOProviderMismatch is returned when the requested endpoint
	// (e.g. `/auth/sso/saml/{slug}/login`) does not match the provider
	// recorded in [SSOConfig].
	ErrSSOProviderMismatch = errors.New("auth: sso provider mismatch")

	// ErrSSOInvalidEmail is returned by [DomainCapture.Enforce] when
	// the supplied email does not contain a `@` separator.
	ErrSSOInvalidEmail = errors.New("auth: invalid email address")

	// ErrSSOInvalidConfig is returned by [SSOConfig.Validate] when a
	// configuration row would fail to wire up (e.g. SAML config with
	// no metadata source, OIDC config with no issuer or client id).
	ErrSSOInvalidConfig = errors.New("auth: invalid sso config")
)

// SSOConfig captures the per-Organization SSO row stored in Postgres.
// It covers both providers in a single struct — only the fields
// relevant to the active provider need to be populated.
//
// The exact column list mirrors the design.md interface table:
//
//	OrgID, IdPMetadataURL/XML, EntityID, ACSURL, Provider (saml|oidc),
//	OIDCIssuer, OIDCClientID, OIDCClientSecret, RequiredDomain (citext)
type SSOConfig struct {
	// OrgID is the owning Organization. The same UUID is exported in
	// PostgreSQL as `organizations.id`.
	OrgID string
	// OrgSlug is the URL-safe identifier used in SSO endpoint paths
	// (`/auth/sso/{provider}/{org_slug}/...`). It is denormalised on
	// purpose so route construction does not need a second DB lookup.
	OrgSlug string

	// Provider selects between SAML 2.0 and OIDC.
	Provider SSOProvider

	// IdPMetadataURL is the IdP's published SAML metadata document.
	// Either IdPMetadataURL or IdPMetadataXML must be set when
	// Provider == SSOProviderSAML.
	IdPMetadataURL string
	// IdPMetadataXML is the raw SAML metadata document, used when the
	// IdP does not publish a stable metadata URL. Mutually exclusive
	// with IdPMetadataURL in practice but not enforced as a struct
	// constraint so admins can flip between sources during testing.
	IdPMetadataXML string
	// EntityID is the SP entity id sent in SAML AuthnRequests. When
	// empty, SAMLService synthesises it from the metadata URL.
	EntityID string
	// ACSURL is the SAML Assertion Consumer Service URL. It must be
	// the absolute URL the IdP will POST the Response to and is
	// stored verbatim so that admins do not have to re-derive it
	// from the deployed hostname.
	ACSURL string

	// OIDCIssuer is the OIDC discovery base URL (RFC 8414).
	OIDCIssuer string
	// OIDCClientID is the public OIDC client id.
	OIDCClientID string
	// OIDCClientSecret is the OIDC client secret. It is stored
	// KMS-encrypted at rest in production; SSOConfig holds the
	// decrypted value for the duration of a request.
	OIDCClientSecret string

	// RequiredDomain is the email domain captured by this Org. When
	// non-empty, every account whose email matches this domain MUST
	// sign in via SSO. Postgres stores the value as `citext`; this
	// field always carries the lower-cased canonical form.
	RequiredDomain string
}

// Validate returns nil if the configuration is internally consistent
// for the selected Provider. The HTTP admin layer must call Validate
// before persisting any SSO row.
func (c *SSOConfig) Validate() error {
	if c == nil {
		return ErrSSOInvalidConfig
	}
	if c.OrgSlug == "" || c.OrgID == "" {
		return fmt.Errorf("%w: org id and slug are required", ErrSSOInvalidConfig)
	}
	switch c.Provider {
	case SSOProviderSAML:
		if c.IdPMetadataURL == "" && c.IdPMetadataXML == "" {
			return fmt.Errorf("%w: saml requires IdPMetadataURL or IdPMetadataXML", ErrSSOInvalidConfig)
		}
		if c.ACSURL == "" {
			return fmt.Errorf("%w: saml requires ACSURL", ErrSSOInvalidConfig)
		}
	case SSOProviderOIDC:
		if c.OIDCIssuer == "" || c.OIDCClientID == "" {
			return fmt.Errorf("%w: oidc requires Issuer and ClientID", ErrSSOInvalidConfig)
		}
	default:
		return fmt.Errorf("%w: unknown provider %q", ErrSSOInvalidConfig, c.Provider)
	}
	return nil
}

// SSOStore is the lookup surface SAMLService, OIDCService, and
// DomainCapture share. Production wires this to a pgx repository that
// queries `organizations` joined to `organization_sso_configs` (added
// in a follow-up migration); tests use a tiny in-memory map.
type SSOStore interface {
	// LookupBySlug returns the SSO configuration for the given org
	// slug, or [ErrSSONotConfigured] if the org has no SSO row.
	LookupBySlug(ctx context.Context, slug string) (*SSOConfig, error)
	// LookupByDomain returns the SSO configuration whose
	// `RequiredDomain` matches the supplied lower-cased domain, or
	// [ErrSSONotConfigured] if no Org has captured the domain.
	LookupByDomain(ctx context.Context, domain string) (*SSOConfig, error)
}

// ----------------------------------------------------------------------
// Domain capture
// ----------------------------------------------------------------------

// DomainCapture enforces Requirement 4.7's "users on the verified
// domain must SSO" rule. It is invoked at the very top of every
// non-SSO sign-in handler (password login, magic link consume, OAuth
// callback) so a captured account cannot bypass SSO by selecting a
// different sign-in method.
type DomainCapture struct {
	store SSOStore
	// baseURL is the absolute origin used to construct the SSO
	// redirect URL when an Org captures an email domain. It MUST
	// include scheme + host (and optional port), with no trailing
	// slash, e.g. "https://app.xalgorix.com".
	baseURL string
}

// NewDomainCapture constructs a DomainCapture. baseURL is normalised
// (trailing slash trimmed) so callers do not need to be careful about
// configuration formatting.
func NewDomainCapture(store SSOStore, baseURL string) *DomainCapture {
	return &DomainCapture{
		store:   store,
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

// Enforce returns ErrSSORequired together with the redirect URL
// `/auth/sso/{provider}/{org_slug}/login` when the email's domain is
// captured by an Organization. When the domain is not captured the
// caller is free to continue with the password/magic-link/oauth flow.
//
// The lookup is case-insensitive and tolerates leading/trailing
// whitespace because users frequently paste their email with extra
// characters. Any storage-layer error other than ErrSSONotConfigured
// is propagated unchanged so the caller can decide whether to fail
// closed or continue.
func (d *DomainCapture) Enforce(ctx context.Context, email string) (redirectURL string, err error) {
	if d == nil || d.store == nil {
		return "", nil
	}
	domain, derr := emailDomain(email)
	if derr != nil {
		return "", derr
	}
	cfg, lerr := d.store.LookupByDomain(ctx, domain)
	if lerr != nil {
		if errors.Is(lerr, ErrSSONotConfigured) {
			return "", nil
		}
		return "", lerr
	}
	if cfg == nil || cfg.RequiredDomain == "" {
		return "", nil
	}
	if !strings.EqualFold(cfg.RequiredDomain, domain) {
		// Defensive: store returned a row whose captured domain does
		// not match the lookup. Treat as not configured.
		return "", nil
	}
	return d.LoginURL(cfg), ErrSSORequired
}

// LoginURL returns the absolute URL the browser must follow to start
// the SSO flow for cfg. It is exposed publicly so callers that have
// already resolved the [SSOConfig] (e.g. an admin "test SSO" button)
// can re-use the same construction without going through Enforce.
func (d *DomainCapture) LoginURL(cfg *SSOConfig) string {
	if cfg == nil {
		return ""
	}
	return d.baseURL + ssoLoginPath(cfg.Provider, cfg.OrgSlug)
}

// emailDomain extracts the lower-cased domain portion of a single
// RFC 5322-ish email address. It is intentionally permissive: SSO
// matching is a coarse signal and the upstream form already runs a
// stricter validation step.
func emailDomain(email string) (string, error) {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return "", ErrSSOInvalidEmail
	}
	at := strings.LastIndexByte(trimmed, '@')
	if at <= 0 || at == len(trimmed)-1 {
		return "", ErrSSOInvalidEmail
	}
	domain := strings.ToLower(trimmed[at+1:])
	if domain == "" {
		return "", ErrSSOInvalidEmail
	}
	return domain, nil
}

// ssoLoginPath returns the path portion of the SSO login endpoint for
// the given provider and org slug. The shape matches the task
// description verbatim: `/auth/sso/{provider}/{org_slug}/login`.
func ssoLoginPath(provider SSOProvider, slug string) string {
	return "/auth/sso/" + string(provider) + "/" + slug + "/login"
}

// ----------------------------------------------------------------------
// SAML service
// ----------------------------------------------------------------------

// SAMLService wraps `github.com/crewjam/saml/samlsp` so handlers can
// stay free of the upstream API surface. It builds a fresh
// [samlsp.Middleware] per request rather than caching one per Org so
// that admin updates to `IdPMetadataXML` take effect on the next
// request without invalidation work.
//
// The service intentionally does not own the chi mux. Instead, the
// API layer (Phase 8) registers `Login`, `ACS`, and `Metadata` against
// the URLs the task description specifies:
//
//	/auth/sso/saml/{org_slug}/login
//	/auth/sso/saml/{org_slug}/acs
//	/auth/sso/saml/{org_slug}/metadata
type SAMLService struct {
	store SSOStore
	// signKey is the SP signing key. It may be nil for IdPs that do
	// not require signed AuthnRequests.
	signKey *rsa.PrivateKey
	// signCert is the SP X.509 certificate paired with signKey. May
	// be nil; samlsp.Options accepts nil cert for unsigned-request
	// deployments.
	signCert *x509.Certificate
	// httpClient is used for IdP metadata fetches. Tests inject a
	// httptest.Server-backed client; production uses a hardened
	// client with the platform's pinned resolvers.
	httpClient *http.Client
}

// NewSAMLService constructs a SAMLService. httpClient may be nil; in
// that case the upstream samlsp default (http.DefaultClient with no
// timeout) is used, which is fine for development but production
// callers should always pass a hardened client.
func NewSAMLService(store SSOStore, signKey *rsa.PrivateKey, signCert *x509.Certificate, httpClient *http.Client) *SAMLService {
	return &SAMLService{
		store:      store,
		signKey:    signKey,
		signCert:   signCert,
		httpClient: httpClient,
	}
}

// MiddlewareFor builds a samlsp.Middleware for the org identified by
// slug. The caller is responsible for routing — this method only
// performs the lookup-and-construct dance so each handler stays a one
// liner.
func (s *SAMLService) MiddlewareFor(ctx context.Context, slug string) (*samlsp.Middleware, *SSOConfig, error) {
	if s == nil || s.store == nil {
		return nil, nil, ErrSSONotConfigured
	}
	cfg, err := s.store.LookupBySlug(ctx, slug)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Provider != SSOProviderSAML {
		return nil, nil, ErrSSOProviderMismatch
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}

	rootURL, err := url.Parse(strings.TrimRight(cfg.ACSURL, "/"))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse ACSURL: %v", ErrSSOInvalidConfig, err)
	}

	idpMeta, err := s.fetchMetadata(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	opts := samlsp.Options{
		EntityID:    cfg.EntityID,
		URL:         *rootURL,
		Key:         s.signKey,
		Certificate: s.signCert,
		IDPMetadata: idpMeta,
		HTTPClient:  s.httpClient,
	}
	mw, err := samlsp.New(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("samlsp.New: %w", err)
	}
	return mw, cfg, nil
}

// LoginURL is the absolute URL of the SAML login endpoint for slug.
// It mirrors [DomainCapture.LoginURL] for callers that already know
// the slug but not the full SSOConfig.
func (s *SAMLService) LoginURL(baseURL, slug string) string {
	return strings.TrimRight(baseURL, "/") + ssoLoginPath(SSOProviderSAML, slug)
}

// fetchMetadata loads the IdP metadata either from the embedded XML
// (preferred when present, since it avoids a network round-trip) or
// from the configured metadata URL.
func (s *SAMLService) fetchMetadata(ctx context.Context, cfg *SSOConfig) (*saml.EntityDescriptor, error) {
	if cfg.IdPMetadataXML != "" {
		md, err := samlsp.ParseMetadata([]byte(cfg.IdPMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("%w: parse metadata xml: %v", ErrSSOInvalidConfig, err)
		}
		return md, nil
	}
	u, err := url.Parse(cfg.IdPMetadataURL)
	if err != nil {
		return nil, fmt.Errorf("%w: parse IdPMetadataURL: %v", ErrSSOInvalidConfig, err)
	}
	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	md, err := samlsp.FetchMetadata(ctx, client, *u)
	if err != nil {
		return nil, fmt.Errorf("samlsp.FetchMetadata: %w", err)
	}
	return md, nil
}

// ----------------------------------------------------------------------
// OIDC service
// ----------------------------------------------------------------------

// OIDCService wraps `github.com/coreos/go-oidc/v3/oidc` and
// `golang.org/x/oauth2` so handlers can drive a standard
// Authorization Code + state flow without dealing with discovery
// directly.
//
// Endpoints (mounted by Phase 8):
//
//	/auth/sso/oidc/{org_slug}/login    — redirects to AuthCodeURL
//	/auth/sso/oidc/{org_slug}/callback — exchanges code for tokens
type OIDCService struct {
	store      SSOStore
	httpClient *http.Client
}

// NewOIDCService constructs an OIDCService. httpClient may be nil;
// in that case the package-level default is used.
func NewOIDCService(store SSOStore, httpClient *http.Client) *OIDCService {
	return &OIDCService{
		store:      store,
		httpClient: httpClient,
	}
}

// ConfigFor returns the OIDC provider, oauth2.Config, and the Org's
// SSOConfig for the given slug. The caller drives the redirect/
// callback flow; ConfigFor performs the discovery handshake using
// `oidc.NewProvider` and assembles a default `openid email profile`
// scope list.
func (o *OIDCService) ConfigFor(ctx context.Context, slug, redirectURL string) (*oidc.Provider, *oauth2.Config, *SSOConfig, error) {
	if o == nil || o.store == nil {
		return nil, nil, nil, ErrSSONotConfigured
	}
	cfg, err := o.store.LookupBySlug(ctx, slug)
	if err != nil {
		return nil, nil, nil, err
	}
	if cfg.Provider != SSOProviderOIDC {
		return nil, nil, nil, ErrSSOProviderMismatch
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, nil, err
	}
	if redirectURL == "" {
		return nil, nil, nil, fmt.Errorf("%w: redirectURL is required", ErrSSOInvalidConfig)
	}

	if o.httpClient != nil {
		ctx = oidc.ClientContext(ctx, o.httpClient)
	}
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oidc.NewProvider: %w", err)
	}
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	return provider, oauthCfg, cfg, nil
}

// LoginURL builds the absolute URL that initiates the OIDC code+state
// flow. It does not perform discovery; that is deferred until the
// browser actually arrives at the login endpoint.
func (o *OIDCService) LoginURL(baseURL, slug string) string {
	return strings.TrimRight(baseURL, "/") + ssoLoginPath(SSOProviderOIDC, slug)
}

// AuthCodeURL is a thin pass-through to oauth2.Config.AuthCodeURL
// kept here so handlers can build the redirect with one call:
//
//	provider, cfg, _, _ := svc.ConfigFor(ctx, slug, redirectURL)
//	url := svc.AuthCodeURL(cfg, state, nonce)
func (o *OIDCService) AuthCodeURL(oauthCfg *oauth2.Config, state, nonce string) string {
	if oauthCfg == nil {
		return ""
	}
	if nonce == "" {
		return oauthCfg.AuthCodeURL(state)
	}
	return oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce))
}

// ----------------------------------------------------------------------
// In-memory store helper (used by tests and admin-side seeding)
// ----------------------------------------------------------------------

// MemorySSOStore is a tiny in-memory [SSOStore] keyed on org slug and
// captured domain. It is intentionally small and unsynchronised — the
// admin pgx-backed implementation lives next to the migration that
// adds the SSO table. Tests use this directly.
type MemorySSOStore struct {
	bySlug   map[string]*SSOConfig
	byDomain map[string]*SSOConfig
}

// NewMemorySSOStore constructs an empty MemorySSOStore.
func NewMemorySSOStore() *MemorySSOStore {
	return &MemorySSOStore{
		bySlug:   map[string]*SSOConfig{},
		byDomain: map[string]*SSOConfig{},
	}
}

// Put inserts or replaces a config row. Domain matching is
// case-insensitive: the domain is lower-cased before being indexed.
func (m *MemorySSOStore) Put(cfg *SSOConfig) {
	if cfg == nil || cfg.OrgSlug == "" {
		return
	}
	clone := *cfg
	clone.RequiredDomain = strings.ToLower(strings.TrimSpace(clone.RequiredDomain))
	m.bySlug[clone.OrgSlug] = &clone
	if clone.RequiredDomain != "" {
		m.byDomain[clone.RequiredDomain] = &clone
	}
}

// LookupBySlug implements [SSOStore].
func (m *MemorySSOStore) LookupBySlug(_ context.Context, slug string) (*SSOConfig, error) {
	cfg, ok := m.bySlug[slug]
	if !ok {
		return nil, ErrSSONotConfigured
	}
	return cfg, nil
}

// LookupByDomain implements [SSOStore]. The domain is matched
// case-insensitively.
func (m *MemorySSOStore) LookupByDomain(_ context.Context, domain string) (*SSOConfig, error) {
	cfg, ok := m.byDomain[strings.ToLower(domain)]
	if !ok {
		return nil, ErrSSONotConfigured
	}
	return cfg, nil
}
