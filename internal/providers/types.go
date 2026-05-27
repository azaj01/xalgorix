// Package providers implements the runtime-editable LLM provider
// catalog (Catalog_Service) backed by ~/.xalgorix/data/providers.json.
//
// This file declares the on-disk + on-the-wire Entry shape, the id
// regex shared by Create/Update, the header-style allowlist, and the
// shared field-presence validator consumed by both the in-process
// CRUD surface and the HTTP handlers in internal/web. The actual
// Service type, file IO, and openclaw merge live in sibling files
// (service.go, openclaw.go) introduced by later Wave B tasks.
package providers

import (
	"errors"
	"fmt"
	"regexp"
)

// Entry mirrors the runtime-editable catalog shape (Requirement 1.2).
// The json tags drive both the on-disk providers.json format and the
// HTTP body shape returned by GET /api/providers — the design pins
// the field names exactly, so do not rename without updating the
// design doc and the webui CatalogEntry type in webui/src/types/api.ts.
//
// Validates: Requirements 1.2, 1.5, 1.6, 1.8.
type Entry struct {
	ID                          string   `json:"id"`
	DisplayName                 string   `json:"displayName"`
	BaseURL                     string   `json:"baseURL"`
	Models                      []string `json:"models,omitempty"`
	HeaderStyle                 string   `json:"headerStyle"`
	Flow                        string   `json:"flow,omitempty"`
	ClientID                    string   `json:"clientID,omitempty"`
	AuthorizationEndpoint       string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string   `json:"tokenEndpoint,omitempty"`
	DeviceAuthorizationEndpoint string   `json:"deviceAuthorizationEndpoint,omitempty"`
	// RevocationEndpoint is the optional RFC 7009 token revocation
	// endpoint. When set, Driver implementations that satisfy the
	// auth.Revoker contract POST {token, token_type_hint} here on
	// profile delete to invalidate the upstream token. When unset,
	// the driver falls back to "<tokenEndpoint>/revoke" per the
	// RFC 7009 §2.1 sibling-path convention; if even that produces
	// no usable URL the revoke step is skipped (best-effort).
	// Validates: H1 (best-effort revoke on delete).
	RevocationEndpoint string   `json:"revocationEndpoint,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	Audience           string   `json:"audience,omitempty"`
}

// idRE is the canonical id format from Requirement 1.2: starts with
// a lowercase alphanumeric, followed by up to 63 lowercase
// alphanumerics, dashes, or underscores. The same regex constrains
// auth-profile profileIds in Profile_Store (Requirement 4.2). Wave B
// task 2.2 (Service.Create / Service.Update) and Wave C task 3.1
// reference this variable.
var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// headerStyles is the allowlist of values accepted in Entry.HeaderStyle
// (Requirement 1.6). The set mirrors the three outbound request
// shapes the LLM client knows how to build (OpenAI-compatible chat,
// Anthropic /v1/messages, Gemini :generateContent) — adding a new
// header style here without teaching internal/llm/client.go how to
// build the matching request body would silently misroute scans.
var headerStyles = map[string]struct{}{
	"openai":    {},
	"anthropic": {},
	"gemini":    {},
}

// Validation sentinel errors. The HTTP layer (internal/web Wave E
// task 5.1) maps each of these to HTTP 400 per Requirements 1.5 and
// 1.6. They are declared as sentinels (rather than ad-hoc fmt.Errorf
// strings) so the web handlers can errors.Is on them.
var (
	// ErrIDRequired is returned when an Entry is missing its id.
	// Validates: Requirement 1.5.
	ErrIDRequired = errors.New("id is required")

	// ErrDisplayNameRequired is returned when displayName is empty.
	// Validates: Requirement 1.5.
	ErrDisplayNameRequired = errors.New("displayName is required")

	// ErrBaseURLRequired is returned when baseURL is empty.
	// Validates: Requirement 1.5.
	ErrBaseURLRequired = errors.New("baseURL is required")

	// ErrHeaderStyleRequired is returned when headerStyle is empty.
	// Validates: Requirement 1.5.
	ErrHeaderStyleRequired = errors.New("headerStyle is required")

	// ErrHeaderStyleInvalid is returned when headerStyle is non-empty
	// but not one of the three allowlisted values.
	// Validates: Requirement 1.6.
	ErrHeaderStyleInvalid = errors.New("headerStyle must be one of openai, anthropic, gemini")
)

// validateEntry checks the field-presence + header-style allowlist
// invariants every Entry must satisfy before persistence. It is the
// shared gate consulted by Service.Create, Service.Update, and the
// HTTP handlers — keeping the policy in one place avoids drift
// between the in-process and HTTP surfaces.
//
// Per the task brief, validateEntry only enforces the four
// emptiness checks and the headerStyle allowlist. The id regex
// (idRE) is enforced separately by Service.Create / Service.Update
// because Update accepts the id from the URL path rather than from
// the body, so the two sites apply the regex against different
// inputs.
//
// Validates: Requirements 1.5, 1.6.
func validateEntry(e Entry) error {
	if e.ID == "" {
		return ErrIDRequired
	}
	if e.DisplayName == "" {
		return ErrDisplayNameRequired
	}
	if e.BaseURL == "" {
		return ErrBaseURLRequired
	}
	if e.HeaderStyle == "" {
		return ErrHeaderStyleRequired
	}
	if _, ok := headerStyles[e.HeaderStyle]; !ok {
		return fmt.Errorf("%w: got %q", ErrHeaderStyleInvalid, e.HeaderStyle)
	}
	return nil
}
