// Package auth — on-disk Profile shape and the narrow CatalogResolver
// interface that Profile_Store needs from Catalog_Service.
//
// This file declares the Profile struct (the union of API_Key_Profile
// and OAuth_Profile fields per the design), the ProfileType
// discriminator constants, and the CatalogResolver interface used by
// Store.Put to reject unknown providers (Requirement 4.8).
//
// Keeping the resolver interface here — rather than importing
// internal/providers from internal/auth — preserves a one-way
// dependency (providers → auth via the interface; auth never imports
// providers). *providers.Service satisfies CatalogResolver
// structurally because its Get / IsEmpty signatures match.
package auth

import (
	"context"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// ProfileType discriminates between the two stored credential shapes.
// Validates: Requirements 4.5, 4.6.
type ProfileType string

const (
	// APIKey marks a profile that holds a stored API key plus an
	// optional baseURL override.
	APIKey ProfileType = "api_key"

	// OAuth marks a profile that holds access/refresh tokens plus
	// expiry metadata obtained through one of the four OAuth flows.
	OAuth ProfileType = "oauth"
)

// Profile is the on-disk and in-memory shape persisted in
// auth-profiles.json. The struct is the union of all fields used by
// API_Key_Profile and OAuth_Profile records — the Type field
// discriminates which subset is meaningful for any given record.
//
// Credential fields (APIKey, AccessToken, RefreshToken) are PLAINTEXT
// in this struct. Masking happens at the HTTP boundary in
// internal/web (Wave E task 5.2, see maskAuthCredential in masks.go).
// Callers inside the process tree (the LLM client resolver, the
// OAuth drivers) consume the plaintext values directly.
//
// Per the design, Provider must match an existing Catalog_Entry.id
// (Store.Put enforces this via the CatalogResolver) and ProfileID
// matches ^[a-z0-9][a-z0-9_-]{0,63}$ (Requirement 4.2). The regex
// itself is enforced in Store.Put rather than here so the validation
// site sees both fields together.
//
// Validates: Requirements 4.1, 4.2, 4.5, 4.6, 10.4.
type Profile struct {
	Provider  string      `json:"provider"`
	ProfileID string      `json:"profileId"`
	Type      ProfileType `json:"type"`

	// API_Key_Profile fields. Populated when Type == APIKey.
	APIKey          string `json:"apiKey,omitempty"`
	APIBaseOverride string `json:"apiBaseOverride,omitempty"`

	// OAuth_Profile fields. Populated when Type == OAuth.
	AccessToken  string    `json:"accessToken,omitempty"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	TokenType    string    `json:"tokenType,omitempty"`

	// RequiresReauth is set by Driver.Refresh when the upstream
	// refresh attempt returned invalid_grant — the caller (the
	// /api/scan path or the dashboard refresh button) sees this
	// via HTTP 401 oauth refresh required.
	// Validates: Requirement 10.4.
	RequiresReauth bool `json:"requiresReauth,omitempty"`

	// UpdatedAt records the last successful Put. Maintained by the
	// Store, not by callers; any value supplied on input is
	// overwritten by Put with the current wall clock.
	UpdatedAt time.Time `json:"updatedAt"`
}

// Key returns the canonical "<provider>:<profileId>" identity the
// rest of the system uses to reference a profile (Requirement 4.2).
// The format is fixed: a single ':' separator, no escaping — both
// halves are constrained by ^[a-z0-9][a-z0-9_-]{0,63}$ so neither
// can contain a colon.
func (p Profile) Key() string {
	return p.Provider + ":" + p.ProfileID
}

// CatalogResolver is the narrow surface Profile_Store needs from
// Catalog_Service. It is declared here, in the auth package, so the
// dependency only flows providers → auth via this interface; auth
// itself does not import internal/providers transitively for any
// runtime symbol other than the providers.Entry type returned from
// Get. *providers.Service satisfies this interface structurally
// because its IsEmpty / Get signatures match.
//
// Validates: Requirement 4.8 — Store.Put consults Get to reject
// unknown providers before persisting.
type CatalogResolver interface {
	// IsEmpty reports whether the catalog currently has zero
	// entries. Used by upstream callers (the LLM resolver in
	// Wave D task 4.1) to decide Legacy_Fallback eligibility;
	// Store.Put itself does not need this, but the interface is
	// shared so callers can hold a single CatalogResolver
	// reference.
	IsEmpty() bool

	// Get returns the catalog entry for id with a (entry, found,
	// error) tuple matching providers.Service.Get. Store.Put uses
	// found==false to surface ErrUnknownProvider per Requirement
	// 4.8.
	Get(ctx context.Context, id string) (providers.Entry, bool, error)
}
