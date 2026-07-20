package reporting

import "testing"

// OAuth `state` is validated by the client app, not the authorization server.
// A "CSRF" finding whose only proof is the authorize endpoint accepting/echoing
// state=test must be rejected at medium+; a full-callback proof passes.
func TestCheckFalsePositive_OAuthStateCSRF(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{
			name:       "state=test accepted by authorize endpoint (the reported FP)",
			title:      "OAuth CSRF — missing state validation",
			desc:       "The authorize endpoint accepts state=test with no rejection, proving CSRF protection is nonexistent",
			severity:   "high",
			proof:      "Sent state=test to /oauth2/authorize -> HTTP 200, no AADSTS error. Also XALGORIX-GARBAGE and empty state both returned 200.",
			wantReject: true,
		},
		{
			name:       "state parameter echoed, medium",
			title:      "Missing state validation in OAuth flow",
			desc:       "state parameter is reflected back unchanged",
			severity:   "medium",
			proof:      "authorize endpoint echoed the arbitrary state value in the response",
			wantReject: true,
		},
		{
			name:       "genuine state CSRF with callback completion → accepted",
			title:      "OAuth CSRF via missing state validation",
			desc:       "Client app accepts an unissued state at the callback",
			severity:   "high",
			proof:      "Completed the flow: the callback at app.example.com/callback accepted ?code=...&state=test that it never issued and logged me into the victim's account (usable session).",
			wantReject: false,
		},
		{
			name:       "info severity exempt",
			title:      "OAuth state parameter observation",
			desc:       "state accepted at authorize",
			severity:   "info",
			proof:      "",
			wantReject: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			if gotReject := result != ""; gotReject != tt.wantReject {
				t.Errorf("reject=%v want %v (msg=%q)", gotReject, tt.wantReject, result)
			}
		})
	}
}

// Public OAuth/OIDC identifiers (tenant ID, client_id, openid-configuration,
// branding) are not secrets; reporting them as disclosure is rejected unless a
// real credential is included.
func TestCheckFalsePositive_OAuthPublicIdentifiers(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{
			name:       "azure tenant id disclosure",
			title:      "Sensitive information disclosure: Azure AD tenant ID",
			desc:       "The Azure AD tenant UUID is exposed via openid-configuration",
			severity:   "medium",
			proof:      "GET /.well-known/openid-configuration returns tenant id 12345678-...",
			wantReject: true,
		},
		{
			name:       "client_id leak",
			title:      "OAuth client_id disclosure",
			desc:       "client_id leaked in authorization URL",
			severity:   "high",
			proof:      "client_id=abcd visible in the authorize request",
			wantReject: true,
		},
		{
			name:       "tenant branding exposed",
			title:      "Information disclosure of tenant branding",
			desc:       "Tenant branding 'Nintendo of Europe' exposed on login page",
			severity:   "low",
			proof:      "login page shows the org display name",
			wantReject: true,
		},
		{
			name:       "real client_secret leak → not rejected by the OAuth-public-id gate",
			title:      "OAuth client_id and client_secret exposed via config endpoint",
			desc:       "client_secret leaked from an unauthenticated /config API",
			severity:   "critical",
			proof:      "GET /api/config returned client_secret=SUPER-SECRET-VALUE; exchanged it at /oauth/token for a valid access token",
			wantReject: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			if gotReject := result != ""; gotReject != tt.wantReject {
				t.Errorf("reject=%v want %v (msg=%q)", gotReject, tt.wantReject, result)
			}
		})
	}
}
