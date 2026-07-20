package reporting

import "testing"

// A Host-header / deployment-protection "bypass" that only reaches public
// production content is a false positive. It must carry a production-direct
// control showing the direct response DIFFERS (staging-only content). Without
// that differential it is rejected at medium+.
func TestCheckFalsePositive_HostHeaderDeploymentBypass(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{
			name:       "vercel staging host-header bypass, no control (the reported FP)",
			title:      "Vercel Deployment Protection bypass via Host header",
			desc:       "staging.store returns 401 but adding Host: store.nintendo.fr returns 200 with JSON + cookies, bypassing the password protection",
			severity:   "high",
			proof:      "curl staging with Host override -> 200, EUID cookie adb831..., /api/customer JSON returned. 401 -> 200 via Host header.",
			wantReject: true,
		},
		{
			name:       "generic host-header password-protection bypass, no baseline",
			title:      "Password protection bypass via Host header",
			desc:       "401 changes to 200 when Host is overridden",
			severity:   "medium",
			proof:      "Sent Host: prod-alias, got 200 and the app loaded.",
			wantReject: true,
		},
		{
			name:       "real bypass with production-direct control showing difference → accepted",
			title:      "Deployment protection bypass exposes staging-only debug endpoint",
			desc:       "Host override reaches a staging-only /debug/env route",
			severity:   "high",
			proof:      "Via Host trick: GET /debug/env -> 200 with staging env vars. Control: production directly returns 404 for /debug/env — this route is not available on production, staging-only.",
			wantReject: false,
		},
		{
			name:       "info severity exempt",
			title:      "Host header behavior on staging",
			desc:       "401 to 200 via host",
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
