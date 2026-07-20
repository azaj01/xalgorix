package reporting

import "testing"

// HTTP request smuggling / desync findings must carry a differential proof
// (timing hang vs. baseline, or cross-connection victim contamination). The
// canonical automated FP — HTTP/1.1 pipelining + a redirect engine echoing the
// path into Location, misread as a CL.TE desync + cache poisoning — must be
// rejected at medium+.
func TestCheckFalsePositive_RequestSmuggling(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{
			name:       "pipelining + redirect echo misread as desync (the reported FP)",
			title:      "CL.TE HTTP Request Smuggling",
			desc:       "CL.TE desync enabling cache poisoning and request hijacking",
			severity:   "high",
			proof:      "Sent smuggling request, got 2 responses in 0.20s. Canary reflected in Location: https://host/ECHO-BASELINE. x-cache: HIT on the redirect.",
			wantReject: true,
		},
		{
			name:       "two responses only, no headers ruled out",
			title:      "HTTP Desync (TE.CL)",
			desc:       "Two responses returned from one connection",
			severity:   "critical",
			proof:      "The smuggled request produced two HTTP responses on the same socket.",
			wantReject: true,
		},
		{
			name:       "front-end simply rejected the malformed request",
			title:      "Request smuggling via conflicting CL and TE",
			desc:       "ALB desync",
			severity:   "high",
			proof:      "Sent conflicting Content-Length and Transfer-Encoding; got 405 Method Not Allowed.",
			wantReject: true,
		},
		{
			name:       "genuine timing differential → accepted",
			title:      "CL.TE HTTP Request Smuggling",
			desc:       "Back-end desyncs on incomplete chunk",
			severity:   "high",
			proof:      "Time-based probe: the CL.TE request hung for 9.8s while an identical baseline request returned instantly (0.2s). Reproduced 3x.",
			wantReject: false,
		},
		{
			name:       "genuine cross-connection victim contamination → accepted",
			title:      "HTTP Request Smuggling (TE.CL)",
			desc:       "Smuggled prefix poisons the next request",
			severity:   "critical",
			proof:      "A victim request on a separate connection received a 302 redirect to /admin that it never requested — the smuggled prefix landed on the victim socket.",
			wantReject: false,
		},
		{
			name:       "info severity is exempt",
			title:      "Possible HTTP desync",
			desc:       "two responses observed",
			severity:   "info",
			proof:      "",
			wantReject: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("checkFalsePositive(%q) reject=%v, want %v (msg=%q)",
					tt.title, gotReject, tt.wantReject, result)
			}
		})
	}
}
