package agent

import "testing"

func TestActivityPolicyBlocksPassiveScanningDirectTarget(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "passive", []string{"https://example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "curl -sk https://example.com/login",
	})
	if !blocked {
		t.Fatal("expected passive scanning to block direct target curl")
	}
	if reason == "" {
		t.Fatal("expected block reason")
	}
}

func TestActivityPolicyAllowsPassiveThirdPartyLookup(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "passive", []string{"example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": `curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value'`,
	})
	if blocked {
		t.Fatalf("passive third-party lookup was blocked: %s", reason)
	}
}

func TestActivityPolicyAllowsPassiveLocalArtifactAnalysis(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "passive", []string{"example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "grep -R \"example.com\" scan.json notes.json findings.json",
	})
	if blocked {
		t.Fatalf("passive local artifact analysis was blocked: %s", reason)
	}
}

func TestActivityPolicyBlocksActiveAccessAfterLocalArtifactCommand(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "passive", []string{"example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "grep -R example.com scan.json && curl -sk https://example.com/login",
	})
	if !blocked {
		t.Fatal("expected passive policy to block active access chained after local artifact analysis")
	}
	if reason == "" {
		t.Fatal("expected block reason")
	}
}

func TestActivityPolicyPassiveReconGuardCountsLocalArtifacts(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "active", []string{"example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "grep -R \"example.com\" scan.json notes.json",
	})
	if blocked {
		t.Fatalf("passive local artifact analysis was blocked: %s", reason)
	}
	if a.passiveReconPassiveLookups != 1 {
		t.Fatalf("local artifact lookup count = %d, want 1", a.passiveReconPassiveLookups)
	}

	blocked, reason = a.shouldBlockForActivityPolicy("web_search", map[string]string{
		"query": "example.com subdomains public search results",
	})
	if blocked {
		t.Fatalf("web_search should be allowed during passive recon guard: %s", reason)
	}
	if msg := a.maybeCompletePassiveReconGuardAtIterationStart(2); msg == "" {
		t.Fatal("expected local artifacts plus web search to complete passive recon guard")
	}
}

func TestActivityPolicyBlocksPassiveReconDiscoveryBrowser(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "active", []string{"example.com"})
	a.SetDiscoveryMode(true)

	blocked, _ := a.shouldBlockForActivityPolicy("browser_action", map[string]string{
		"command": "goto",
		"url":     "https://example.com",
	})
	if !blocked {
		t.Fatal("expected passive recon discovery to block browser target access")
	}
}

func TestActivityPolicyBlocksPassiveReconFullScanUntilPassiveLookup(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "active", []string{"example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "curl -sk https://example.com/login",
	})
	if !blocked {
		t.Fatal("expected passive recon guard to block direct target curl before passive lookup")
	}
	if reason == "" {
		t.Fatal("expected block reason")
	}

	blocked, reason = a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": `curl -s "https://crt.sh/?q=%.example.com&output=json"`,
	})
	if blocked {
		t.Fatalf("passive lookup should be allowed during passive recon guard: %s", reason)
	}
	if a.passiveReconPassiveLookups != 1 {
		t.Fatalf("expected passive lookup to be recorded, got %d", a.passiveReconPassiveLookups)
	}
	if msg := a.maybeCompletePassiveReconGuardAtIterationStart(1); msg != "" {
		t.Fatalf("single passive lookup should not complete recon guard: %s", msg)
	}
	blocked, _ = a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "curl -sk https://example.com/login",
	})
	if !blocked {
		t.Fatal("expected passive recon guard to keep blocking direct target access after only one passive lookup")
	}

	blocked, reason = a.shouldBlockForActivityPolicy("web_search", map[string]string{
		"query": "example.com subdomains public search results",
	})
	if blocked {
		t.Fatalf("web_search should be allowed during passive recon guard: %s", reason)
	}
	if msg := a.maybeCompletePassiveReconGuardAtIterationStart(2); msg == "" {
		t.Fatal("expected two independent passive lookups to complete recon guard")
	}
	blocked, reason = a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "curl -sk https://example.com/login",
	})
	if blocked {
		t.Fatalf("active scan should allow direct target access after passive recon guard completes: %s", reason)
	}
}

func TestActivityPolicyPassiveScanningStillBlocksAfterReconGuardComplete(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("passive", "passive", []string{"example.com"})
	a.finishPassiveReconGuard()

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "curl -sk https://example.com/login",
	})
	if !blocked {
		t.Fatal("expected passive scanning to keep blocking direct target access")
	}
	if reason == "" {
		t.Fatal("expected block reason")
	}
}

func TestActivityPolicyDefaultActiveDoesNotBlock(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("", "", []string{"example.com"})

	blocked, reason := a.shouldBlockForActivityPolicy("terminal_execute", map[string]string{
		"command": "nmap -sV example.com",
	})
	if blocked {
		t.Fatalf("active policy should not block: %s", reason)
	}
}
