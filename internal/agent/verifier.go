// Package agent — verifier.go implements the independent, distinct-purpose
// Verifier agent. It is a deliberately separate role from the hunting/
// exploitation agent: its ONLY job is to adversarially re-test a candidate
// finding and decide whether it is a real, reproducible vulnerability.
//
// The Verifier is wired into the reporting choke point (report_vulnerability):
// every medium+ candidate must survive independent re-testing before it is
// persisted as a validated finding. This is what backs the product promise —
// "real validation, not just detection."
//
// Design constraints:
//   - Distinct purpose: skeptical triager, NOT a hunter.
//   - Restricted tools: read-only re-testing only (terminal/curl, http, browser,
//     notes, web_search). It CANNOT call report_vulnerability or spawn agents,
//     so it can never recurse or self-confirm.
//   - Bounded: a turn cap and an 8-minute wall-clock deadline keep it safely
//     under report_vulnerability's 15-minute tool watchdog (avoiding any race
//     on the shared LLM client, which the blocked main loop is not using).
package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/browser"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
	"github.com/xalgord/xalgorix/v4/internal/tools/websearch"
)

const (
	verifierMaxTurns = 16
	verifierDeadline = 8 * time.Minute
)

// verifyFinding is the FindingVerifier installed into the reporting package.
// It builds a restricted, read-only registry and runs a bounded adversarial
// loop that ends when the model calls submit_verdict (or budget is exhausted).
func (a *Agent) verifyFinding(req reporting.VerificationRequest) reporting.VerificationVerdict {
	if a.client == nil {
		return reporting.VerificationVerdict{Inconclusive: true, Reason: "no LLM client available for verification"}
	}
	if a.stopped.Load() {
		return reporting.VerificationVerdict{Inconclusive: true, Reason: "scan stopped before verification"}
	}

	// Restricted, read-only tool registry — no reporting, no agent spawning.
	vreg := tools.NewRegistry()
	vreg.SetScanContextID(a.scanCtx.ID)
	terminal.Register(vreg)
	httpclient.Register(vreg)
	browser.Register(vreg)
	notes.Register(vreg)
	websearch.Register(vreg)

	var verdict *reporting.VerificationVerdict
	vreg.Register(&tools.Tool{
		Name:        "submit_verdict",
		Description: "Submit your FINAL verdict on the candidate finding. Call exactly once when done re-testing.",
		Parameters: []tools.Parameter{
			{Name: "verdict", Description: "One of: 'confirmed' (you independently reproduced real impact), 'rejected' (you can POSITIVELY show it is NOT a vulnerability — by-design / circular / mislabeled / no impact), or 'inconclusive' (you could not reproduce it but also could not disprove it).", Required: true},
			{Name: "reason", Description: "Concise justification for the verdict", Required: true},
			{Name: "evidence", Description: "The concrete evidence you observed (command output, response excerpt, baseline/control comparison)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			v := strings.ToLower(strings.TrimSpace(args["verdict"]))
			res := reporting.VerificationVerdict{
				Reason:   strings.TrimSpace(args["reason"]),
				Evidence: strings.TrimSpace(args["evidence"]),
			}
			switch v {
			case "confirmed", "confirm", "true", "yes", "valid":
				res.Confirmed = true
			case "inconclusive", "unknown", "unsure", "maybe":
				res.Inconclusive = true
			default: // "rejected", "false", "invalid", "no", or anything unrecognized
				// Unrecognized verdicts are treated as inconclusive, NOT rejected,
				// so a malformed verdict can never silently drop a real finding.
				if v != "rejected" && v != "reject" && v != "false" && v != "invalid" && v != "no" {
					res.Inconclusive = true
				}
			}
			verdict = &res
			return tools.Result{Output: "verdict recorded: " + v}, nil
		},
	})

	msgs := []llm.Message{
		{Role: "system", Content: buildVerifierPrompt(req, vreg.SchemaXML())},
		{Role: "user", Content: "Independently re-test the candidate finding NOW using the tools. Do NOT trust the original proof — reproduce it yourself, include a negative/baseline control where applicable, then call submit_verdict with your decision."},
	}

	a.emit(Event{Type: "message", Content: fmt.Sprintf("🔎 Verifier: independently re-testing candidate %q before it can be reported...", req.Title)})
	a.client.SetTemperature(TempValidator)

	deadline := time.Now().Add(verifierDeadline)
	for turn := 0; turn < verifierMaxTurns && verdict == nil; turn++ {
		if a.stopped.Load() {
			return reporting.VerificationVerdict{Inconclusive: true, Reason: "scan stopped during verification"}
		}
		if time.Now().After(deadline) {
			return reporting.VerificationVerdict{Inconclusive: true, Reason: "verification exceeded time budget"}
		}

		resp, err := a.client.Chat(msgs)
		if err != nil {
			// One retry, then give up (inconclusive — never auto-confirm on error).
			resp, err = a.client.Chat(msgs)
			if err != nil {
				return reporting.VerificationVerdict{Inconclusive: true, Reason: "verifier LLM error: " + err.Error()}
			}
		}

		clean := stripThink(resp)
		msgs = append(msgs, llm.Message{Role: "assistant", Content: resp})

		toolCalls := llm.ParseToolCalls(clean)
		if len(toolCalls) == 0 {
			msgs = append(msgs, llm.Message{Role: "user", Content: "You did not call a tool. Re-test with a tool, or call submit_verdict with your decision now."})
			continue
		}

		for _, tc := range toolCalls {
			if tc.Name == "submit_verdict" {
				_, _ = vreg.Execute(tc.Name, tc.Args)
				break
			}
			// Route through the SAME scope guard + hard-timeout the main agent
			// applies, so the verifier cannot probe out-of-scope/local hosts and
			// a hung re-test cannot outlive the report_vulnerability call.
			res := a.execVerifierToolGuarded(vreg, tc.Name, tc.Args)
			out := res.Output
			if res.Error != "" {
				out = "error: " + res.Error
			}
			a.emit(Event{Type: "tool_result", ToolName: "verify:" + tc.Name, ToolResult: res})
			msgs = append(msgs, llm.Message{Role: "user", Content: fmt.Sprintf("[%s output]\n%s", tc.Name, truncStr(out, 4000))})
			if verdict != nil {
				break
			}
		}
	}

	if verdict == nil {
		return reporting.VerificationVerdict{Inconclusive: true, Reason: "verifier did not reach a verdict within the turn budget"}
	}

	if verdict.Confirmed {
		a.emit(Event{Type: "message", Content: fmt.Sprintf("✅ Verifier CONFIRMED: %s", req.Title)})
	} else {
		a.emit(Event{Type: "message", Content: fmt.Sprintf("🚫 Verifier REJECTED %q: %s", req.Title, verdict.Reason)})
	}
	return *verdict
}

// execVerifierToolGuarded runs a verifier re-test tool through the SAME scope
// guard and hard-timeout the main agent applies to its own tool calls. Without
// this, the verifier's direct registry execution would bypass the
// localhost/RFC1918/dashboard-listener guard and the per-tool watchdog —
// letting it probe hosts the main agent blocks and leaving a hung tool running
// past the report_vulnerability ceiling.
func (a *Agent) execVerifierToolGuarded(vreg *tools.Registry, name string, args map[string]string) tools.Result {
	if blocked, reason := a.shouldBlockForOutOfScope(name, args); blocked {
		return tools.Result{Output: "⛔ OUT-OF-SCOPE TARGET BLOCKED — " + reason +
			"\nYou cannot probe this host during verification. If the finding depends on reaching it, it is not independently verifiable here — submit an 'inconclusive' verdict."}
	}

	resultCh := make(chan tools.Result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultCh <- tools.Result{Error: fmt.Sprintf("verifier tool panicked: %v", r)}
			}
		}()
		res, err := vreg.Execute(name, args)
		if err != nil && res.Error == "" {
			res.Error = err.Error()
		}
		resultCh <- res
	}()

	timeout := a.hardTimeoutFor(name)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-resultCh:
		a.touchActivity()
		return res
	case <-timer.C:
		switch name {
		case "terminal_execute", "python_action":
			a.scanCtx.Terminal.KillAll()
		case "browser_action":
			browser.CleanupContext(a.scanCtx.ID)
		}
		return tools.Result{Error: fmt.Sprintf("[verifier tool %q TIMEOUT after %s]", name, timeout)}
	case <-a.ctx.Done():
		return tools.Result{Error: "agent stopped during verification"}
	}
}

// buildVerifierPrompt produces the adversarial verifier system prompt.
func buildVerifierPrompt(req reporting.VerificationRequest, toolSchema string) string {
	return fmt.Sprintf(`You are the XALGORIX INDEPENDENT VERIFIER — a skeptical senior security engineer whose ONLY job is to confirm or DISPROVE a candidate vulnerability that another agent claims to have found. You are NOT a hunter. You do not look for new bugs. You re-test THIS finding and decide if it is real.

Your default stance is DISBELIEF. Most "findings" are false positives. Assume this one is wrong until your own re-testing proves otherwise.

## CANDIDATE FINDING (claimed by the hunting agent — treat as UNVERIFIED)
- Title:        %s
- Severity:     %s
- CWE:          %s
- Claimed via:  %s (verification_method)
- CVSS vector:  %s
- Target:       %s
- Endpoint:     %s
- HTTP method:  %s

Description:
%s

Claimed proof (DO NOT TRUST — reproduce it yourself):
%s

## YOUR JOB
1. Re-run the test yourself with the tools. Reproduce the EXACT observable the claim depends on.
2. Use a NEGATIVE/BASELINE CONTROL: compare against an un-injected/benign request, an unauthenticated vs authenticated request, baseline vs payload timing, etc. A difference you cannot tie to the control is not proof.
3. Apply the EVIDENCE STANDARD — the claim is only real if the evidence matches the class:
   - SSRF (CWE-918): the TARGET'S SERVER made the request (OOB callback or internal-only resource). Browser/client-side URL handling is NOT SSRF.
   - XSS (CWE-79): the script actually EXECUTED (alert(document.domain), OOB callback, screenshot). Reflection alone is NOT XSS.
   - SQLi (CWE-89): extracted data, a DB error, or a DIFFERENTIAL repeated time delay. A single slow response is NOT proof.
   - Access control / IDOR: protected DATA returned or a real STATE CHANGE. A 200 (especially empty body) on POST/PUT/DELETE/OPTIONS is NOT access — usually CORS preflight / no-op.
   - Info disclosure (CWE-200): an actual secret VALUE leaked. Field/parameter NAMES, public OpenAPI/Swagger specs, and by-design data are NOT disclosure.
4. Sanity-check the narrative: Is this the intended behavior of the technology? Did the "attacker" supply the secret themselves (a token placed in the URL cannot be "stolen" — circular)? Is the CVSS impact (C/I/A) actually demonstrated?
5. EVIDENCE PROVENANCE — the proof must demonstrate THIS finding's OWN mechanism. If the evidence was actually obtained through a DIFFERENT vulnerability (e.g. "SQLi" proven by dumping the database through an RCE/eval bug instead of through the injection point), it does NOT prove this finding. Re-test the claimed mechanism directly at its own injection point. If only the other vulnerability works, this finding is inconclusive (or rejected if the claimed point is not actually injectable).
6. BLIND CLASSES (blind XXE / blind SSRF / blind SQLi) — a generic "success"/"OK"/"request made" response is NOT proof. Require an out-of-band callback (interactsh / Burp Collaborator / your own listener) OR actually-retrieved data/file content (e.g. /etc/passwd contents). If you only observe a generic success message with no OOB hit and no returned data, mark inconclusive — do not confirm.

## VERDICT RULES
- "confirmed" ONLY if YOU independently reproduced real, exploitable impact, ideally with a control.
- "rejected" ONLY if you can POSITIVELY show it is NOT a vulnerability: by-design behavior, circular/attacker-supplied "secret", mislabeled class, encoded/non-executing payload, an empty/no-op response, or you reproduced the request and it demonstrably does nothing.
- "inconclusive" if you could NOT reproduce it AND could NOT disprove it — e.g. it needs authentication, a second account, specific state, or timing you don't have, or it is a blind/stored finding that fires somewhere you cannot observe.

CRITICAL: NEVER mark a finding "rejected" merely because you could not reproduce it. Rejection means you actively DISPROVED it. If you have not disproven it, the verdict is "inconclusive" — that finding is preserved (flagged for manual review), not dropped. Dropping a real vulnerability is a serious error; preserving an unproven one as inconclusive is safe. Reserve "rejected" for findings you are confident are false.

Re-test now, then call submit_verdict exactly once.

## TOOLS (read-only re-testing — you cannot report or spawn agents)
%s

Call tools using the XML format shown above.`,
		valueOr(req.Title, "(none)"),
		valueOr(req.Severity, "(none)"),
		valueOr(req.CWE, "(none)"),
		valueOr(req.VerificationMethod, "(none)"),
		valueOr(req.CVSSVector, "(none)"),
		valueOr(req.Target, "(none)"),
		valueOr(req.Endpoint, "(none)"),
		valueOr(req.HTTPMethod, "(none)"),
		valueOr(req.Description, "(none)"),
		valueOr(req.Proof, "(none)"),
		toolSchema,
	)
}

func valueOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
