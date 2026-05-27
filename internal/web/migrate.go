// Package web — one-time legacy provider migration importer (Wave G
// task 7.1 of the provider-catalog-and-oauth spec).
//
// The migration importer is a confirmation-gated, dashboard-driven
// helper that converts an operator's legacy XALGORIX_LLM /
// XALGORIX_API_KEY / XALGORIX_API_BASE settings into a single
// Catalog_Entry + API_Key_Profile pair so the rest of the catalog
// surface (Settings → Providers tab, per-scan provider_profile
// picker) becomes immediately useful for installs that upgraded
// from the API-key-only build.
//
// Two endpoints back the dashboard banner described in the design's
// Migration section:
//
//   • GET  /api/providers/migrate-legacy/status  — eligibility probe.
//     Cheap, idempotent, and side-effect free; the dashboard polls
//     it on load to decide whether to render the banner. Returns
//     {eligible: bool, reason?: string}.
//
//   • POST /api/providers/migrate-legacy        — perform the
//     migration. Re-checks eligibility under the catalog/profile
//     mutex order, creates one Catalog_Entry (id="legacy",
//     displayName="Legacy"), one API_Key_Profile (legacy:default),
//     and writes a sentinel ~/.xalgorix/data/.legacy-providers-migrated
//     so the banner never reappears.
//
// Eligibility rules (mirrors the design's Migration section):
//
//   1. cfg.LLM != "" OR cfg.APIKey != ""           — operator has
//      legacy configuration to migrate.
//   2. ~/.xalgorix/data/providers.json absent OR empty  — catalog
//      is unpopulated; otherwise the operator already moved on.
//   3. ~/.xalgorix/data/auth-profiles.json absent OR empty  — same,
//      for credentials.
//   4. ~/.xalgorix/data/.legacy-providers-migrated absent — the
//      sentinel guarantees idempotence even across restarts.
//
// Importer never touches ~/.xalgorix.env — the legacy env-var path
// keeps working unchanged after the import (Requirement 15.5). The
// new catalog entry is purely additive: the operator can switch the
// new-scan picker to "legacy:default" or keep using the existing
// free-text Settings form.
//
// Routes are mounted in Server.Start (Wave E surface, see server.go)
// alongside the rest of /api/providers/*. Both endpoints inherit
// authMw (Authenticated_Operator gate, R12.4) and the global
// isCSRFSafe gate (R12.5) — there is no per-handler CSRF logic
// because the global authMiddleware already covers it for every
// state-changing /api/* request.
//
// Validates: Requirements 2.1, 2.2, 4.5, 15.4, 15.5.
package web

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// legacyMigrateSentinelName is the sentinel-file basename written
// after a successful migration run. Living under s.dataDir alongside
// providers.json / auth-profiles.json keeps every catalog-related
// artifact in the same securely-mode-700 directory tree.
const legacyMigrateSentinelName = ".legacy-providers-migrated"

// legacyMigrateStatusResponse is the wire shape returned by
// handleLegacyMigrateStatus. The Reason field is omitempty so the
// happy-path eligible:true response carries no extra payload.
type legacyMigrateStatusResponse struct {
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason,omitempty"`
}

// legacyProviderPrefix returns the slug portion of an XALGORIX_LLM
// value (the part before the first '/'), lowercased. An empty input
// returns the empty string. The split mirrors LegacyProviderShape's
// own parsing so an LLM value that LegacyProviderShape would accept
// also produces a usable slug here.
func legacyProviderPrefix(xalgorixLLM string) string {
	s := strings.ToLower(strings.TrimSpace(xalgorixLLM))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i]
	}
	return s
}

// legacyHeaderStyleFor maps a legacy provider slug to one of the
// three header styles the catalog allows ("openai" | "anthropic" |
// "gemini"). The mapping mirrors the request-shape switch used by
// the LLM client today: anthropic → "anthropic", google/gemini →
// "gemini", everything else (openai, minimax, deepseek, groq,
// ollama, plus arbitrary unknown values) → "openai" since those
// providers all speak the OpenAI-compatible chat-completions API.
//
// An empty slug returns "openai" so callers always receive a valid
// allowlist value — providers.validateEntry would otherwise reject
// the migration write with ErrHeaderStyleInvalid.
func legacyHeaderStyleFor(provider string) string {
	switch strings.ToLower(provider) {
	case "anthropic":
		return "anthropic"
	case "google", "gemini":
		return "gemini"
	default:
		return "openai"
	}
}

// legacyMigrateBaseURL picks the BaseURL to stamp into the
// migrated Catalog_Entry. Operator-supplied cfg.APIBase wins —
// that's the explicit override the operator chose in the existing
// Settings form. Otherwise we fall back to the default base URL
// for the detected provider slug via the canonical
// llm.LegacyProviderBaseURL lookup; an unknown or empty slug
// falls through to the OpenAI default so validateEntry's
// required-field check passes.
//
// Validates: Requirement 2.3 (BaseURL preservation); H7 (single
// source of truth via llm.LegacyProviderBaseURL).
func legacyMigrateBaseURL(cfg legacyMigrateSourceConfig, provider string) string {
	if v := strings.TrimSpace(cfg.APIBase); v != "" {
		return v
	}
	if base, ok := llm.LegacyProviderBaseURL(provider); ok {
		return base
	}
	// Fall back to the OpenAI default rather than empty so the
	// resulting Entry passes validateEntry. Operators with truly
	// unknown providers should populate cfg.APIBase explicitly.
	openai, _ := llm.LegacyProviderBaseURL("openai")
	return openai
}

// legacyMigrateSourceConfig captures only the cfg fields the
// importer reads. Defining a narrow input shape keeps the helpers
// testable without instantiating a full config.Config and makes it
// obvious to a reader that the importer never touches anything
// beyond LLM, APIKey, APIBase.
type legacyMigrateSourceConfig struct {
	LLM     string
	APIKey  string
	APIBase string
}

// fileAbsentOrEmpty reports whether the file at path either does
// not exist or has zero bytes. Either condition counts as "not
// populated" for the purposes of the eligibility gate — a file
// containing literal "{}" with non-zero size is still considered
// populated by this helper, but the catalog/profile readers
// themselves treat such a payload as the parse-error path which
// would have already disqualified the migration anyway.
//
// Stat errors other than os.ErrNotExist (permission denied, ELOOP,
// stale NFS handle, etc.) return false — we treat the file as
// "populated, leave it alone" so the migration write path surfaces
// the underlying error directly instead of clobbering the
// problematic file. Earlier the gate treated every stat error as
// "absent" which let a permission failure silently advance the
// migration into a half-written state. M3.
//
// We deliberately do NOT call providers.Service.IsEmpty /
// auth.Store.List here because the importer's ServiceUnavailable
// path uses the same eligibility helper as the status endpoint,
// and we want the status probe to work even when the in-memory
// Service / Store are nil (e.g. their constructors failed at
// startup and the dashboard is showing a banner urging the
// operator to fix the file). The on-disk byte size is the single
// source of truth that doesn't depend on a healthy in-memory
// snapshot.
func fileAbsentOrEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	return info.Size() == 0
}

// sentinelExists reports whether the migration sentinel file is
// present at path. Any non-not-exist stat error is treated as
// "exists" — if the dashboard cannot read the directory, hiding the
// banner is the safer default than offering an action that will
// itself fail with the same permission error.
func sentinelExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrNotExist) || os.IsNotExist(err) {
		return false
	}
	return true
}

// legacyMigrateEligibility returns the eligibility decision plus a
// machine-readable reason string for any "not eligible" result.
// Both endpoints share this helper so the reason surfaced by GET
// matches what POST would have rejected.
//
// Reason values are stable, lowercased, and use snake_case so the
// dashboard can branch on them programmatically without parsing
// human prose.
func (s *Server) legacyMigrateEligibility() (bool, string) {
	cfg := s.legacyMigrateConfigSnapshot()
	if strings.TrimSpace(cfg.LLM) == "" && strings.TrimSpace(cfg.APIKey) == "" {
		return false, "no_legacy_config"
	}
	if s.dataDir == "" {
		// dataDir is set in NewServer; an empty value here is a
		// programming error rather than a normal runtime state.
		// Surface it as ineligible so the banner stays hidden.
		return false, "data_dir_unset"
	}
	if sentinelExists(filepath.Join(s.dataDir, legacyMigrateSentinelName)) {
		return false, "already_migrated"
	}
	if !fileAbsentOrEmpty(filepath.Join(s.dataDir, "providers.json")) {
		return false, "catalog_already_populated"
	}
	if !fileAbsentOrEmpty(filepath.Join(s.dataDir, "auth-profiles.json")) {
		return false, "profiles_already_populated"
	}
	return true, ""
}

// legacyMigrateConfigSnapshot copies the three legacy fields off
// s.cfg into the importer's narrow input shape. A nil s.cfg yields
// a zero-value snapshot which makes the eligibility check report
// "no_legacy_config" — a safer default than dereferencing nil.
func (s *Server) legacyMigrateConfigSnapshot() legacyMigrateSourceConfig {
	if s.cfg == nil {
		return legacyMigrateSourceConfig{}
	}
	return legacyMigrateSourceConfig{
		LLM:     s.cfg.LLM,
		APIKey:  s.cfg.APIKey,
		APIBase: s.cfg.APIBase,
	}
}

// handleLegacyMigrateStatus serves GET /api/providers/migrate-legacy/status.
//
// The endpoint is read-only and exists so the dashboard can decide
// whether to render the migration banner without first POSTing to
// the importer. It returns a stable JSON envelope:
//
//   {"eligible": true}
//   {"eligible": false, "reason": "already_migrated"}
//
// Validates: Requirements 2.1, 2.2, 15.4.
func (s *Server) handleLegacyMigrateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	eligible, reason := s.legacyMigrateEligibility()
	resp := legacyMigrateStatusResponse{Eligible: eligible}
	if !eligible {
		resp.Reason = reason
	}
	writeJSONStatus(w, http.StatusOK, resp)
}

// handleLegacyMigrate serves POST /api/providers/migrate-legacy.
//
// The handler:
//
//  1. Verifies the catalog + profile stores are initialized
//     (returns 503 otherwise — a startup load failure is the only
//     way this happens, and the operator must repair the file
//     before the importer can run).
//  2. Re-checks the eligibility gate under the same rules as the
//     status endpoint. A no-longer-eligible request returns 409
//     Conflict with the machine-readable reason.
//  3. Builds a Catalog_Entry from the legacy cfg fields and writes
//     it via Catalog_Service.Create.
//  4. Builds an API_Key_Profile (legacy:default) and writes it via
//     Profile_Store.Put. ON FAILURE, ROLLS BACK the catalog entry
//     created in step 3 so the import never leaves a half-imported
//     state behind. H6.
//  5. Writes the sentinel via storage.WriteAtomic so the banner
//     never reappears even across restarts. A sentinel write
//     failure is logged but does not roll back the catalog +
//     profile — the migration outcome is the catalog/profile pair,
//     and on a sentinel-write failure the next call to the
//     eligibility gate observes "catalog_already_populated" and
//     correctly declines, which is the same end state.
//  6. Returns 200 + {"success": true, "entry": ..., "profileKey": ...}
//     so the dashboard can refresh its catalog/profile queries
//     without a follow-up GET.
//
// Importer never modifies ~/.xalgorix.env — the legacy env-var path
// keeps working unchanged.
//
// Validates: Requirements 2.1, 2.2, 4.5, 15.4, 15.5; H6 (rollback
// on partial failure).
func (s *Server) handleLegacyMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Both stores must be live; otherwise the catalog handlers'
	// 503 contract applies here too. A startup load failure is the
	// only realistic path to this branch.
	if !s.profilesReady(w) {
		return
	}

	eligible, reason := s.legacyMigrateEligibility()
	if !eligible {
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error":  "legacy migration not eligible",
			"reason": reason,
		})
		return
	}

	cfg := s.legacyMigrateConfigSnapshot()
	provider := legacyProviderPrefix(cfg.LLM)

	// Decide header style. When the operator has only an API key
	// configured (cfg.LLM is empty), provider == "" falls through
	// to the OpenAI default — this matches the historical behavior
	// of the legacy resolver, which assumed OpenAI when LLM was
	// empty but APIKey was set.
	headerStyle := legacyHeaderStyleFor(provider)

	// Step 1 (in-memory build, no writes yet) — assemble the
	// Catalog_Entry and API_Key_Profile so we know both will
	// validate before touching disk. Building both up front lets
	// step 4 (rollback on profile-Put failure) operate on a known
	// pair rather than re-deriving it.
	entry := providers.Entry{
		ID:          "legacy",
		DisplayName: "Legacy",
		BaseURL:     legacyMigrateBaseURL(cfg, provider),
		HeaderStyle: headerStyle,
		Flow:        "",
	}
	if provider != "" {
		if model := strings.TrimPrefix(strings.ToLower(cfg.LLM), provider+"/"); model != "" && model != strings.ToLower(cfg.LLM) {
			entry.Models = []string{model}
		}
	}
	profile := auth.Profile{
		Provider:        "legacy",
		ProfileID:       "default",
		Type:            auth.APIKey,
		APIKey:          cfg.APIKey,
		APIBaseOverride: "",
	}

	// Step 2 — catalog Create. A failure here surfaces directly
	// without rollback (nothing to undo).
	if err := s.catalog.Create(r.Context(), entry); err != nil {
		writeCatalogError(w, err)
		return
	}

	// Step 3 — profile Put with rollback on failure (H6). When
	// Put fails we Delete the catalog entry we just created so the
	// next run of the eligibility gate sees an empty catalog and
	// the operator can retry without manual cleanup. Both the
	// original error and the rollback's outcome are logged so a
	// triage reader can correlate them.
	if err := s.profiles.Put(r.Context(), profile); err != nil {
		log.Printf("[migrate-legacy] profile Put failed for %s: %v — rolling back catalog entry %q", profile.Key(), err, entry.ID)
		if rerr := s.catalog.Delete(r.Context(), entry.ID); rerr != nil {
			log.Printf("[migrate-legacy] rollback catalog Delete %q failed: %v (manual cleanup may be needed)", entry.ID, rerr)
		} else {
			log.Printf("[migrate-legacy] rollback catalog Delete %q succeeded", entry.ID)
		}
		writeProfileError(w, err)
		return
	}

	// Step 4 — sentinel write. A failure here is recoverable: the
	// catalog + profile are already persisted (which IS the
	// migration outcome), so the next eligibility check observes
	// catalog_already_populated and correctly declines without us
	// having to roll back the successful pair. We log so triage
	// readers can correlate the disappearance of the banner with
	// the underlying state.
	sentinelPath := filepath.Join(s.dataDir, legacyMigrateSentinelName)
	body := []byte(fmt.Sprintf("migrated %s\n", time.Now().UTC().Format(time.RFC3339)))
	if err := storage.WriteAtomic(sentinelPath, body); err != nil {
		log.Printf("[migrate-legacy] sentinel write failed: %v (catalog + profile already persisted; banner suppressed via catalog_already_populated)", err)
	}

	writeJSONStatus(w, http.StatusOK, map[string]any{
		"success":    true,
		"entry":      entry,
		"profileKey": profile.Key(),
	})
}

// Compile-time assertion that the handlers satisfy http.HandlerFunc.
// Server.Start registers them via mux.HandleFunc; this guard catches
// signature drift before that wiring lands or after future refactors.
var (
	_ http.HandlerFunc = (*Server)(nil).handleLegacyMigrate
	_ http.HandlerFunc = (*Server)(nil).handleLegacyMigrateStatus
)
