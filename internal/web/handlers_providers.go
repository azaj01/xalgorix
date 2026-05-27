// Package web — HTTP handlers for the runtime-editable provider
// catalog (/api/providers) and the openclaw bulk importer
// (/api/providers/import-openclaw).
//
// These handlers are thin adapters around *providers.Service: they
// decode JSON, dispatch to the right Service method, and translate
// the package's typed error sentinels into HTTP status codes. The
// validation policy itself lives in internal/providers/types.go
// (validateEntry, idRE, headerStyles); keeping the gate there means
// the same rules apply whether an Entry arrives via the HTTP path
// or, in the future, via an internal CLI tool.
//
// Status-code mapping (Requirements 1.5, 1.6, 1.7, 3.4, 12.1):
//
//   • providers.ErrIDInvalid              → 400 (id failed regex)
//   • providers.ErrIDRequired             → 400 (validateEntry: empty id)
//   • providers.ErrDisplayNameRequired    → 400 (validateEntry: empty displayName)
//   • providers.ErrBaseURLRequired        → 400 (validateEntry: empty baseURL)
//   • providers.ErrHeaderStyleRequired    → 400 (validateEntry: empty headerStyle)
//   • providers.ErrHeaderStyleInvalid     → 400 (validateEntry: not in allowlist)
//   • providers.ErrIDMismatch             → 400 (PUT body id != path id)
//   • providers.ErrIDExists               → 409 (POST collision)
//   • providers.ErrNotFound               → 404 (PUT/DELETE missing id)
//   • providers.ErrCatalogCorrupt         → 503 (file failed JSON validation)
//   • providers.ErrUpstream{StatusCode,B} → 502 with {statusCode, body}
//
// Routes are NOT registered in this file — Wave E task 5.4 mounts
// them under authMw → rlMiddleware → CSRF in NewServer.Start. This
// task only builds the handler functions and the helpers they need.
package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// jsonWriteBodyLimit caps the request body size every catalog /
// profile / openclaw write handler will read. 1 MiB is generous —
// the largest legitimate payload is the openclaw catalog import
// (a JSON array of openclaw entries; today the public openclaw
// directory is well under 100 KiB). Capping protects the dashboard
// from a misbehaving operator (or a malicious client that bypassed
// the auth gate) sending a multi-gigabyte body that would otherwise
// be buffered into memory. M4 / H8.
const jsonWriteBodyLimit = 1 << 20 // 1 MiB

// limitJSONBody installs a http.MaxBytesReader on r.Body so any
// downstream json.Decoder fails cleanly with an error referencing
// the limit instead of buffering arbitrarily large payloads.
// Returns the request unchanged for chaining at the top of each
// write handler. The MaxBytesReader's Close method is no-op-safe
// so existing defer r.Body.Close() lines continue to work.
func limitJSONBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, jsonWriteBodyLimit)
}

// catalogReady gates every handler on the catalog field having been
// initialized at startup. NewServer constructs *providers.Service
// against ~/.xalgorix/data/providers.json and only logs (does not
// fail) on error, so we surface the missing dependency as HTTP 503
// here. The body shape mirrors writeCatalogError so the dashboard
// can render a single error UI for both "catalog not initialized"
// and "catalog corrupt".
func (s *Server) catalogReady(w http.ResponseWriter) bool {
	if s.catalog == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error": "catalog not initialized",
		})
		return false
	}
	return true
}

// writeJSONStatus is a small helper that sets the JSON content type,
// writes the status code, and JSON-encodes body. It exists so the
// catalog handlers don't each repeat the three-line preamble.
//
// Errors from json.Encode are intentionally not surfaced — at this
// point we have already committed the status code, and the only
// realistic failure is a closed connection which the caller already
// sees through r.Context().Err().
func writeJSONStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// catalogErrorStatus maps a *providers.Service error to the HTTP
// status code documented at the top of this file. Returns 0 when
// err does not match any known sentinel so the caller falls back
// to 500.
func catalogErrorStatus(err error) int {
	switch {
	case errors.Is(err, providers.ErrCatalogCorrupt):
		return http.StatusServiceUnavailable
	case errors.Is(err, providers.ErrIDExists):
		return http.StatusConflict
	case errors.Is(err, providers.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, providers.ErrIDInvalid),
		errors.Is(err, providers.ErrIDMismatch),
		errors.Is(err, providers.ErrIDRequired),
		errors.Is(err, providers.ErrDisplayNameRequired),
		errors.Is(err, providers.ErrBaseURLRequired),
		errors.Is(err, providers.ErrHeaderStyleRequired),
		errors.Is(err, providers.ErrHeaderStyleInvalid):
		return http.StatusBadRequest
	}
	return 0
}

// writeCatalogError writes err to w using catalogErrorStatus's
// mapping, falling back to 500 for unrecognised errors. The body is
// always {"error": <message>} so the dashboard's error renderer has
// a single shape to consume.
func writeCatalogError(w http.ResponseWriter, err error) {
	status := catalogErrorStatus(err)
	if status == 0 {
		status = http.StatusInternalServerError
	}
	writeJSONStatus(w, status, map[string]string{"error": err.Error()})
}

// providerIDFromPath extracts the trailing id segment from URL paths
// of the form "/api/providers/{id}". Returns "" when the path has
// no id, which the caller should reject with 400.
//
// The helper is deliberately strict: it requires the literal prefix
// "/api/providers/" so a stray "/api/providers/foo/bar" does not
// match a malformed multi-segment path as the id "foo".
func providerIDFromPath(p string) string {
	const prefix = "/api/providers/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(p, prefix)
	// Reject any trailing path segments — only "{id}" is valid.
	if strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

// handleListProviders serves GET /api/providers.
//
// The response body is a JSON array of providers.Entry — exactly the
// on-disk shape of providers.json — so the webui CatalogEntry type
// in webui/src/types/api.ts can deserialize it without an envelope.
//
// Validates: Requirements 1.7, 12.1.
func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.catalogReady(w) {
		return
	}
	entries, err := s.catalog.List(r.Context())
	if err != nil {
		writeCatalogError(w, err)
		return
	}
	if entries == nil {
		// Service.List always returns a non-nil slice today, but
		// keep the guard so the JSON body is "[]" not "null" if a
		// future refactor changes that contract.
		entries = []providers.Entry{}
	}
	writeJSONStatus(w, http.StatusOK, entries)
}

// handleCreateProvider serves POST /api/providers.
//
// Body shape: a single providers.Entry. Echoes the persisted entry
// (after validation) back to the caller with status 201. Validation
// failures (validateEntry, idRE) become 400; id collisions become
// 409; a corrupt on-disk catalog becomes 503.
//
// Validates: Requirements 1.2, 1.5, 1.6, 1.7, 12.1.
func (s *Server) handleCreateProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.catalogReady(w) {
		return
	}
	limitJSONBody(w, r)
	var entry providers.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON: " + err.Error(),
		})
		return
	}
	if err := s.catalog.Create(r.Context(), entry); err != nil {
		writeCatalogError(w, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, entry)
}

// handleUpdateProvider serves PUT /api/providers/{id}.
//
// The id from the URL path is the source of truth; if the body
// includes a non-empty id it must match the path id (otherwise
// providers.ErrIDMismatch → 400). This prevents callers from
// renaming an entry through Update.
//
// Validates: Requirements 1.2, 1.5, 1.6, 1.7, 12.1.
func (s *Server) handleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.catalogReady(w) {
		return
	}
	id := providerIDFromPath(r.URL.Path)
	if id == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "missing provider id in URL path",
		})
		return
	}
	limitJSONBody(w, r)
	var entry providers.Entry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON: " + err.Error(),
		})
		return
	}
	if err := s.catalog.Update(r.Context(), id, entry); err != nil {
		writeCatalogError(w, err)
		return
	}
	// Echo the canonical entry back so the dashboard can refresh its
	// row state without a second round-trip to GET /api/providers.
	if entry.ID == "" {
		entry.ID = id
	}
	writeJSONStatus(w, http.StatusOK, entry)
}

// handleDeleteProvider serves DELETE /api/providers/{id}.
//
// Returns 204 No Content on success. Missing id maps to
// providers.ErrNotFound → 404; the corrupt-file state still maps to
// 503 so deletes do not silently appear to succeed against a
// catalog that cannot be persisted.
//
// Validates: Requirements 1.7, 12.1.
func (s *Server) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.catalogReady(w) {
		return
	}
	id := providerIDFromPath(r.URL.Path)
	if id == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "missing provider id in URL path",
		})
		return
	}
	if err := s.catalog.Delete(r.Context(), id); err != nil {
		writeCatalogError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleImportOpenclaw serves POST /api/providers/import-openclaw.
//
// Body shape: {"url": "https://..."} — the operator-supplied
// openclaw catalog URL. On success the response is the providers
// outcomes envelope: {"outcomes":[{id,action,reason?}, ...]}. On
// upstream non-2xx the response is HTTP 502 with the {statusCode,
// body} envelope from the design (Requirement 3.4) so the dashboard
// can show the operator the upstream error verbatim.
//
// Validates: Requirements 3.1, 3.2, 3.4, 12.2.
func (s *Server) handleImportOpenclaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.catalogReady(w) {
		return
	}
	limitJSONBody(w, r)
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON: " + err.Error(),
		})
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{
			"error": "url is required",
		})
		return
	}

	result, err := s.catalog.ImportOpenclaw(r.Context(), req.URL)
	if err != nil {
		// Upstream non-2xx: surface the upstream envelope at 502
		// (Requirement 3.4). errors.As lets the caller match the
		// value-type ErrUpstream regardless of whether it was
		// returned as ErrUpstream{...} or wrapped via fmt.Errorf.
		var upstream providers.ErrUpstream
		if errors.As(err, &upstream) {
			writeJSONStatus(w, http.StatusBadGateway, map[string]any{
				"statusCode": upstream.StatusCode,
				"body":       upstream.Body,
			})
			return
		}
		writeCatalogError(w, err)
		return
	}
	writeJSONStatus(w, http.StatusOK, result)
}

// Compile-time assertion that the handlers satisfy http.HandlerFunc.
// Wave E task 5.4 will register them via mux.HandleFunc; this guard
// catches signature drift before that wiring lands.
var (
	_ http.HandlerFunc = (*Server)(nil).handleListProviders
	_ http.HandlerFunc = (*Server)(nil).handleCreateProvider
	_ http.HandlerFunc = (*Server)(nil).handleUpdateProvider
	_ http.HandlerFunc = (*Server)(nil).handleDeleteProvider
	_ http.HandlerFunc = (*Server)(nil).handleImportOpenclaw
)
