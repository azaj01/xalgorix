// Logo upload endpoint for branded report cover pages. This file
// implements task 6.3 of the xalgorix-saas spec — "Logo upload with
// ClamAV scan".
//
// The endpoint accepts a single `multipart/form-data` part named
// `logo`, validates the declared `Content-Type` against the
// MIME-allowlist defined in `requirements.md` Decisions and Defaults
// ("Maximum logo upload size: 2 MiB; allowed types: PNG, JPEG, SVG
// (sanitized), WebP"), enforces the 2 MiB body cap via
// [http.MaxBytesReader], sanitizes SVG payloads before persistence,
// and streams the result through the tenant-scoped [storage.Storage]
// implementation. The storage layer (task 14.2) runs the body through
// the configured [storage.AVScanner] before any bytes hit S3, so a
// virus hit propagates back here as [storage.ErrInfected]; we map
// that to HTTP 422 with the structured error payload
// `{"error":"upload_rejected_av"}` and emit a structured log line
// alongside the audit event already recorded by the storage layer.
//
// Validates: Requirements 6.11, 20.8.
package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
	"github.com/xalgord/xalgorix/v4/internal/cloud/tenancy"
)

// MaxLogoBytes is the upper bound on a logo upload body, in bytes. The
// value mirrors `requirements.md` Decisions and Defaults ("Maximum
// logo upload size: 2 MiB"). The cap is enforced in two places:
//
//  1. The HTTP body is wrapped in [http.MaxBytesReader] so the request
//     terminates with a [http.MaxBytesError] before allocating a
//     gigabyte-sized buffer.
//  2. After the multipart parse, the file's actual length is asserted
//     so a client cannot smuggle a larger body by claiming a small
//     `Content-Length`.
//
// Validates: Requirements 6.11.
const MaxLogoBytes int64 = 2 * 1024 * 1024

// allowed logo content types and the on-disk extension we apply when
// composing the S3 object key. Keys are canonicalized to ASCII
// lowercase before lookup so a casing-only variant ("Image/PNG") still
// matches.
const (
	contentTypePNG  = "image/png"
	contentTypeJPEG = "image/jpeg"
	contentTypeSVG  = "image/svg+xml"
	contentTypeWebP = "image/webp"
)

var allowedLogoContentTypes = map[string]string{
	contentTypePNG:  "png",
	contentTypeJPEG: "jpg",
	contentTypeSVG:  "svg",
	contentTypeWebP: "webp",
}

// LogoUploadResponse is the JSON success body returned to the caller
// when the upload completes. The `key` field is the canonical S3
// object key under the per-tenant prefix
// `org/{org}/workspace/{ws}/branding/logo-{uuid}.{ext}` so the caller
// can persist it on the workspace branding settings row in a follow-up
// request.
type LogoUploadResponse struct {
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
}

// logoUploadError is the JSON error envelope. The `error` code is the
// machine-readable contract — clients MUST switch on the code rather
// than the human-readable message attached to non-2xx responses.
type logoUploadError struct {
	Error string `json:"error"`
}

// StorageFactory returns a tenant-scoped [storage.Storage] for the
// supplied principal. The production wiring constructs an
// [storage.S3Storage] bound to (orgID, workspaceID) so every Put goes
// through the antivirus scanner configured on the storage Config; the
// unit tests in `logo_upload_test.go` inject an in-memory fake.
type StorageFactory func(ctx context.Context, orgID, workspaceID string) (storage.Storage, error)

// LogoUploadHandler is the `http.Handler` mounted at
// `POST /api/v1/reports/logos`. It is concurrency-safe — every
// request is served on its own goroutine with no shared state beyond
// the immutable [StorageFactory] and the optional MaxBytes override.
type LogoUploadHandler struct {
	// StorageFor returns the tenant-scoped storage for the request.
	// Required.
	StorageFor StorageFactory

	// MaxBytes overrides [MaxLogoBytes]. Zero or negative values fall
	// back to the production default. Tests use a tiny override so
	// the oversized-rejection case can exercise the limit without
	// allocating a 2 MiB body.
	MaxBytes int64
}

// NewLogoUploadHandler returns a handler bound to factory with the
// production [MaxLogoBytes] cap. Tests that need a smaller limit
// construct the [LogoUploadHandler] struct directly.
func NewLogoUploadHandler(factory StorageFactory) *LogoUploadHandler {
	return &LogoUploadHandler{
		StorageFor: factory,
		MaxBytes:   MaxLogoBytes,
	}
}

// ServeHTTP implements [http.Handler].
//
// Validates: Requirements 6.11, 20.8.
func (h *LogoUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.StorageFor == nil {
		writeLogoError(w, http.StatusInternalServerError, "storage_factory_unset")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeLogoError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	orgID := tenancy.OrgID(r.Context())
	workspaceID := tenancy.WorkspaceID(r.Context())
	if orgID == "" || workspaceID == "" {
		writeLogoError(w, http.StatusUnauthorized, "tenant_unresolved")
		return
	}

	maxBytes := h.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxLogoBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	// `ParseMultipartForm` calls into `MultipartReader` which streams
	// the request body. The first argument is the in-memory limit
	// before files spill to a temp file on disk; using the same value
	// as the body cap means a fully in-flight 2 MiB upload never
	// allocates a temp file but is still hard-bounded by the
	// `MaxBytesReader` above.
	if err := r.ParseMultipartForm(maxBytes); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeLogoError(w, http.StatusRequestEntityTooLarge, "logo_too_large")
			return
		}
		writeLogoError(w, http.StatusBadRequest, "invalid_multipart")
		return
	}

	file, header, err := r.FormFile("logo")
	if err != nil {
		writeLogoError(w, http.StatusBadRequest, "missing_logo_field")
		return
	}
	defer file.Close()

	declared := canonicalContentType(header.Header.Get("Content-Type"))
	ext, ok := allowedLogoContentTypes[declared]
	if !ok {
		writeLogoError(w, http.StatusUnprocessableEntity, "unsupported_content_type")
		return
	}

	// Buffer the file contents. `MaxBytesReader` already caps the
	// total request size at `maxBytes`, so this read is safe; we
	// still re-check the post-read length so a future change to the
	// streaming layer cannot regress the invariant.
	body, err := io.ReadAll(file)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeLogoError(w, http.StatusRequestEntityTooLarge, "logo_too_large")
			return
		}
		writeLogoError(w, http.StatusBadRequest, "read_logo_failed")
		return
	}
	if int64(len(body)) > maxBytes {
		writeLogoError(w, http.StatusRequestEntityTooLarge, "logo_too_large")
		return
	}

	if declared == contentTypeSVG {
		body = sanitizeSVG(body)
	}

	store, err := h.StorageFor(r.Context(), orgID, workspaceID)
	if err != nil {
		log.Error().Err(err).
			Str("org_id", orgID).
			Str("workspace_id", workspaceID).
			Msg("logo upload storage factory failed")
		writeLogoError(w, http.StatusInternalServerError, "storage_unavailable")
		return
	}

	key := fmt.Sprintf("org/%s/workspace/%s/branding/logo-%s.%s", orgID, workspaceID, uuid.NewString(), ext)
	meta := storage.Meta{
		ContentType: declared,
		UserMetadata: map[string]string{
			"original-filename": sanitizeFilename(header.Filename),
		},
	}

	if err := store.Put(r.Context(), key, bytes.NewReader(body), meta); err != nil {
		switch {
		case errors.Is(err, storage.ErrInfected):
			log.Warn().
				Str("event", "upload_rejected_av").
				Str("org_id", orgID).
				Str("workspace_id", workspaceID).
				Str("key", key).
				Str("content_type", declared).
				Int("size", len(body)).
				Msg("logo upload rejected by antivirus")
			writeLogoError(w, http.StatusUnprocessableEntity, "upload_rejected_av")
			return
		case errors.Is(err, storage.ErrTenantIsolationViolation):
			writeLogoError(w, http.StatusForbidden, "tenant_isolation_violation")
			return
		default:
			log.Error().Err(err).
				Str("org_id", orgID).
				Str("workspace_id", workspaceID).
				Str("key", key).
				Msg("logo upload storage put failed")
			writeLogoError(w, http.StatusInternalServerError, "storage_put_failed")
			return
		}
	}

	writeLogoJSON(w, http.StatusCreated, LogoUploadResponse{
		Key:         key,
		ContentType: declared,
		Size:        len(body),
	})
}

// canonicalContentType strips MIME parameters (`; charset=...`) and
// lowercases the result so the allowlist lookup is case-insensitive.
// It returns the empty string when the input is empty or whitespace
// only — callers treat that as "missing", which falls through to the
// `unsupported_content_type` branch.
func canonicalContentType(raw string) string {
	if raw == "" {
		return ""
	}
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// sanitizeFilename clamps the original filename to a defensible length
// and strips path separators so the value embedded in S3 user metadata
// cannot smuggle additional path segments. The function is best-effort
// — the canonical key already lives under the per-tenant prefix so
// even a hostile filename cannot escape.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "\x00", "_")
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

// SVG sanitization. The regex set below is intentionally narrow
// rather than exhaustive — it covers the high-impact XSS vectors
// called out in the task brief (script elements, inline event
// handlers, `xlink:href` to non-data URIs, `href="javascript:..."`)
// without pulling in a large HTML/XML parsing dependency. A future
// task can swap in `github.com/microcosm-cc/bluemonday` once that
// dependency is added to `go.mod`.
//
// The patterns use the case-insensitive `(?i)` and dot-matches-newline
// `(?s)` flags so multi-line SVGs and mixed-case attribute names are
// handled in a single pass.
var (
	svgScriptBlockRe   = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`)
	svgScriptSingleRe  = regexp.MustCompile(`(?is)<script\b[^>]*/>`)
	svgEventAttrRe     = regexp.MustCompile(`(?i)\s+on[a-z][a-z0-9]*\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	svgXlinkHrefRe     = regexp.MustCompile(`(?i)\s+xlink:href\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	svgJavaScriptHrefRe = regexp.MustCompile(`(?i)\s+href\s*=\s*("\s*javascript:[^"]*"|'\s*javascript:[^']*'|javascript:[^\s>]+)`)
)

// sanitizeSVG removes script elements, event-handler attributes, and
// `xlink:href` attributes whose value is not a `data:` URI from body.
// It always returns a non-nil slice (possibly empty) so the caller can
// treat the result identically to the original payload.
func sanitizeSVG(body []byte) []byte {
	body = svgScriptBlockRe.ReplaceAll(body, nil)
	body = svgScriptSingleRe.ReplaceAll(body, nil)
	body = svgEventAttrRe.ReplaceAll(body, nil)
	body = stripXlinkNonData(body)
	body = svgJavaScriptHrefRe.ReplaceAll(body, nil)
	if body == nil {
		return []byte{}
	}
	return body
}

// stripXlinkNonData removes `xlink:href` attributes whose value is not
// a `data:` URI. The match function inspects each occurrence so legal
// embedded data URIs (the only safe target for SVG `xlink:href`) are
// preserved while every external reference (`http:`, `javascript:`,
// `file:`, raw paths) is stripped.
func stripXlinkNonData(body []byte) []byte {
	return svgXlinkHrefRe.ReplaceAllFunc(body, func(match []byte) []byte {
		eq := bytes.IndexByte(match, '=')
		if eq < 0 {
			return nil
		}
		val := bytes.TrimSpace(match[eq+1:])
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		val = bytes.TrimSpace(val)
		lowered := bytes.ToLower(val)
		if bytes.HasPrefix(lowered, []byte("data:")) {
			return match
		}
		return nil
	})
}

// writeLogoJSON marshals body and writes it to w with the supplied
// status code and `application/json` Content-Type. The encode error
// is intentionally swallowed — the response headers have already been
// flushed by `WriteHeader`, so the only surface is the trailing body.
func writeLogoJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeLogoError is the error counterpart of writeLogoJSON.
func writeLogoError(w http.ResponseWriter, status int, code string) {
	writeLogoJSON(w, status, logoUploadError{Error: code})
}
