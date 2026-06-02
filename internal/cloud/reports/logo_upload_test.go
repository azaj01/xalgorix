package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
	"github.com/xalgord/xalgorix/v4/internal/cloud/tenancy"
)

// logoTestWorkspaceID is a workspace UUID disjoint from the
// `testWorkspaceID` constant in `fakestorage_test.go` so the logo
// upload tests remain independent of the report-generation tests
// even though they share the package's [fakeStorage] fixture.
const logoTestWorkspaceID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

// newLogoTestRequest builds a multipart/form-data request with one
// `logo` part populated from body and contentType. The request is
// stamped with a tenancy context so the handler resolves an org and
// workspace.
func newLogoTestRequest(t *testing.T, body []byte, contentType, filename string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	hdr := make(textproto.MIMEHeader)
	hdr.Set("Content-Disposition", `form-data; name="logo"; filename="`+filename+`"`)
	hdr.Set("Content-Type", contentType)
	part, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := part.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports/logos", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req = req.WithContext(tenancy.WithTenantInfo(req.Context(), testOrgID, logoTestWorkspaceID))
	return req
}

// newLogoHandler constructs a handler that always resolves to fs and
// honours the supplied byte cap. Tests pin the cap to a small value
// when exercising the oversized-rejection branch so the body cap is
// hit deterministically without allocating megabytes per test run.
func newLogoHandler(fs *fakeStorage, max int64) *LogoUploadHandler {
	return &LogoUploadHandler{
		StorageFor: func(_ context.Context, _, _ string) (storage.Storage, error) {
			return fs, nil
		},
		MaxBytes: max,
	}
}

// TestLogoUpload_HappyPathPNG asserts a well-formed PNG upload
// completes with HTTP 201, persists under the per-tenant branding
// prefix, and stamps the declared content type onto the S3 metadata.
//
// Validates: Requirements 6.11.
func TestLogoUpload_HappyPathPNG(t *testing.T) {
	fs := &fakeStorage{}
	h := newLogoHandler(fs, MaxLogoBytes)
	body := []byte("\x89PNG\r\n\x1a\nfake-png-payload")
	req := newLogoTestRequest(t, body, "image/png", "logo.png")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	puts := fs.snapshot()
	if len(puts) != 1 {
		t.Fatalf("expected 1 Put, got %d", len(puts))
	}
	put := puts[0]
	wantPrefix := "org/" + testOrgID + "/workspace/" + logoTestWorkspaceID + "/branding/logo-"
	if !strings.HasPrefix(put.Key, wantPrefix) || !strings.HasSuffix(put.Key, ".png") {
		t.Errorf("key = %q, want prefix %q with .png suffix", put.Key, wantPrefix)
	}
	if put.Meta.ContentType != "image/png" {
		t.Errorf("content type = %q, want image/png", put.Meta.ContentType)
	}
	if !bytes.Equal(put.Body, body) {
		t.Errorf("uploaded body mismatch")
	}

	var resp LogoUploadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Key != put.Key {
		t.Errorf("response key = %q, want %q", resp.Key, put.Key)
	}
	if resp.ContentType != "image/png" {
		t.Errorf("response content_type = %q", resp.ContentType)
	}
	if resp.Size != len(body) {
		t.Errorf("response size = %d, want %d", resp.Size, len(body))
	}
}

// TestLogoUpload_OversizedRejected asserts that a body larger than
// the configured maximum produces HTTP 413 and never reaches storage.
//
// Validates: Requirements 6.11.
func TestLogoUpload_OversizedRejected(t *testing.T) {
	fs := &fakeStorage{}
	const cap = 1024
	h := newLogoHandler(fs, cap)
	body := bytes.Repeat([]byte("A"), cap*4)
	req := newLogoTestRequest(t, body, "image/png", "big.png")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body = %s", rec.Code, rec.Body.String())
	}
	if len(fs.snapshot()) != 0 {
		t.Errorf("expected 0 Puts on oversized request")
	}
	var env logoUploadError
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error != "logo_too_large" {
		t.Errorf("error code = %q, want logo_too_large", env.Error)
	}
}

// TestLogoUpload_WrongContentTypeRejected asserts that an unsupported
// MIME type returns HTTP 422 and bypasses storage. The 422 response
// is the contract called out in the task description ("wrong
// content-type rejected with 422").
//
// Validates: Requirements 6.11.
func TestLogoUpload_WrongContentTypeRejected(t *testing.T) {
	fs := &fakeStorage{}
	h := newLogoHandler(fs, MaxLogoBytes)
	req := newLogoTestRequest(t, []byte("PDF body"), "application/pdf", "evil.pdf")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if len(fs.snapshot()) != 0 {
		t.Errorf("expected 0 Puts on wrong content type")
	}
	var env logoUploadError
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env.Error != "unsupported_content_type" {
		t.Errorf("error code = %q, want unsupported_content_type", env.Error)
	}
}

// TestLogoUpload_InfectedRejected asserts that when the storage
// layer signals [storage.ErrInfected] (the audit event was already
// emitted by the storage layer), the handler returns HTTP 422 with
// the `upload_rejected_av` error code.
//
// Validates: Requirements 6.11, 20.8.
func TestLogoUpload_InfectedRejected(t *testing.T) {
	fs := &fakeStorage{putError: storage.ErrInfected}
	h := newLogoHandler(fs, MaxLogoBytes)
	req := newLogoTestRequest(t, []byte("EICAR-payload"), "image/png", "logo.png")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	var env logoUploadError
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != "upload_rejected_av" {
		t.Errorf("error code = %q, want upload_rejected_av", env.Error)
	}
}

// TestLogoUpload_SVGSanitization asserts that SVG payloads are
// stripped of script tags, event-handler attributes, and
// `xlink:href` attributes that point at non-data URIs before being
// persisted. The bytes uploaded to storage MUST NOT contain any of
// the dangerous constructs from the input payload.
//
// Validates: Requirements 6.11.
func TestLogoUpload_SVGSanitization(t *testing.T) {
	fs := &fakeStorage{}
	h := newLogoHandler(fs, MaxLogoBytes)
	hostile := []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">` +
		`<script>alert(2)</script>` +
		`<a xlink:href="javascript:alert(3)">link</a>` +
		`<image xlink:href="https://attacker.example/x.png"/>` +
		`<image xlink:href="data:image/png;base64,AAAA"/>` +
		`<a href="javascript:alert(4)">x</a>` +
		`</svg>`)

	req := newLogoTestRequest(t, hostile, "image/svg+xml", "logo.svg")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
	}
	puts := fs.snapshot()
	if len(puts) != 1 {
		t.Fatalf("expected 1 Put, got %d", len(puts))
	}
	got := strings.ToLower(string(puts[0].Body))

	if strings.Contains(got, "<script") {
		t.Errorf("sanitized body still contains <script: %q", got)
	}
	if strings.Contains(got, "onload") {
		t.Errorf("sanitized body still contains onload: %q", got)
	}
	if strings.Contains(got, "javascript:") {
		t.Errorf("sanitized body still contains javascript: %q", got)
	}
	if strings.Contains(got, "attacker.example") {
		t.Errorf("sanitized body still references external host: %q", got)
	}
	// The legitimate data: URI MUST be preserved so embedded raster
	// thumbnails continue to work after sanitization.
	if !strings.Contains(got, "data:image/png;base64,aaaa") {
		t.Errorf("sanitized body dropped legitimate data URI: %q", got)
	}
	if puts[0].Meta.ContentType != "image/svg+xml" {
		t.Errorf("content type = %q, want image/svg+xml", puts[0].Meta.ContentType)
	}
}

// TestLogoUpload_TenantUnresolved asserts the handler refuses to
// dispatch to storage when the request context lacks a tenant
// binding. Without an org+workspace we cannot construct a valid
// per-tenant key, so the request is rejected with HTTP 401.
func TestLogoUpload_TenantUnresolved(t *testing.T) {
	fs := &fakeStorage{}
	h := newLogoHandler(fs, MaxLogoBytes)
	body := []byte("payload")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	hdr := make(textproto.MIMEHeader)
	hdr.Set("Content-Disposition", `form-data; name="logo"; filename="x.png"`)
	hdr.Set("Content-Type", "image/png")
	part, _ := mw.CreatePart(hdr)
	_, _ = part.Write(body)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports/logos", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(fs.snapshot()) != 0 {
		t.Errorf("expected 0 Puts when tenant is unresolved")
	}
}
