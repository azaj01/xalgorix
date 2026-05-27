// Package auth — driver_setup_test verifies the setup_token driver
// against Requirements 8.1, 8.2, 8.3.
//
// Properties covered (cross-referenced from design.md):
//
//   - Property 17 (upstream-error envelope preservation): R8.2 →
//     TestSetup_UpstreamErrorEnvelope iterates ≥ 100 sampled status
//     codes in [300, 599] and asserts that for each one the driver
//     returns providers.ErrUpstream with StatusCode == sampled and
//     Body containing the upstream-supplied marker.
//
//   - Property 18 (no-token-bytes-in-logs): R8.3 →
//     TestSetup_NeverLogsToken captures log.Default(), os.Stdout,
//     and os.Stderr across a happy-path Complete, an error-path
//     Complete, and an invalid_grant Refresh. None of those byte
//     streams may contain the pasted setup token or the access
//     token returned by the upstream.
//
//   - Happy path (R8.1) → TestSetup_HappyPath asserts the persisted
//     OAuth_Profile carries AccessToken == "at" with the upstream
//     access_token verbatim.
//
// Validates: Requirements 8.1, 8.2, 8.3.
package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// setupStubCatalog is a tiny CatalogResolver returning a single
// pre-configured Entry for any matching id. The setup_token driver
// itself does not consult the catalog (Store.Put does, for the R4.8
// gate) so the stub only exists to admit the persisted Profile.
//
// We use a distinct type name (setupStubCatalog) because store_test.go
// and sink_test.go already declare a package-scoped stubCatalog with
// a different field shape, and reusing that type name would collide
// at compile time.
type setupStubCatalog struct {
	id    string
	entry providers.Entry
}

func (s *setupStubCatalog) IsEmpty() bool { return false }

func (s *setupStubCatalog) Get(_ context.Context, id string) (providers.Entry, bool, error) {
	if id != s.id {
		return providers.Entry{}, false, nil
	}
	return s.entry, true, nil
}

// setupTestFixture wires a stub upstream tokenEndpoint, a freshly-
// constructed setupTokenDriver, an on-disk Profile_Store rooted in
// t.TempDir(), and a Catalog_Entry whose TokenEndpoint already
// points at the stub. setupTestFixture exposes a small set of
// atomic-int knobs every test mutates before triggering an
// exchange; the handler reads them atomically so a concurrent
// configure-then-trigger pattern never races.
type setupTestFixture struct {
	t          *testing.T
	server     *httptest.Server
	driver     *setupTokenDriver
	store      *Store
	entry      providers.Entry
	tokenCalls atomic.Int64

	// nextStatus / nextBody control the next response the stub
	// returns. Both are read atomically by the handler so a test
	// goroutine swapping the configuration never races the
	// handler reading it.
	nextStatus atomic.Int64
	nextBody   atomic.Pointer[[]byte]
}

// newSetupTestFixture stands up the upstream stub, the driver, the
// store, and the Catalog_Entry. The default response shape on a
// "no knobs touched" configuration is the documented OAuth 2.0
// happy-path body so happy-path tests do not have to set the
// fields explicitly.
func newSetupTestFixture(t *testing.T) *setupTestFixture {
	t.Helper()
	f := &setupTestFixture{t: t}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)

		status := int(f.nextStatus.Load())
		if status == 0 {
			status = http.StatusOK
		}
		body := []byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600}`)
		if bp := f.nextBody.Load(); bp != nil {
			body = *bp
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	f.entry = providers.Entry{
		ID:            "anthropic",
		DisplayName:   "Anthropic",
		BaseURL:       f.server.URL,
		HeaderStyle:   "anthropic",
		Flow:          "setup_token",
		ClientID:      "xalgorix-anthropic",
		TokenEndpoint: f.server.URL + "/token",
		Scopes:        []string{"read", "write"},
	}

	cat := &setupStubCatalog{id: f.entry.ID, entry: f.entry}
	storePath := filepath.Join(t.TempDir(), "auth-profiles.json")
	store, err := NewStore(storePath, cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	f.store = store
	f.driver = newSetupTokenDriver(store, f.server.Client())
	return f
}

// setNextResponse pins the status + body the stub returns on the
// next /token request. Both arguments are copied so the caller can
// reuse the slice safely.
func (f *setupTestFixture) setNextResponse(status int, body []byte) {
	f.nextStatus.Store(int64(status))
	cp := append([]byte(nil), body...)
	f.nextBody.Store(&cp)
}

// ----------------------------------------------------------------------
// TestSetup_HappyPath — Requirement 8.1
// ----------------------------------------------------------------------

// TestSetup_HappyPath drives the documented happy path: a stub
// returning {access_token:"at", token_type:"Bearer", expires_in:
// 3600} is exchanged through Complete with a fresh setup token,
// and the persisted profile carries AccessToken == "at" verbatim.
//
// Validates: Requirement 8.1.
func TestSetup_HappyPath(t *testing.T) {
	f := newSetupTestFixture(t)

	// Default fixture response is exactly the shape the task
	// brief specifies; no knob configuration required.

	got, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{
		SetupToken: "secret-paste-token",
	})
	if err != nil {
		t.Fatalf("Complete: unexpected error: %v", err)
	}
	if got.Provider != f.entry.ID {
		t.Fatalf("Provider = %q, want %q", got.Provider, f.entry.ID)
	}
	if got.AccessToken != "at" {
		t.Fatalf("AccessToken = %q, want %q", got.AccessToken, "at")
	}
	if got.Type != OAuth {
		t.Fatalf("Type = %q, want %q", got.Type, OAuth)
	}
	if got.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q", got.TokenType, "Bearer")
	}

	// Re-read from the on-disk store to confirm persistence.
	stored, ok, err := f.store.Get(context.Background(), got.Key())
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !ok {
		t.Fatalf("profile %q not persisted", got.Key())
	}
	if stored.AccessToken != "at" {
		t.Fatalf("persisted AccessToken = %q, want %q", stored.AccessToken, "at")
	}
	if f.tokenCalls.Load() != 1 {
		t.Fatalf("token endpoint hit %d times, want 1", f.tokenCalls.Load())
	}
}

// ----------------------------------------------------------------------
// TestSetup_UpstreamErrorEnvelope — Requirement 8.2 / Property 17
// ----------------------------------------------------------------------

// TestSetup_UpstreamErrorEnvelope samples ≥ 100 random status codes
// in [300, 599] and asserts that for each one the driver surfaces
// providers.ErrUpstream with StatusCode == sampled and Body
// preserved verbatim. The 200..299 band is excluded — those are
// success codes the driver routes through the JSON-decode path.
//
// Validates: Requirement 8.2 (Property 17).
func TestSetup_UpstreamErrorEnvelope(t *testing.T) {
	const N = 128 // > 100 per the task brief

	f := newSetupTestFixture(t)

	rng := rand.New(rand.NewSource(0xC0FFEE_8_2))

	for i := 0; i < N; i++ {
		status := 300 + rng.Intn(300) // [300, 599]
		marker := "upstream-body-" + strings.Repeat("X", 1+rng.Intn(8))
		body := []byte(`{"error":"upstream","detail":"` + marker + `"}`)
		f.setNextResponse(status, body)

		_, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{
			SetupToken: "secret-paste-token",
		})
		if err == nil {
			t.Fatalf("iter %d (status=%d): expected error, got nil", i, status)
		}
		var up providers.ErrUpstream
		if !errors.As(err, &up) {
			t.Fatalf("iter %d (status=%d): err = %v; want providers.ErrUpstream", i, status, err)
		}
		if up.StatusCode != status {
			t.Fatalf("iter %d: ErrUpstream.StatusCode = %d, want %d", i, up.StatusCode, status)
		}
		if !strings.Contains(up.Body, "upstream-body") {
			t.Fatalf("iter %d (status=%d): ErrUpstream.Body = %q, want substring %q", i, status, up.Body, "upstream-body")
		}
	}
}

// ----------------------------------------------------------------------
// TestSetup_NeverLogsToken — Requirement 8.3 / Property 18
// ----------------------------------------------------------------------

// TestSetup_NeverLogsToken captures log.Default() output and the
// process-wide os.Stdout / os.Stderr file descriptors across three
// representative driver paths and asserts none of those byte streams
// contains the pasted setup token or the access token returned by
// the upstream.
//
// Paths exercised:
//
//  1. Happy-path Complete with the unique setup token. The stub
//     returns a body containing a marker access token; the captured
//     output must not contain either.
//  2. Error-path Complete with an upstream 500 + body. The driver
//     logs the non-2xx event but never the request body or response
//     bytes that would carry the token.
//  3. Refresh whose exchange callback returns ErrInvalidGrant. The
//     refreshWithSink helper persists requires_reauth and returns
//     ErrReauthRequired; no token bytes are logged along the way.
//
// Validates: Requirement 8.3 (Property 18).
func TestSetup_NeverLogsToken(t *testing.T) {
	const setupToken = "UNIQUE-SECRET-XYZ-1234"
	const accessToken = "ACCESS-TOKEN-NEVER-LOG-9876"
	const refreshToken = "REFRESH-TOKEN-NEVER-LOG-5555"

	f := newSetupTestFixture(t)

	// Swap log.Default()'s output to a bytes.Buffer for the
	// duration of the test. This captures every log.Printf call
	// the driver issues without coordinating with the production
	// logger configuration.
	logBuf := &bytes.Buffer{}
	origWriter := log.Default().Writer()
	log.Default().SetOutput(logBuf)
	t.Cleanup(func() { log.Default().SetOutput(origWriter) })

	// Replace the driver's logger field too — the driver caches
	// log.Default() in its struct on construction and a later
	// SetOutput on log.Default() would not reroute writes that
	// already reached the cached *log.Logger. Reassigning the
	// field guarantees every driver log line lands in logBuf.
	f.driver.log = log.New(logBuf, "", log.LstdFlags)

	// Capture os.Stdout / os.Stderr by swapping in pipes. The
	// pipe writers feed background goroutines that drain into
	// per-stream buffers. We restore the originals before
	// asserting on the captured content (closing the writers
	// makes the drain goroutines see EOF and exit) so we don't
	// leak a pipe fd into the rest of the suite.
	origStdout, origStderr := os.Stdout, os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = stdoutW
	os.Stderr = stderrW

	var (
		stdoutBuf, stderrBuf bytes.Buffer
		drainWG              sync.WaitGroup
	)
	drainWG.Add(2)
	go func() {
		defer drainWG.Done()
		_, _ = io.Copy(&stdoutBuf, stdoutR)
	}()
	go func() {
		defer drainWG.Done()
		_, _ = io.Copy(&stderrBuf, stderrR)
	}()

	// restoreStdio is invoked exactly once — either at the end
	// of the test body (so we can read the drained buffers
	// before t.Cleanup runs) or via t.Cleanup if the test
	// fataled before reaching the manual call. sync.Once makes
	// the double-invocation safe.
	var restoreOnce sync.Once
	restoreStdio := func() {
		restoreOnce.Do(func() {
			_ = stdoutW.Close()
			_ = stderrW.Close()
			drainWG.Wait()
			_ = stdoutR.Close()
			_ = stderrR.Close()
			os.Stdout = origStdout
			os.Stderr = origStderr
		})
	}
	t.Cleanup(restoreStdio)

	// Path 1 — happy-path Complete. Pin the upstream response
	// body to a payload containing the marker access + refresh
	// tokens so we can assert neither leaks.
	happyBody := []byte(`{"access_token":"` + accessToken + `","refresh_token":"` + refreshToken + `","token_type":"Bearer","expires_in":3600}`)
	f.setNextResponse(http.StatusOK, happyBody)

	prof, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{
		SetupToken: setupToken,
	})
	if err != nil {
		t.Fatalf("happy Complete: %v", err)
	}
	if prof.AccessToken != accessToken {
		t.Fatalf("Complete persisted AccessToken = %q, want %q", prof.AccessToken, accessToken)
	}

	// Path 2 — upstream 500 with a body that also contains the
	// unique token markers. The driver must surface ErrUpstream
	// without echoing the request body or the stored token to
	// any captured stream.
	errBody := []byte(`{"error":"server","echo":"` + setupToken + `","upstream-body":"` + accessToken + `"}`)
	f.setNextResponse(http.StatusInternalServerError, errBody)
	if _, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{
		SetupToken: setupToken,
	}); err == nil {
		t.Fatalf("error-path Complete: expected error")
	}

	// Path 3 — Refresh whose upstream returns invalid_grant.
	// refreshWithSink converts ErrInvalidGrant into the
	// requires_reauth + ErrReauthRequired pair; no token bytes
	// should reach any captured stream.
	f.setNextResponse(http.StatusBadRequest, []byte(`{"error":"invalid_grant","detail":"`+accessToken+`"}`))
	_, err = f.driver.Refresh(context.Background(), prof, f.entry)
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("Refresh err = %v; want ErrReauthRequired", err)
	}

	// Drain the pipe writers BEFORE asserting on the captured
	// buffers so the assertions run against fully-flushed
	// content. restoreStdio closes the writers, waits for the
	// drain goroutines to consume EOF, and restores the
	// originals; sync.Once inside ensures t.Cleanup's later
	// invocation is a no-op.
	restoreStdio()

	captured := logBuf.String() + "\n" + stdoutBuf.String() + "\n" + stderrBuf.String()

	for label, needle := range map[string]string{
		"setup token":   setupToken,
		"access token":  accessToken,
		"refresh token": refreshToken,
	} {
		if strings.Contains(captured, needle) {
			t.Fatalf("captured output contains %s %q; want zero matches.\nCaptured:\n%s", label, needle, captured)
		}
	}
}
