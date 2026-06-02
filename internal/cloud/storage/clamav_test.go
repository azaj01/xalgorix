package storage

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAVScanner is the test double used to drive the [S3Storage.Put] AV
// hook without standing up a real `clamd`. The Scan func is invoked
// verbatim so each test can decide whether to return [ErrInfected], a
// transport error, or nil.
type fakeAVScanner struct {
	mu    sync.Mutex
	calls int
	bytes []byte
	scan  func(ctx context.Context, body io.Reader) error
}

func (f *fakeAVScanner) Scan(ctx context.Context, body io.Reader) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	buf, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.bytes = append(f.bytes[:0], buf...)
	f.mu.Unlock()
	if f.scan == nil {
		return nil
	}
	return f.scan(ctx, nil)
}

func (f *fakeAVScanner) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestS3Storage_PutScansBeforeS3 confirms that when the scanner returns
// nil the bytes are forwarded to the S3 client and the audit emitter
// stays silent.
//
// Validates: Requirements 6.11, 20.8.
func TestS3Storage_PutScansBeforeS3(t *testing.T) {
	rec := &RecordingEmitter{}
	scanner := &fakeAVScanner{}

	c := &fakeS3{}
	p := &fakePresigner{}
	s, err := New(Config{
		Bucket:      "test-bucket",
		KMSKeyID:    "alias/test",
		OrgID:       testOrgA,
		WorkspaceID: testWsA,
		Client:      c,
		Presigner:   p,
		Audit:       rec,
		Scanner:     scanner,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := "org/" + testOrgA + "/workspace/" + testWsA + "/logo.png"
	payload := strings.Repeat("a", 1024)
	if err := s.Put(context.Background(), key, strings.NewReader(payload), Meta{ContentType: "image/png"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if scanner.Calls() != 1 {
		t.Fatalf("scanner Calls = %d, want 1", scanner.Calls())
	}
	if len(c.puts) != 1 {
		t.Fatalf("expected 1 PutObject, got %d", len(c.puts))
	}
	body := c.puts[0].Body
	uploaded, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read uploaded body: %v", err)
	}
	if string(uploaded) != payload {
		t.Errorf("uploaded body mismatch: got %d bytes, want %d", len(uploaded), len(payload))
	}
	if rec.RejectionsLen() != 0 {
		t.Errorf("expected 0 upload_rejected_av events, got %d", rec.RejectionsLen())
	}
	if rec.Len() != 0 {
		t.Errorf("expected 0 tenant_isolation_violation events, got %d", rec.Len())
	}
}

// TestS3Storage_PutRejectsInfectedUpload confirms that when the scanner
// returns [ErrInfected] the upload never reaches S3 and a single
// `upload_rejected_av` audit event is emitted with the expected
// metadata.
//
// Validates: Requirements 6.11, 20.8.
func TestS3Storage_PutRejectsInfectedUpload(t *testing.T) {
	rec := &RecordingEmitter{}
	signature := "stream: Eicar-Test-Signature FOUND"
	scanner := &fakeAVScanner{
		scan: func(_ context.Context, _ io.Reader) error {
			return wrapInfected(signature)
		},
	}

	c := &fakeS3{}
	p := &fakePresigner{}
	s, err := New(Config{
		Bucket:      "test-bucket",
		KMSKeyID:    "alias/test",
		OrgID:       testOrgA,
		WorkspaceID: testWsA,
		Client:      c,
		Presigner:   p,
		Audit:       rec,
		Scanner:     scanner,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := "org/" + testOrgA + "/workspace/" + testWsA + "/logo.png"
	err = s.Put(context.Background(), key, strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"), Meta{ContentType: "image/png"})
	if !errors.Is(err, ErrInfected) {
		t.Fatalf("Put error = %v, want ErrInfected", err)
	}
	if len(c.puts) != 0 {
		t.Fatalf("S3 PutObject must not be reached on infected upload, got %d calls", len(c.puts))
	}
	rejects := rec.UploadRejections()
	if len(rejects) != 1 {
		t.Fatalf("expected 1 upload_rejected_av event, got %d", len(rejects))
	}
	got := rejects[0]
	if got.Operation != "Put" {
		t.Errorf("Operation = %q want Put", got.Operation)
	}
	if got.OrgID != testOrgA || got.WorkspaceID != testWsA {
		t.Errorf("bound principal mismatch: %+v", got)
	}
	if got.Key != key {
		t.Errorf("Key = %q want %q", got.Key, key)
	}
	if got.Signature != signature {
		t.Errorf("Signature = %q want %q", got.Signature, signature)
	}
	if got.At.IsZero() {
		t.Errorf("At must be populated")
	}
}

// TestS3Storage_PutNoScannerSkipsAVPath confirms that when no scanner is
// configured the upload reaches S3 without buffering and no AV audit
// events are emitted.
//
// Validates: Requirements 1.5, 1.6.
func TestS3Storage_PutNoScannerSkipsAVPath(t *testing.T) {
	rec := &RecordingEmitter{}
	c := &fakeS3{}
	p := &fakePresigner{}
	s, err := New(Config{
		Bucket:      "test-bucket",
		KMSKeyID:    "alias/test",
		OrgID:       testOrgA,
		WorkspaceID: testWsA,
		Client:      c,
		Presigner:   p,
		Audit:       rec,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := "org/" + testOrgA + "/workspace/" + testWsA + "/scan/abc/report.pdf"
	if err := s.Put(context.Background(), key, strings.NewReader("hello"), Meta{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(c.puts) != 1 {
		t.Fatalf("expected 1 PutObject call, got %d", len(c.puts))
	}
	if rec.RejectionsLen() != 0 {
		t.Errorf("expected 0 upload_rejected_av events, got %d", rec.RejectionsLen())
	}
}

// TestS3Storage_PutPropagatesScannerTransportError confirms that a
// non-[ErrInfected] scanner error short-circuits the upload but does
// NOT emit an `upload_rejected_av` event (transport failures are not
// virus hits).
//
// Validates: Requirements 6.11, 20.8.
func TestS3Storage_PutPropagatesScannerTransportError(t *testing.T) {
	rec := &RecordingEmitter{}
	wantErr := errors.New("clamav: dial connection refused")
	scanner := &fakeAVScanner{
		scan: func(context.Context, io.Reader) error { return wantErr },
	}
	c := &fakeS3{}
	p := &fakePresigner{}
	s, err := New(Config{
		Bucket:      "test-bucket",
		KMSKeyID:    "alias/test",
		OrgID:       testOrgA,
		WorkspaceID: testWsA,
		Client:      c,
		Presigner:   p,
		Audit:       rec,
		Scanner:     scanner,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := "org/" + testOrgA + "/workspace/" + testWsA + "/logo.png"
	err = s.Put(context.Background(), key, strings.NewReader("hi"), Meta{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Put error = %v, want %v", err, wantErr)
	}
	if len(c.puts) != 0 {
		t.Errorf("S3 PutObject must not be reached on scanner error, got %d", len(c.puts))
	}
	if rec.RejectionsLen() != 0 {
		t.Errorf("upload_rejected_av must not fire on transport errors, got %d", rec.RejectionsLen())
	}
}

// TestNopScanner confirms the no-op scanner accepts any payload.
//
// Validates: Requirements 6.11, 20.8.
func TestNopScanner(t *testing.T) {
	if err := (NopScanner{}).Scan(context.Background(), strings.NewReader("anything")); err != nil {
		t.Fatalf("NopScanner.Scan: %v", err)
	}
}

// TestClamAVScanner_INSTREAM exercises the full INSTREAM wire protocol
// against a stub clamd listening on a Unix socket. Three sub-tests cover
// the clean, infected, and engine-error response paths.
//
// Validates: Requirements 6.11, 20.8.
func TestClamAVScanner_INSTREAM(t *testing.T) {
	cases := []struct {
		name    string
		respond string
		wantErr error
	}{
		{"clean", "stream: OK\x00", nil},
		{"infected", "stream: Eicar-Test-Signature FOUND\x00", ErrInfected},
		{"engine error", "INSTREAM size limit exceeded ERROR\x00", nil}, // checked separately below
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sockPath := newClamdStub(t, tc.respond)
			scanner := NewClamAVScanner(sockPath, WithClamAVTimeout(2*time.Second), WithClamAVChunkSize(8))
			payload := strings.NewReader("0123456789ABCDEF") // exercises chunk loop
			err := scanner.Scan(context.Background(), payload)
			switch {
			case tc.name == "clean":
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
			case tc.name == "infected":
				if !errors.Is(err, ErrInfected) {
					t.Fatalf("Scan = %v, want ErrInfected", err)
				}
				if !strings.Contains(err.Error(), "Eicar-Test-Signature") {
					t.Errorf("error should contain signature name, got %q", err.Error())
				}
			case tc.name == "engine error":
				if err == nil {
					t.Fatal("Scan must surface engine errors")
				}
				if errors.Is(err, ErrInfected) {
					t.Fatalf("engine error must NOT match ErrInfected, got %v", err)
				}
			}
		})
	}
}

// TestClamAVScanner_NilBody confirms a nil reader is a no-op.
//
// Validates: Requirements 6.11, 20.8.
func TestClamAVScanner_NilBody(t *testing.T) {
	scanner := NewClamAVScanner("/dev/null/clamd.sock")
	if err := scanner.Scan(context.Background(), nil); err != nil {
		t.Fatalf("Scan(nil) = %v, want nil", err)
	}
}

// wrapInfected mirrors the wrapping ClamAVScanner uses so the storage
// layer can extract the signature from the error string.
func wrapInfected(signature string) error {
	return &infectedErr{msg: ErrInfected.Error() + ": " + signature}
}

type infectedErr struct{ msg string }

func (e *infectedErr) Error() string { return e.msg }
func (e *infectedErr) Unwrap() error { return ErrInfected }

// newClamdStub spins up a Unix-socket listener that speaks the bare
// minimum INSTREAM protocol: it reads the `zINSTREAM\0` command, drains
// chunks until a zero-length terminator, then writes resp and closes.
// The returned socket path is registered for cleanup.
func newClamdStub(t *testing.T, resp string) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read command up to NUL.
		cmd := make([]byte, 0, 16)
		one := make([]byte, 1)
		for {
			if _, err := io.ReadFull(conn, one); err != nil {
				return
			}
			if one[0] == 0x00 {
				break
			}
			cmd = append(cmd, one[0])
		}
		if string(cmd) != "zINSTREAM" {
			return
		}
		// Drain chunks until length == 0.
		hdr := make([]byte, 4)
		for {
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			n := uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3])
			if n == 0 {
				break
			}
			body := make([]byte, n)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		_, _ = conn.Write([]byte(resp))
	}()
	return sock
}
