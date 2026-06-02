package storage

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ErrInfected is the sentinel returned by [AVScanner.Scan] (and bubbled
// up by [S3Storage.Put]) whenever an upload is determined to contain a
// known virus signature. Callers MUST translate this into HTTP 422 and
// emit an `upload_rejected_av` audit event before returning to the
// client, per Requirement 20.8.
//
// Validates: Requirements 6.11, 20.8.
var ErrInfected = errors.New("storage: upload infected")

// AVScanner streams an upload through an antivirus engine. The scanner
// MUST consume body completely before returning. Implementations are
// safe for concurrent use.
//
// Validates: Requirements 6.11, 20.8.
type AVScanner interface {
	// Scan inspects body. It returns nil on a clean payload,
	// [ErrInfected] (typically wrapped with the matched signature
	// name) when the engine reports a positive hit, or a wrapped error
	// for transport / protocol failures. The caller is expected to
	// reject the upload on every non-nil return.
	Scan(ctx context.Context, body io.Reader) error
}

// Default tunables for [ClamAVScanner].
const (
	defaultClamAVTimeout   = 30 * time.Second
	defaultClamAVChunkSize = 64 * 1024 // 64 KiB INSTREAM chunk
)

// ClamAVScanner is an [AVScanner] that talks to a `clamd` daemon over a
// Unix-domain socket using the INSTREAM protocol.
//
// The wire protocol is:
//
//  1. Send `zINSTREAM\0` (the leading `z` selects the null-terminated
//     command form).
//  2. For every body chunk, send a 4-byte big-endian unsigned length
//     followed by the chunk bytes.
//  3. Send a 4-byte zero-length terminator.
//  4. Read the null-terminated response. `stream: OK` is clean; a line
//     ending in `FOUND` is a hit; anything ending in `ERROR` is a
//     transport / engine failure.
//
// On a hit the returned error wraps [ErrInfected] with the exact
// response string so audit emitters can record the matched signature.
//
// Validates: Requirements 6.11, 20.8.
type ClamAVScanner struct {
	socketPath string
	network    string
	timeout    time.Duration
	chunkSize  int
}

// ClamAVOption configures a new [ClamAVScanner].
type ClamAVOption func(*ClamAVScanner)

// WithClamAVTimeout overrides the default per-scan timeout (30s). The
// timeout is applied as a connection deadline; if the request context
// has a sooner deadline, that wins.
func WithClamAVTimeout(d time.Duration) ClamAVOption {
	return func(c *ClamAVScanner) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithClamAVChunkSize overrides the default 64 KiB INSTREAM chunk size.
// Useful for tests that want to exercise the chunking path with small
// payloads.
func WithClamAVChunkSize(n int) ClamAVOption {
	return func(c *ClamAVScanner) {
		if n > 0 {
			c.chunkSize = n
		}
	}
}

// NewClamAVScanner returns a [ClamAVScanner] bound to socketPath. The
// scanner connects lazily — construction does NOT verify the daemon is
// reachable.
func NewClamAVScanner(socketPath string, opts ...ClamAVOption) *ClamAVScanner {
	c := &ClamAVScanner{
		socketPath: socketPath,
		network:    "unix",
		timeout:    defaultClamAVTimeout,
		chunkSize:  defaultClamAVChunkSize,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SocketPath returns the configured Unix socket path.
func (c *ClamAVScanner) SocketPath() string { return c.socketPath }

// Scan implements [AVScanner]. A nil body returns nil immediately.
//
// Validates: Requirements 6.11, 20.8.
func (c *ClamAVScanner) Scan(ctx context.Context, body io.Reader) error {
	if c == nil {
		return errors.New("storage: clamav scanner is nil")
	}
	if body == nil {
		return nil
	}
	if c.socketPath == "" {
		return errors.New("storage: clamav socket path is empty")
	}

	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, c.network, c.socketPath)
	if err != nil {
		return fmt.Errorf("storage: clamav dial %q: %w", c.socketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("storage: clamav set deadline: %w", err)
	}

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return fmt.Errorf("storage: clamav write command: %w", err)
	}

	chunkSize := c.chunkSize
	if chunkSize <= 0 {
		chunkSize = defaultClamAVChunkSize
	}
	buf := make([]byte, chunkSize)
	var hdr [4]byte
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, err := conn.Write(hdr[:]); err != nil {
				return fmt.Errorf("storage: clamav write chunk header: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return fmt.Errorf("storage: clamav write chunk body: %w", err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return fmt.Errorf("storage: clamav read upload: %w", readErr)
		}
	}

	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, err := conn.Write(hdr[:]); err != nil {
		return fmt.Errorf("storage: clamav write terminator: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString(0x00)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("storage: clamav read response: %w", err)
	}
	resp = strings.TrimRight(resp, "\x00")
	resp = strings.TrimRight(resp, "\n")
	resp = strings.TrimSpace(resp)
	if resp == "" {
		return errors.New("storage: clamav empty response")
	}

	switch {
	case strings.HasSuffix(resp, ": OK"), strings.HasSuffix(resp, " OK"):
		return nil
	case strings.HasSuffix(resp, " FOUND"):
		return fmt.Errorf("%w: %s", ErrInfected, resp)
	case strings.HasSuffix(resp, " ERROR") || strings.Contains(resp, "ERROR"):
		return fmt.Errorf("storage: clamav scan error: %s", resp)
	default:
		return fmt.Errorf("storage: clamav unexpected response: %q", resp)
	}
}

// NopScanner is an [AVScanner] that approves every payload. It is the
// safe default for tests and local development where ClamAV is not
// available; production code paths in `cmd/xalgorix-cloud` MUST wire a
// real [ClamAVScanner].
//
// Validates: Requirements 6.11, 20.8.
type NopScanner struct{}

// Scan implements [AVScanner]. It always returns nil.
func (NopScanner) Scan(context.Context, io.Reader) error { return nil }

// Compile-time interface checks.
var (
	_ AVScanner = (*ClamAVScanner)(nil)
	_ AVScanner = NopScanner{}
)
