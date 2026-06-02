package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// pseudoUUID returns a synthetic UUID-shaped string drawn from rng. It
// keeps property tests deterministic when rng is seeded but avoids
// pulling in a uuid dependency just for tests.
func pseudoUUID(rng *rand.Rand) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 32)
	for i := range b {
		b[i] = hex[rng.Intn(16)]
	}
	s := string(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// TestValidateKey_PropertyOverManyTenantPairs is a property-style table
// test. For 500 deterministic `(orgA, wsA)` and `(orgB, wsB)` pairs it
// asserts:
//
//   - the canonical key under `(orgA, wsA)` is accepted by ValidateKey,
//   - swapping in either id from the other tenant produces a
//     [ErrTenantIsolationViolation].
//
// The fixed RNG seed makes the table reproducible while still covering
// enough of the input space (500 random pairs ≈ 2,000 cross-tenant
// permutations) to give us confidence the prefix guard is symmetric in
// both axes.
//
// Validates: Requirements 1.5, 1.6.
func TestValidateKey_PropertyOverManyTenantPairs(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const cases = 500
	tried := 0
	for i := 0; i < cases; i++ {
		orgA := pseudoUUID(rng)
		wsA := pseudoUUID(rng)
		orgB := pseudoUUID(rng)
		wsB := pseudoUUID(rng)
		// Skip the astronomically unlikely collision so we never
		// confuse the diagnostic when the suite expands.
		if orgA == orgB || wsA == wsB {
			continue
		}
		tried++
		canonical := KeyPrefix(orgA, wsA) + "scan/" + pseudoUUID(rng) + "/report.pdf"
		if err := ValidateKey(orgA, wsA, canonical); err != nil {
			t.Fatalf("case #%d: canonical key rejected: %v", i, err)
		}

		// Foreign org, same workspace.
		foreignOrg := KeyPrefix(orgB, wsA) + "scan/x/report.pdf"
		if err := ValidateKey(orgA, wsA, foreignOrg); !errors.Is(err, ErrTenantIsolationViolation) {
			t.Fatalf("case #%d: foreign-org key expected violation, got %v", i, err)
		}
		// Same org, foreign workspace.
		foreignWs := KeyPrefix(orgA, wsB) + "scan/x/report.pdf"
		if err := ValidateKey(orgA, wsA, foreignWs); !errors.Is(err, ErrTenantIsolationViolation) {
			t.Fatalf("case #%d: foreign-workspace key expected violation, got %v", i, err)
		}
		// Fully foreign tenant.
		full := KeyPrefix(orgB, wsB) + "scan/x/report.pdf"
		if err := ValidateKey(orgA, wsA, full); !errors.Is(err, ErrTenantIsolationViolation) {
			t.Fatalf("case #%d: foreign tenant key expected violation, got %v", i, err)
		}
	}
	if tried < cases-5 {
		t.Fatalf("only %d/%d property cases ran; rng pairings should not collide that often", tried, cases)
	}
}

// concurrentFakeS3 is a concurrency-safe stand-in for [S3API] used by
// [TestS3Storage_ConcurrentMixedKeys]. It uses atomic counters so the
// hammer test stays clean under `go test -race`.
type concurrentFakeS3 struct {
	puts    atomic.Int64
	gets    atomic.Int64
	deletes atomic.Int64
}

func (f *concurrentFakeS3) PutObject(_ context.Context, _ *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.puts.Add(1)
	return &s3.PutObjectOutput{}, nil
}

func (f *concurrentFakeS3) GetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.gets.Add(1)
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (f *concurrentFakeS3) DeleteObject(_ context.Context, _ *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.deletes.Add(1)
	return &s3.DeleteObjectOutput{}, nil
}

// concurrentFakePresigner is a concurrency-safe [Presigner] used by the
// hammer test.
type concurrentFakePresigner struct {
	calls atomic.Int64
}

func (p *concurrentFakePresigner) PresignGetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.PresignOptions)) (*PresignedHTTPRequest, error) {
	p.calls.Add(1)
	return &PresignedHTTPRequest{URL: "https://signed.example/x"}, nil
}

// TestS3Storage_ConcurrentMixedKeys hammers Put/Get/Presign/Delete from
// many goroutines using a 50/50 mix of valid and invalid keys. It is
// the audit-accounting invariant from design.md: the prefix guard is
// the single source of truth for tenant-isolation violation counting,
// so the recorded audit event count MUST match the number of violation
// attempts exactly — no over-emission, no missed emissions, no races.
//
// Validates: Requirements 1.5, 1.6.
func TestS3Storage_ConcurrentMixedKeys(t *testing.T) {
	rec := &RecordingEmitter{}
	c := &concurrentFakeS3{}
	p := &concurrentFakePresigner{}
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

	const goroutines = 32
	const opsPerGoroutine = 50
	var violationsAttempted int64
	var successfulOps int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		seed := int64(g + 1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < opsPerGoroutine; i++ {
				violation := rng.Intn(2) == 0
				var key string
				if violation {
					// Flip the org id so the prefix mismatches.
					key = KeyPrefix(pseudoUUID(rng), testWsA) + fmt.Sprintf("scan/%d/%d/report.pdf", seed, i)
					atomic.AddInt64(&violationsAttempted, 1)
				} else {
					key = KeyPrefix(testOrgA, testWsA) + fmt.Sprintf("scan/%d/%d/report.pdf", seed, i)
					atomic.AddInt64(&successfulOps, 1)
				}
				op := rng.Intn(4)
				ctx := context.Background()
				var opErr error
				switch op {
				case 0:
					opErr = s.Put(ctx, key, strings.NewReader("x"), Meta{})
				case 1:
					var rc io.ReadCloser
					rc, opErr = s.Get(ctx, key)
					if rc != nil {
						_ = rc.Close()
					}
				case 2:
					_, opErr = s.Presign(ctx, key, time.Minute)
				case 3:
					opErr = s.Delete(ctx, key)
				}
				if violation {
					if !errors.Is(opErr, ErrTenantIsolationViolation) {
						t.Errorf("op=%d violation expected, got %v (key=%q)", op, opErr, key)
					}
				} else if opErr != nil {
					t.Errorf("op=%d valid key %q errored: %v", op, key, opErr)
				}
			}
		}()
	}
	wg.Wait()

	if got, want := int64(rec.Len()), violationsAttempted; got != want {
		t.Fatalf("audit emission count = %d, want exactly %d (no double-count, no drop)", got, want)
	}
	// Sanity: at least one op of each kind must have run, otherwise the
	// concurrency mix is degenerate.
	if c.puts.Load()+c.gets.Load()+c.deletes.Load()+p.calls.Load() == 0 {
		t.Fatalf("no successful S3 ops dispatched; mix is degenerate")
	}
	if c.puts.Load()+c.gets.Load()+c.deletes.Load()+p.calls.Load() != successfulOps {
		t.Fatalf("S3 dispatched ops = %d, expected %d (must equal successful key count)",
			c.puts.Load()+c.gets.Load()+c.deletes.Load()+p.calls.Load(), successfulOps)
	}
	// And the emitter must have observed every attempted violation.
	for _, ev := range rec.Events() {
		if ev.OrgID != testOrgA || ev.WorkspaceID != testWsA {
			t.Fatalf("audit principal mismatch: %+v", ev)
		}
		if ev.Operation == "" || ev.Key == "" || ev.Reason == "" || ev.At.IsZero() {
			t.Fatalf("audit event missing fields: %+v", ev)
		}
	}
}

// TestS3Storage_AuditEmissionPayloadAllOps drives every Storage method
// with a foreign-tenant key and asserts the emitted
// [TenantIsolationViolationEvent] populates every field — including the
// per-method `Operation` discriminator that the audit reader uses to
// classify the breach.
//
// Validates: Requirements 1.5, 1.6.
func TestS3Storage_AuditEmissionPayloadAllOps(t *testing.T) {
	cases := []struct {
		op string
		do func(s *S3Storage, key string) error
	}{
		{"Put", func(s *S3Storage, key string) error {
			return s.Put(context.Background(), key, strings.NewReader("x"), Meta{})
		}},
		{"Get", func(s *S3Storage, key string) error {
			rc, err := s.Get(context.Background(), key)
			if rc != nil {
				_ = rc.Close()
			}
			return err
		}},
		{"Presign", func(s *S3Storage, key string) error {
			_, err := s.Presign(context.Background(), key, time.Minute)
			return err
		}},
		{"Delete", func(s *S3Storage, key string) error {
			return s.Delete(context.Background(), key)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			rec := &RecordingEmitter{}
			s, _, _ := newTestStorage(t, rec)
			before := time.Now().Add(-time.Second)

			badKey := KeyPrefix(testOrgB, testWsA) + "scan/abc/report.pdf"
			err := tc.do(s, badKey)
			if !errors.Is(err, ErrTenantIsolationViolation) {
				t.Fatalf("expected violation, got %v", err)
			}

			events := rec.Events()
			if len(events) != 1 {
				t.Fatalf("expected exactly 1 audit event, got %d", len(events))
			}
			ev := events[0]
			if ev.OrgID != testOrgA {
				t.Errorf("OrgID = %q want %q", ev.OrgID, testOrgA)
			}
			if ev.WorkspaceID != testWsA {
				t.Errorf("WorkspaceID = %q want %q", ev.WorkspaceID, testWsA)
			}
			if ev.Operation != tc.op {
				t.Errorf("Operation = %q want %q", ev.Operation, tc.op)
			}
			if ev.Key != badKey {
				t.Errorf("Key = %q want %q", ev.Key, badKey)
			}
			if !strings.Contains(ev.Reason, "tenant isolation violation") {
				t.Errorf("Reason = %q must mention tenant isolation violation", ev.Reason)
			}
			if ev.At.IsZero() {
				t.Error("At must be populated")
			}
			if ev.At.Before(before) {
				t.Errorf("At = %v earlier than test start %v", ev.At, before)
			}
			if time.Since(ev.At) > time.Minute {
				t.Errorf("At = %v is too far in the past (clock skew?)", ev.At)
			}
		})
	}
}

// TestS3Storage_SuccessfulOpsEmitNoAudit confirms the negative case: a
// happy-path Put/Get/Presign/Delete sequence on a key under the bound
// prefix produces zero audit events. This guards against a regression
// where the guard accidentally emits on every call instead of only on
// violation.
//
// Validates: Requirements 1.5, 1.6.
func TestS3Storage_SuccessfulOpsEmitNoAudit(t *testing.T) {
	rec := &RecordingEmitter{}
	s, _, _ := newTestStorage(t, rec)

	key := KeyPrefix(testOrgA, testWsA) + "scan/abc/report.pdf"
	if err := s.Put(context.Background(), key, strings.NewReader("x"), Meta{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, err := s.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = rc.Close()
	if _, err := s.Presign(context.Background(), key, time.Minute); err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if err := s.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if rec.Len() != 0 {
		t.Fatalf("expected 0 audit events on happy path, got %d: %+v", rec.Len(), rec.Events())
	}
}
