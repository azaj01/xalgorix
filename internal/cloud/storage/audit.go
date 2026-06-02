package storage

import (
	"context"
	"sync"
	"time"
)

// TenantIsolationViolationEvent is the canonical payload emitted whenever
// a caller attempts an S3 operation whose key prefix does not match the
// active request principal's `(org_id, workspace_id)`. The event is
// persisted to `audit_events` with `action = "tenant_isolation_violation"`
// by Phase 13 once the audit-event writer lands; until then this struct
// is the swappable hand-off contract used by the in-process audit
// emitter so handlers and tests can record violations uniformly.
//
// Validates: Requirements 1.5, 1.6, 20.7.
type TenantIsolationViolationEvent struct {
	// OrgID is the organization id resolved from the request principal.
	OrgID string
	// WorkspaceID is the workspace id resolved from the request principal.
	WorkspaceID string
	// Operation is the [Storage] method that detected the violation
	// ("Put", "Get", "Presign", "Delete").
	Operation string
	// Key is the offending S3 object key the caller tried to use.
	Key string
	// Reason is a short developer-readable description of why the key
	// was rejected (mirrors the error string from [ValidateKey]).
	Reason string
	// At is the timestamp the violation was observed. The audit writer
	// stamps this with the database `now()` if zero.
	At time.Time
}

// UploadRejectedAVEvent is the canonical payload emitted when a file
// upload is rejected because [AVScanner.Scan] reported a positive virus
// hit. The event is persisted to `audit_events` with
// `action = "upload_rejected_av"` per Requirement 20.8 and design.md
// "Security Hardening → ClamAV".
//
// Validates: Requirements 6.11, 20.8.
type UploadRejectedAVEvent struct {
	// OrgID is the organization id resolved from the request principal.
	OrgID string
	// WorkspaceID is the workspace id resolved from the request principal.
	WorkspaceID string
	// Operation is the [Storage] method that detected the infection
	// (currently always "Put", but typed for forward compatibility).
	Operation string
	// Key is the S3 object key the caller tried to write.
	Key string
	// Signature is the ClamAV match string (e.g. "stream: Eicar-Test-Signature FOUND").
	// Empty when the upstream scanner did not surface a signature name.
	Signature string
	// At is the timestamp the rejection was observed. The audit writer
	// stamps this with the database `now()` if zero.
	At time.Time
}

// AuditEmitter records storage-layer audit events. Phase 13 wires the
// production implementation, which inserts a row into `audit_events`
// inside the active transaction. Tests inject [RecordingEmitter] (or any
// [AuditEmitterFunc]) so emission can be asserted without touching the
// database.
//
// Implementations MUST be safe for concurrent use.
//
// Validates: Requirements 1.5, 1.6, 6.11, 20.8.
type AuditEmitter interface {
	EmitTenantIsolationViolation(ctx context.Context, event TenantIsolationViolationEvent)
	EmitUploadRejectedAV(ctx context.Context, event UploadRejectedAVEvent)
}

// AuditEmitterFunc adapts a plain function into an [AuditEmitter] that
// only handles tenant-isolation violations. The upload-rejection hook is
// a no-op for the func adapter; callers needing both should implement
// the interface directly or use [RecordingEmitter].
type AuditEmitterFunc func(ctx context.Context, event TenantIsolationViolationEvent)

// EmitTenantIsolationViolation implements [AuditEmitter].
func (f AuditEmitterFunc) EmitTenantIsolationViolation(ctx context.Context, event TenantIsolationViolationEvent) {
	if f == nil {
		return
	}
	f(ctx, event)
}

// EmitUploadRejectedAV implements [AuditEmitter] as a no-op for the
// function adapter.
func (AuditEmitterFunc) EmitUploadRejectedAV(context.Context, UploadRejectedAVEvent) {}

// NopEmitter discards every event. It is the safe fallback when the
// caller has not wired a real emitter yet (e.g. early-bootstrap code
// paths in `cmd/xalgorix-cloud`).
type NopEmitter struct{}

// EmitTenantIsolationViolation implements [AuditEmitter].
func (NopEmitter) EmitTenantIsolationViolation(context.Context, TenantIsolationViolationEvent) {}

// EmitUploadRejectedAV implements [AuditEmitter].
func (NopEmitter) EmitUploadRejectedAV(context.Context, UploadRejectedAVEvent) {}

// RecordingEmitter is a thread-safe in-memory [AuditEmitter] used by the
// unit tests in this package and by Phase 19 property tests. It captures
// every event in insertion order so tests can assert exact payloads.
type RecordingEmitter struct {
	mu       sync.Mutex
	events   []TenantIsolationViolationEvent
	rejects  []UploadRejectedAVEvent
}

// EmitTenantIsolationViolation implements [AuditEmitter].
func (r *RecordingEmitter) EmitTenantIsolationViolation(_ context.Context, event TenantIsolationViolationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

// EmitUploadRejectedAV implements [AuditEmitter].
func (r *RecordingEmitter) EmitUploadRejectedAV(_ context.Context, event UploadRejectedAVEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejects = append(r.rejects, event)
}

// Events returns a copy of every tenant-isolation violation recorded so
// far. The slice is safe to retain after the test exits because we copy
// under the mutex.
func (r *RecordingEmitter) Events() []TenantIsolationViolationEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TenantIsolationViolationEvent, len(r.events))
	copy(out, r.events)
	return out
}

// UploadRejections returns a copy of every `upload_rejected_av` event
// recorded so far.
func (r *RecordingEmitter) UploadRejections() []UploadRejectedAVEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]UploadRejectedAVEvent, len(r.rejects))
	copy(out, r.rejects)
	return out
}

// Len returns the number of recorded tenant-isolation violations.
func (r *RecordingEmitter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// RejectionsLen returns the number of recorded `upload_rejected_av`
// events.
func (r *RecordingEmitter) RejectionsLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rejects)
}

// Reset clears every recorded event.
func (r *RecordingEmitter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
	r.rejects = nil
}
