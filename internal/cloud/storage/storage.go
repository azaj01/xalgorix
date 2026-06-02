package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MaxPresignTTL is the upper bound on every presigned URL issued by the
// Cloud_Platform. Reports are signed with TTL ≤ 15 minutes per
// design.md "Property 12: Report URL TTL ≤ 15 minutes" and
// Requirement 6.6. [S3Storage.Presign] silently clamps any caller TTL
// that exceeds this limit so the invariant cannot be violated by a
// misbehaving handler.
//
// Validates: Requirements 6.6, 20.7.
const MaxPresignTTL = 15 * time.Minute

// Meta carries per-object metadata that propagates onto the S3 object
// (`Content-Type`, `Cache-Control`, `Content-Disposition`) and the
// caller-defined user metadata map (S3 `x-amz-meta-*` headers).
//
// Meta is intentionally a small, opaque struct so the [Storage]
// interface remains stable as we add additional fields (e.g.
// content-encoding, server-side-encryption customer keys) in later
// phases.
type Meta struct {
	// ContentType sets the object's Content-Type header. Defaults to
	// "application/octet-stream" when empty.
	ContentType string
	// ContentDisposition sets the Content-Disposition header. Empty
	// means S3 returns the object inline.
	ContentDisposition string
	// CacheControl sets the Cache-Control header. Empty leaves the
	// header unset.
	CacheControl string
	// UserMetadata is copied verbatim into the object's `x-amz-meta-*`
	// headers. Keys must be ASCII per the S3 contract.
	UserMetadata map[string]string
}

// Storage is the tenant-aware S3 wrapper consumed by the Cloud_Platform
// for every artifact (reports, evidence, logos, archived events, data
// exports). Every method MUST validate the supplied key against the
// active request principal's `(org_id, workspace_id)` and refuse the
// operation with [ErrTenantIsolationViolation] when the key prefix does
// not match.
//
// Implementations are safe for concurrent use.
//
// Validates: Requirements 1.5, 1.6, 6.6, 20.7.
type Storage interface {
	Put(ctx context.Context, key string, body io.Reader, meta Meta) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Presign(ctx context.Context, key string, ttl time.Duration) (string, error)
	Delete(ctx context.Context, key string) error
}

// S3API is the subset of the AWS S3 client this package depends on. The
// interface exists so unit tests can inject a fake without spinning up
// LocalStack or MinIO; the production binary passes the real
// `*s3.Client`.
type S3API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// Presigner is the subset of `s3.PresignClient` used by [S3Storage]. It
// is split out so tests can substitute a deterministic implementation.
type Presigner interface {
	PresignGetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.PresignOptions)) (*PresignedHTTPRequest, error)
}

// PresignedHTTPRequest mirrors `v4.PresignedHTTPRequest` with only the
// fields this package needs. Decoupling the type lets the test fake
// avoid pulling in the AWS request types.
type PresignedHTTPRequest struct {
	URL string
}

// Config configures a new [S3Storage].
type Config struct {
	// Bucket is the destination bucket. All keys are written under the
	// per-tenant prefix `org/{org_id}/workspace/{ws_id}/` inside the
	// bucket.
	Bucket string
	// KMSKeyID is the AWS KMS key id (or alias ARN) used for SSE-KMS
	// envelope encryption. Required by design.md "S3 + KMS" — every
	// object is encrypted at rest with this key.
	KMSKeyID string
	// OrgID is the organization id of the active request principal.
	OrgID string
	// WorkspaceID is the workspace id of the active request principal.
	WorkspaceID string
	// Client is the AWS S3 client. Required.
	Client S3API
	// Presigner issues signed URLs. Required.
	Presigner Presigner
	// Audit receives `tenant_isolation_violation` and
	// `upload_rejected_av` events. When nil [NopEmitter] is used.
	Audit AuditEmitter
	// Scanner runs every Put body through an antivirus engine before
	// the bytes hit S3. When nil, AV scanning is skipped — production
	// configs in `cmd/xalgorix-cloud` MUST inject a [ClamAVScanner];
	// tests typically inject [NopScanner] or a fake.
	//
	// Validates: Requirements 6.11, 20.8.
	Scanner AVScanner
}

// S3Storage is the concrete [Storage] implementation backed by AWS S3
// with KMS envelope encryption and a per-request principal binding that
// enforces the tenant-scoped key prefix.
//
// Construction does NOT verify the bucket exists; the readiness probe
// in `internal/cloud/observability` is responsible for that.
//
// Validates: Requirements 1.5, 1.6, 6.6, 6.11, 20.1, 20.7, 20.8.
type S3Storage struct {
	bucket      string
	kmsKeyID    string
	orgID       string
	workspaceID string
	client      S3API
	presigner   Presigner
	audit       AuditEmitter
	scanner     AVScanner
}

// New builds an [S3Storage] bound to the supplied request principal. The
// returned storage will refuse any key whose prefix does not match
// `org/{cfg.OrgID}/workspace/{cfg.WorkspaceID}/`.
//
// Validates: Requirements 1.5, 1.6.
func New(cfg Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("storage: bucket is required")
	}
	if cfg.KMSKeyID == "" {
		return nil, errors.New("storage: kms key id is required")
	}
	if cfg.OrgID == "" {
		return nil, errors.New("storage: org id is required")
	}
	if cfg.WorkspaceID == "" {
		return nil, errors.New("storage: workspace id is required")
	}
	if cfg.Client == nil {
		return nil, errors.New("storage: s3 client is required")
	}
	if cfg.Presigner == nil {
		return nil, errors.New("storage: presigner is required")
	}
	audit := cfg.Audit
	if audit == nil {
		audit = NopEmitter{}
	}
	return &S3Storage{
		bucket:      cfg.Bucket,
		kmsKeyID:    cfg.KMSKeyID,
		orgID:       cfg.OrgID,
		workspaceID: cfg.WorkspaceID,
		client:      cfg.Client,
		presigner:   cfg.Presigner,
		audit:       audit,
		scanner:     cfg.Scanner,
	}, nil
}

// OrgID returns the organization id this storage is bound to.
func (s *S3Storage) OrgID() string { return s.orgID }

// WorkspaceID returns the workspace id this storage is bound to.
func (s *S3Storage) WorkspaceID() string { return s.workspaceID }

// guard validates key against the bound principal and emits the audit
// event on mismatch. It returns the validated key prefix-check error
// (which already wraps [ErrTenantIsolationViolation]) so callers can
// return it directly.
func (s *S3Storage) guard(ctx context.Context, op, key string) error {
	if err := ValidateKey(s.orgID, s.workspaceID, key); err != nil {
		s.audit.EmitTenantIsolationViolation(ctx, TenantIsolationViolationEvent{
			OrgID:       s.orgID,
			WorkspaceID: s.workspaceID,
			Operation:   op,
			Key:         key,
			Reason:      err.Error(),
			At:          time.Now().UTC(),
		})
		return err
	}
	return nil
}

// Put streams body to S3 under key with SSE-KMS using the configured
// customer-managed key. Returns [ErrTenantIsolationViolation] if key is
// outside the bound tenant prefix.
//
// When a [Config.Scanner] is configured and body is non-nil, the entire
// payload is buffered in memory and forwarded to the scanner BEFORE
// any bytes reach S3. A positive virus hit returns [ErrInfected] and
// emits an `upload_rejected_av` audit event; the body is never written
// to S3. This invariant is what backs Requirement 20.8 ("scan the file
// with ClamAV before persistence").
//
// Validates: Requirements 1.5, 1.6, 6.6, 6.11, 20.1, 20.8.
func (s *S3Storage) Put(ctx context.Context, key string, body io.Reader, meta Meta) error {
	if err := s.guard(ctx, "Put", key); err != nil {
		return err
	}
	contentType := meta.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Run the antivirus scan BEFORE the upload reaches S3. The body is
	// buffered so the scanner sees the same bytes we ship to S3 and so
	// a non-seekable reader is supported (multipart form readers are
	// not seekable). Upload size limits are enforced upstream by the
	// HTTP body limit middleware (1 MiB target lists, 2 MiB logos).
	uploadBody := body
	if body != nil && s.scanner != nil {
		buf, err := io.ReadAll(body)
		if err != nil {
			return fmt.Errorf("storage: buffer upload for av scan: %w", err)
		}
		if scanErr := s.scanner.Scan(ctx, bytes.NewReader(buf)); scanErr != nil {
			if errors.Is(scanErr, ErrInfected) {
				s.audit.EmitUploadRejectedAV(ctx, UploadRejectedAVEvent{
					OrgID:       s.orgID,
					WorkspaceID: s.workspaceID,
					Operation:   "Put",
					Key:         key,
					Signature:   strings.TrimPrefix(scanErr.Error(), ErrInfected.Error()+": "),
					At:          time.Now().UTC(),
				})
			}
			return scanErr
		}
		uploadBody = bytes.NewReader(buf)
	}

	input := &s3.PutObjectInput{
		Bucket:               aws.String(s.bucket),
		Key:                  aws.String(key),
		Body:                 uploadBody,
		ContentType:          aws.String(contentType),
		ServerSideEncryption: s3types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String(s.kmsKeyID),
	}
	if meta.ContentDisposition != "" {
		input.ContentDisposition = aws.String(meta.ContentDisposition)
	}
	if meta.CacheControl != "" {
		input.CacheControl = aws.String(meta.CacheControl)
	}
	if len(meta.UserMetadata) > 0 {
		input.Metadata = meta.UserMetadata
	}
	if _, err := s.client.PutObject(ctx, input); err != nil {
		return fmt.Errorf("storage: put %q: %w", key, err)
	}
	return nil
}

// Get returns the object body for key. The caller MUST close the
// returned reader.
//
// Validates: Requirements 1.5, 1.6.
func (s *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := s.guard(ctx, "Get", key); err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("storage: get %q: %w", key, err)
	}
	return out.Body, nil
}

// Presign issues a presigned GET URL for key. ttl is clamped to
// [MaxPresignTTL] (15 minutes) and rounded up to 1 second when
// non-positive. The clamp guarantees Property 12 from design.md.
//
// Validates: Requirements 6.6, 20.7.
func (s *S3Storage) Presign(ctx context.Context, key string, ttl time.Duration) (string, error) {
	if err := s.guard(ctx, "Presign", key); err != nil {
		return "", err
	}
	if ttl <= 0 || ttl > MaxPresignTTL {
		ttl = MaxPresignTTL
	}
	req, err := s.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, func(o *s3.PresignOptions) {
		o.Expires = ttl
	})
	if err != nil {
		return "", fmt.Errorf("storage: presign %q: %w", key, err)
	}
	return req.URL, nil
}

// Delete removes key from S3.
//
// Validates: Requirements 1.5, 1.6, 13.4.
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	if err := s.guard(ctx, "Delete", key); err != nil {
		return err
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}); err != nil {
		return fmt.Errorf("storage: delete %q: %w", key, err)
	}
	return nil
}

// PresignClientAdapter adapts the AWS SDK `*s3.PresignClient` into the
// [Presigner] interface.
type PresignClientAdapter struct {
	Client *s3.PresignClient
}

// PresignGetObject implements [Presigner].
func (p PresignClientAdapter) PresignGetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.PresignOptions)) (*PresignedHTTPRequest, error) {
	r, err := p.Client.PresignGetObject(ctx, params, optFns...)
	if err != nil {
		return nil, err
	}
	return &PresignedHTTPRequest{URL: r.URL}, nil
}

// Compile-time check that S3Storage satisfies Storage.
var _ Storage = (*S3Storage)(nil)
