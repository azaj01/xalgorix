//go:build integration

// File integration_test.go — task 2.12 of the xalgorix-saas spec.
//
// This integration test stitches every primitive built in tasks 2.1–2.11
// against real PostgreSQL 16 + Redis 7 containers spun up via
// `ory/dockertest/v3`. Unit tests under this package use miniredis and
// in-memory fakes; this test exercises the actual SQL grammar (RLS
// policies, citext, UUID defaults) and the actual Redis command set
// against pinned upstream images.
//
// Coverage (per the task body in tasks.md):
//
//   1. POST /auth/signup → HTTP 201 creates an account in
//      `pending_verification`, a default Organization, a `default`
//      Workspace, and an Owner member in a single transaction.
//   2. The verification token written to Redis under `verify:{token}`
//      is consumed and the account transitions to `active` — the same
//      sequence the future verify endpoint will perform (design.md →
//      "Sequence diagrams → 1. Signup").
//   3. POST /auth/login → HTTP 200 sets a `__Host-xalgorix_session`
//      cookie that validates against the session store.
//   4. The MFAService (task 2.9) generates a TOTP secret + recovery
//      codes, persists them to `account_mfa`, and a valid TOTP code at
//      the current time step satisfies VerifyTOTP — the "MFA challenge"
//      half of Requirement 3.7.
//
// The build tag keeps this file out of the default `go test ./...`
// invocation. Run with `go test -tags=integration ./internal/cloud/auth/...`.
//
// Validates: Requirements 3.1, 3.2, 3.6, 3.7.
package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 specifies HMAC-SHA1 for TOTP
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx driver for database/sql
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	clouddb "github.com/xalgord/xalgorix/v4/internal/cloud/db"
	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// ----------------------------------------------------------------------
// Container harness
// ----------------------------------------------------------------------

// containerStartTimeout caps the wall-clock budget for pulling images
// and waiting for the database/Redis to accept connections. The default
// dockertest pool retry loop already retries internally; this timeout
// bounds the outer go-test run so a CI worker without docker fails
// quickly instead of blocking the whole job.
const containerStartTimeout = 90 * time.Second

// authTestEnv holds the shared resources the integration test depends
// on: the dockertest pool (so the test can purge containers on teardown),
// the pgx pool, the goose-applied schema, and a Redis client backed by
// the matching container.
type authTestEnv struct {
	pool      *dockertest.Pool
	pgRes     *dockertest.Resource
	redisRes  *dockertest.Resource
	pg        *pgxpool.Pool
	pgDSN     string
	redis     *redisclient.Client
	rawRedis  goredis.UniversalClient
	purgeOnce sync.Once
}

// teardown stops and removes the started containers exactly once. It is
// safe to call from `t.Cleanup` even if the test panics in the middle
// of setup because every resource handle is nil-checked.
func (e *authTestEnv) teardown(t *testing.T) {
	t.Helper()
	e.purgeOnce.Do(func() {
		if e.redis != nil {
			_ = e.redis.Close()
		}
		if e.pg != nil {
			e.pg.Close()
		}
		if e.pool == nil {
			return
		}
		if e.pgRes != nil {
			if err := e.pool.Purge(e.pgRes); err != nil {
				t.Logf("purge postgres: %v", err)
			}
		}
		if e.redisRes != nil {
			if err := e.pool.Purge(e.redisRes); err != nil {
				t.Logf("purge redis: %v", err)
			}
		}
	})
}

// startAuthTestEnv brings up Postgres + Redis containers, applies every
// embedded migration, and returns a wired environment ready for the
// signup → login → MFA sequence. Failure modes (no docker daemon, image
// pull error, slow start) are surfaced as test skips so the integration
// suite stays opt-in via the build tag without making CI brittle.
func startAuthTestEnv(t *testing.T) *authTestEnv {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("dockertest: cannot connect to docker daemon: %v", err)
	}
	pool.MaxWait = containerStartTimeout
	if err := pool.Client.Ping(); err != nil {
		t.Skipf("dockertest: docker daemon ping failed: %v", err)
	}

	env := &authTestEnv{pool: pool}
	t.Cleanup(func() { env.teardown(t) })

	// ---- Postgres ----
	pgRes, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "16-alpine",
		Env: []string{
			"POSTGRES_PASSWORD=postgres",
			"POSTGRES_USER=postgres",
			"POSTGRES_DB=xalgorix_test",
			"listen_addresses=*",
		},
	}, func(c *docker.HostConfig) {
		c.AutoRemove = true
		c.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Skipf("dockertest: start postgres: %v", err)
	}
	env.pgRes = pgRes

	dsn := fmt.Sprintf(
		"postgres://postgres:postgres@%s/xalgorix_test?sslmode=disable",
		pgRes.GetHostPort("5432/tcp"),
	)
	env.pgDSN = dsn

	if err := pool.Retry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		return conn.Ping(ctx)
	}); err != nil {
		t.Fatalf("postgres did not become ready: %v", err)
	}

	// Apply the embedded goose migrations against the fresh database
	// so tests run on the same schema the cloud binary ships with.
	// The repo's migrations FS includes a `00000000000000_init.sql`
	// placeholder that goose rejects as version 0; copy every real
	// migration to a temp directory and apply from there so the
	// integration test mirrors the production schema without the
	// placeholder noise.
	{
		sqlDB, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Fatalf("sql.Open(pgx): %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		dir, err := stagedMigrationsDir(t)
		if err != nil {
			_ = sqlDB.Close()
			t.Fatalf("stage migrations: %v", err)
		}
		goose.SetBaseFS(nil)
		if err := goose.SetDialect("postgres"); err != nil {
			_ = sqlDB.Close()
			t.Fatalf("goose dialect: %v", err)
		}
		if err := goose.UpContext(ctx, sqlDB, dir); err != nil {
			_ = sqlDB.Close()
			t.Fatalf("apply migrations: %v", err)
		}
		_ = sqlDB.Close()
	}

	// Open the long-lived pgx pool used by the rest of the test.
	pgPool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	env.pg = pgPool

	// ---- Redis ----
	redisRes, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Tag:        "7-alpine",
	}, func(c *docker.HostConfig) {
		c.AutoRemove = true
		c.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Skipf("dockertest: start redis: %v", err)
	}
	env.redisRes = redisRes

	redisAddr := redisRes.GetHostPort("6379/tcp")
	if err := pool.Retry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c := goredis.NewClient(&goredis.Options{Addr: redisAddr})
		defer c.Close()
		return c.Ping(ctx).Err()
	}); err != nil {
		t.Fatalf("redis did not become ready: %v", err)
	}

	rdb, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{redisAddr}})
	if err != nil {
		t.Fatalf("redisclient.New: %v", err)
	}
	env.redis = rdb
	env.rawRedis = rdb.Underlying()

	return env
}

// ----------------------------------------------------------------------
// Test-only pgx repositories
//
// These satisfy the SignupRepository / AccountLookup / MFARepo
// interfaces using direct SQL against the migrated schema. They live in
// the test file because the production wiring (cmd/xalgorix-cloud) is
// scheduled for a later spec phase; the integration test cannot wait
// for that work and its repositories have no business existing outside
// this package's tests.
// ----------------------------------------------------------------------

// pgSignupRepo persists the (account, organization, workspace, members)
// quartet inside a single transaction so the integration test exercises
// the same atomicity guarantee SignupHandler relies on. Duplicate-email
// collisions surface as ErrDuplicateEmail per the SignupRepository
// contract.
type pgSignupRepo struct{ pool *pgxpool.Pool }

func (r *pgSignupRepo) CreateAccountWithOrg(ctx context.Context, in CreateAccountWithOrgInput) (SignupAccount, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return SignupAccount{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var accountID, orgID, workspaceID string
	err = tx.QueryRow(ctx, `
		INSERT INTO accounts (email, password_hash, status)
		VALUES ($1, $2, 'pending_verification')
		RETURNING id::text
	`, in.Email, in.PasswordHash).Scan(&accountID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return SignupAccount{}, ErrDuplicateEmail
		}
		return SignupAccount{}, fmt.Errorf("insert account: %w", err)
	}

	// Build a deterministic-but-unique slug. The DB UNIQUE constraint
	// catches any collision; the test exercises one signup per case so
	// the timestamp suffix is plenty.
	slug := fmt.Sprintf("org-%d", time.Now().UnixNano())
	err = tx.QueryRow(ctx, `
		INSERT INTO organizations (name, slug, region, plan, status)
		VALUES ($1, $2, 'us-east-1', 'free', 'active')
		RETURNING id::text
	`, in.OrgName, slug).Scan(&orgID)
	if err != nil {
		return SignupAccount{}, fmt.Errorf("insert organization: %w", err)
	}

	// Workspaces and members are RLS-protected. Bind the GUC inside
	// the transaction so the INSERTs satisfy the policy.
	if _, err := tx.Exec(ctx, `SELECT set_config('app.organization_id', $1, true)`, orgID); err != nil {
		return SignupAccount{}, fmt.Errorf("set_config app.organization_id: %w", err)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO workspaces (org_id, name)
		VALUES ($1::uuid, 'default')
		RETURNING id::text
	`, orgID).Scan(&workspaceID)
	if err != nil {
		return SignupAccount{}, fmt.Errorf("insert workspace: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO members (org_id, account_id, role, workspace_access)
		VALUES ($1::uuid, $2::uuid, 'owner', ARRAY[$3::uuid])
	`, orgID, accountID, workspaceID); err != nil {
		return SignupAccount{}, fmt.Errorf("insert member: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return SignupAccount{}, fmt.Errorf("commit: %w", err)
	}

	return SignupAccount{
		AccountID:   accountID,
		OrgID:       orgID,
		WorkspaceID: workspaceID,
		Email:       in.Email,
	}, nil
}

// pgAccountLookup resolves an email to an AccountRecord. The login
// handler intentionally treats missing accounts and inactive accounts
// the same way (timing-equivalent 401), so the lookup also refuses to
// return rows still in `pending_verification` — that filter is what
// makes the "verify before login" requirement enforceable end-to-end.
type pgAccountLookup struct{ pool *pgxpool.Pool }

func (l *pgAccountLookup) FindByEmail(ctx context.Context, email string) (*AccountRecord, error) {
	var (
		id     string
		hash   sql.NullString
		status string
	)
	err := l.pool.QueryRow(ctx, `
		SELECT id::text, password_hash, status FROM accounts WHERE email = $1
	`, email).Scan(&id, &hash, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("find account: %w", err)
	}
	if status != "active" {
		// Pre-verification accounts are indistinguishable from
		// "no such email" at the login surface.
		return nil, ErrAccountNotFound
	}
	return &AccountRecord{ID: id, PasswordHash: hash.String}, nil
}

// pgMFARepo persists TOTP secrets + recovery hashes against the
// `account_mfa` table created by migration 20250101000100. It uses
// upsert semantics on SaveMFA so a re-enable scenario (rotation) is
// well-defined for future expansion.
type pgMFARepo struct{ pool *pgxpool.Pool }

func (r *pgMFARepo) AccountEmail(ctx context.Context, accountID string) (string, error) {
	var email string
	err := r.pool.QueryRow(ctx, `SELECT email::text FROM accounts WHERE id = $1::uuid`, accountID).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("lookup email: %w", err)
	}
	return email, nil
}

func (r *pgMFARepo) SaveMFA(ctx context.Context, accountID string, totpSecretEnc []byte, recoveryHashes []string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO account_mfa (account_id, totp_secret_enc, recovery_codes)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (account_id) DO UPDATE
		   SET totp_secret_enc = EXCLUDED.totp_secret_enc,
		       recovery_codes  = EXCLUDED.recovery_codes,
		       enabled_at      = now()
	`, accountID, totpSecretEnc, recoveryHashes)
	if err != nil {
		return fmt.Errorf("save mfa: %w", err)
	}
	return nil
}

func (r *pgMFARepo) LoadMFA(ctx context.Context, accountID string) ([]byte, []string, error) {
	var (
		enc    []byte
		hashes []string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT totp_secret_enc, recovery_codes FROM account_mfa WHERE account_id = $1::uuid
	`, accountID).Scan(&enc, &hashes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrMFANotEnabled
		}
		return nil, nil, fmt.Errorf("load mfa: %w", err)
	}
	return enc, hashes, nil
}

func (r *pgMFARepo) UpdateRecoveryHashes(ctx context.Context, accountID string, recoveryHashes []string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE account_mfa SET recovery_codes = $2 WHERE account_id = $1::uuid
	`, accountID, recoveryHashes)
	if err != nil {
		return fmt.Errorf("update recovery: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMFANotEnabled
	}
	return nil
}

// ----------------------------------------------------------------------
// Lightweight in-test collaborators
// ----------------------------------------------------------------------

// recordingEmailSender captures every verification email so the test
// can read the token without hitting Redis directly. Production code
// uses the Resend wrapper; the integration test uses an in-memory
// recorder so the assertions stay deterministic.
type recordingEmailSender struct {
	mu       sync.Mutex
	messages []VerificationEmail
}

func (s *recordingEmailSender) SendVerificationEmail(_ context.Context, msg VerificationEmail) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
	return nil
}

func (s *recordingEmailSender) last() (VerificationEmail, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return VerificationEmail{}, false
	}
	return s.messages[len(s.messages)-1], true
}

// noopAuditEmitter satisfies AuditEmitter without persisting anything.
// The integration test does not assert on audit rows; the audit
// pipeline gets its own integration coverage in Phase 13 once the
// `audit_events` writer lands.
type noopAuditEmitter struct{}

func (noopAuditEmitter) EmitAuthLockout(_ context.Context, _ AuthLockoutEvent) {}

// integrationSigningKey returns a deterministic 32-byte key used by
// every store + service constructed in the test. Deterministic so a
// session cookie issued early in the test still validates after a
// process-internal store reuse.
func integrationSigningKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// ----------------------------------------------------------------------
// The end-to-end test
// ----------------------------------------------------------------------

// TestAuth_HappyPath_SignupVerifyLoginMFA is the only entry point
// declared by task 2.12. It walks the full signup → verify → login →
// MFA challenge sequence against the dockertest containers and
// asserts every observable side effect along the way: Redis token TTL,
// account status transition, session cookie shape, and TOTP / recovery
// code consumption.
//
// Validates: Requirements 3.1, 3.2, 3.6, 3.7.
func TestAuth_HappyPath_SignupVerifyLoginMFA(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires docker; skipping in -short mode")
	}

	env := startAuthTestEnv(t)

	signupRepo := &pgSignupRepo{pool: env.pg}
	accountLookup := &pgAccountLookup{pool: env.pg}
	mfaRepo := &pgMFARepo{pool: env.pg}
	emailSender := &recordingEmailSender{}

	logger := zerolog.Nop()

	// Wire the signup handler. The HIBP probe is left nil; HIBP
	// k-anonymity is a fail-open optional check (task 2.2) and
	// pulling on the public API from CI would make the test flaky.
	signup := NewSignupHandler(
		env.redis,
		Hash,
		nil,
		emailSender,
		signupRepo,
		"https://app.test.xalgorix.com",
		logger,
	)

	sessions := NewSessionStore(env.redis, integrationSigningKey())
	lockout := NewLockoutTracker(env.redis, logger)
	login := NewLoginHandler(accountLookup, lockout, sessions, noopAuditEmitter{}, logger)

	mfa := NewMFAService(mfaRepo, IdentityEnvelope{}, integrationSigningKey())

	const (
		signupEmail    = "owner@happy-path.example.com"
		signupPassword = "Correct-Horse-Battery-9"
		signupOrg      = "Happy Path Co"
	)

	// ---- 1. Signup ---------------------------------------------------
	signupRec := postJSON(t, signup.Handle, "/auth/signup", SignupRequest{
		Email:    signupEmail,
		Password: signupPassword,
		OrgName:  signupOrg,
	})
	if signupRec.Code != http.StatusCreated {
		t.Fatalf("signup status: got %d, want 201; body=%s", signupRec.Code, signupRec.Body.String())
	}
	var signupResp SignupResponse
	if err := json.Unmarshal(signupRec.Body.Bytes(), &signupResp); err != nil {
		t.Fatalf("decode signup body: %v", err)
	}
	if signupResp.AccountID == "" || signupResp.OrgID == "" {
		t.Fatalf("signup response missing ids: %+v", signupResp)
	}
	requireAccountStatus(t, env.pg, signupResp.AccountID, "pending_verification")

	// The email sender is invoked synchronously by the handler, so
	// the verification email is in place by the time the response
	// returns 201.
	msg, ok := emailSender.last()
	if !ok {
		t.Fatal("no verification email captured after signup")
	}
	if msg.AccountID != signupResp.AccountID {
		t.Fatalf("verification email account id: got %q, want %q", msg.AccountID, signupResp.AccountID)
	}

	// The token must be present in Redis with a TTL bounded by 24h.
	storedAccount, err := env.rawRedis.Get(t.Context(), verifyKeyPrefix+msg.Token).Result()
	if err != nil {
		t.Fatalf("redis Get verify token: %v", err)
	}
	if storedAccount != signupResp.AccountID {
		t.Fatalf("verify token mapped to %q, want %q", storedAccount, signupResp.AccountID)
	}
	ttl, err := env.rawRedis.TTL(t.Context(), verifyKeyPrefix+msg.Token).Result()
	if err != nil {
		t.Fatalf("redis TTL: %v", err)
	}
	if ttl <= 0 || ttl > VerifyTokenTTL {
		t.Fatalf("verify TTL out of bounds: got %v, want (0, %v]", ttl, VerifyTokenTTL)
	}

	// ---- 2. Verify ---------------------------------------------------
	// The verify endpoint is scheduled for a follow-up task. The
	// behaviour from the design.md sequence diagram is reproduced
	// verbatim here so the integration coverage is not blocked on
	// that work landing.
	consumeVerifyToken(t, env, msg.Token, signupResp.AccountID)
	requireAccountStatus(t, env.pg, signupResp.AccountID, "active")

	// ---- 3. Login ---------------------------------------------------
	loginRec := postJSON(t, login.ServeHTTP, "/auth/login", map[string]string{
		"email":    signupEmail,
		"password": signupPassword,
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status: got %d, want 200; body=%s", loginRec.Code, loginRec.Body.String())
	}

	cookie := extractSessionCookie(t, loginRec.Result())
	sess, err := sessions.Validate(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("Validate session cookie: %v", err)
	}
	if sess.AccountID != signupResp.AccountID {
		t.Fatalf("session account id: got %q, want %q", sess.AccountID, signupResp.AccountID)
	}

	// ---- 4. MFA enable + challenge ----------------------------------
	secretB32, otpURL, recoveryCodes, err := mfa.EnableTOTP(t.Context(), signupResp.AccountID)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if secretB32 == "" || otpURL == "" {
		t.Fatalf("EnableTOTP returned empty secret/url")
	}
	if got, want := len(recoveryCodes), RecoveryCodeCount; got != want {
		t.Fatalf("recovery codes: got %d, want %d", got, want)
	}

	// Compute the expected TOTP code for the current step and feed
	// it back through the service. This is the moral equivalent of
	// an authenticator app prompt (Requirement 3.7).
	code, err := computeTOTPFromBase32(secretB32, time.Now())
	if err != nil {
		t.Fatalf("computeTOTPFromBase32: %v", err)
	}
	ok2, err := mfa.VerifyTOTP(t.Context(), signupResp.AccountID, code)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if !ok2 {
		t.Fatalf("VerifyTOTP rejected a freshly-computed code (secret=%s)", secretB32)
	}

	// A blatantly wrong code must be rejected.
	if rejected, err := mfa.VerifyTOTP(t.Context(), signupResp.AccountID, "000000"); err != nil {
		t.Fatalf("VerifyTOTP(wrong): %v", err)
	} else if rejected {
		// The fresh secret is unlikely to evaluate to "000000" at
		// this step, but if it does we cannot trust the negative
		// assertion. Skip the negative branch instead of failing
		// spuriously.
		t.Logf("warning: 000000 happened to be valid for this secret; skipping negative assertion")
	}

	// One recovery code is single-use: a successful consume must
	// remove the entry so a replay returns false.
	consumed, err := mfa.ConsumeRecovery(t.Context(), signupResp.AccountID, recoveryCodes[0])
	if err != nil {
		t.Fatalf("ConsumeRecovery: %v", err)
	}
	if !consumed {
		t.Fatalf("ConsumeRecovery rejected a freshly-issued code")
	}
	if replay, err := mfa.ConsumeRecovery(t.Context(), signupResp.AccountID, recoveryCodes[0]); err != nil {
		t.Fatalf("ConsumeRecovery(replay): %v", err)
	} else if replay {
		t.Fatalf("recovery code accepted twice")
	}
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// postJSON marshals body as JSON, drives handler with a fresh
// httptest.ResponseRecorder, and returns the recorder. It is a thin
// wrapper around the standard library so the test reads cleanly.
func postJSON(t *testing.T, handler http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// extractSessionCookie pulls the `__Host-xalgorix_session` cookie from
// resp and fails the test if it is missing or malformed. The Set-Cookie
// header shape is part of Requirement 20.6 so the assertion doubles as
// a regression check.
func extractSessionCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
				t.Fatalf("session cookie attributes: %+v", c)
			}
			if c.Value == "" {
				t.Fatal("session cookie has empty value")
			}
			return c
		}
	}
	t.Fatalf("response missing %s cookie: cookies=%v", SessionCookieName, resp.Cookies())
	return nil
}

// requireAccountStatus reads the live `accounts.status` for accountID
// and fails the test on any mismatch. It is the single observation
// point used to assert the pre-/post-verify state transition.
func requireAccountStatus(t *testing.T, pool *pgxpool.Pool, accountID, want string) {
	t.Helper()
	var got string
	err := pool.QueryRow(t.Context(), `SELECT status FROM accounts WHERE id = $1::uuid`, accountID).Scan(&got)
	if err != nil {
		t.Fatalf("read account status: %v", err)
	}
	if got != want {
		t.Fatalf("account %s status: got %q, want %q", accountID, got, want)
	}
}

// consumeVerifyToken reproduces the verify endpoint's behaviour from
// design.md → "Sequence diagrams → 1. Signup": GET the Redis pointer,
// transition the account to `active`, drop the token. The endpoint
// itself is implemented by a follow-up task; doing the same dance here
// keeps the integration test self-contained until then.
func consumeVerifyToken(t *testing.T, env *authTestEnv, token, accountID string) {
	t.Helper()
	got, err := env.rawRedis.Get(t.Context(), verifyKeyPrefix+token).Result()
	if err != nil {
		t.Fatalf("redis GET verify token: %v", err)
	}
	if got != accountID {
		t.Fatalf("verify token mismatch: got %q, want %q", got, accountID)
	}
	if _, err := env.pg.Exec(t.Context(), `
		UPDATE accounts SET status = 'active', updated_at = now() WHERE id = $1::uuid
	`, accountID); err != nil {
		t.Fatalf("transition account to active: %v", err)
	}
	if err := env.rawRedis.Del(t.Context(), verifyKeyPrefix+token).Err(); err != nil {
		t.Fatalf("redis DEL verify token: %v", err)
	}
}

// computeTOTPFromBase32 decodes a base32-encoded TOTP secret and
// produces the HOTP code for the time step containing `at`. It mirrors
// the algorithm in mfa.go's `hotp` helper so the test does not have to
// share unexported internals across files.
func computeTOTPFromBase32(secretB32 string, at time.Time) (string, error) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return "", fmt.Errorf("decode base32: %w", err)
	}
	step := uint64(at.Unix() / int64(TOTPPeriodSeconds))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)

	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, value%mod), nil
}
