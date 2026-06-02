package auth

// File session.go implements task 2.3 of the xalgorix-saas spec:
//
//   - Issue:     mints a 32-byte random session id, signs it with
//                HMAC-SHA256 over hmacKey, encodes the cookie token as
//                "<rand_hex>.<tag_hex>", stores
//                {account_id, issued_at, last_seen_at, expires_at} at
//                `sess:{sid}` with a 30-day TTL, and tracks the sid in a
//                per-account pointer set `sess_account:{account_id}` so
//                that RevokeAll can fan out without scanning every key.
//   - Validate:  re-derives and constant-time-compares the HMAC tag,
//                fetches the JSON record from Redis, rejects the session
//                if the absolute idle (12h since last_seen_at) has been
//                exceeded, then refreshes last_seen_at, expires_at, and
//                the Redis TTL by another 30 days (rolling expiration).
//   - Revoke:    deletes `sess:{sid}` and removes the sid from the
//                per-account pointer set.
//   - RevokeAll: walks `sess_account:{account_id}` and deletes every
//                live `sess:{sid}` plus the pointer set itself. Used by
//                the password reset and MFA rotation flows so that
//                Requirement 3.10 holds.
//   - WriteCookie: sets the `__Host-xalgorix_session` cookie with
//                  Secure + HttpOnly + SameSite=Lax + Path=/, the only
//                  combination accepted by the `__Host-` cookie prefix
//                  (Decisions and Defaults / Requirement 20.6).
//
// The `__Host-` prefix is incompatible with a `Domain` attribute and
// requires `Path=/` and `Secure`, so callers cannot scope the cookie
// further. This is intentional and documented in Requirement 20.6.
//
// Requirements: 3.2, 3.10, 3.11, 20.6.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// SessionCookieName is the cookie name used to carry the session token
// in Dashboard requests. The `__Host-` prefix is part of the contract
// and is enforced by browsers (Path=/, Secure, no Domain).
const SessionCookieName = "__Host-xalgorix_session"

// SessionTTL is the rolling lifetime of a session record in Redis. Each
// successful Validate call extends the TTL by another SessionTTL window.
const SessionTTL = 30 * 24 * time.Hour

// SessionAbsoluteIdle is the maximum gap between two consecutive
// Validate calls. Any longer gap forces a re-authentication on the
// next request, even though the Redis key may still be alive.
const SessionAbsoluteIdle = 12 * time.Hour

// rawSessionIDBytes is the entropy in a session id before hex encoding.
const rawSessionIDBytes = 32

// minHMACKeyBytes is the smallest accepted signing key size.
// HMAC-SHA256 has a block size of 64 bytes; we require at least 32
// bytes so that a hand-rolled deploy cannot accidentally weaken the
// signature.
const minHMACKeyBytes = 32

// Sentinel errors. The HTTP layer maps these onto 401/403 responses.
var (
	// ErrSessionMalformedToken is returned when Validate is called with
	// a token that is not of the form "<sid_hex>.<tag_hex>" or whose
	// segments are not valid hex strings of the expected length.
	ErrSessionMalformedToken = errors.New("auth: malformed session token")
	// ErrSessionInvalidSignature is returned when the HMAC tag in the
	// token does not match the tag computed from the sid using the
	// configured hmacKey.
	ErrSessionInvalidSignature = errors.New("auth: invalid session signature")
	// ErrSessionNotFound is returned when no record exists at
	// `sess:{sid}` (TTL elapsed, manually revoked, or never issued).
	ErrSessionNotFound = errors.New("auth: session not found")
	// ErrSessionIdle is returned when the session record is still
	// present in Redis but its last_seen_at is older than
	// SessionAbsoluteIdle. The record is removed as part of the call.
	ErrSessionIdle = errors.New("auth: session idle timeout")
)

// Session is the public view of a session record. The cookie token
// (`<sid>.<tag>`) is returned only on Issue and is not persisted as
// part of the JSON payload.
type Session struct {
	// ID is the random hex-encoded session id (the part before the
	// '.' in the cookie token). It is also the Redis key suffix for
	// `sess:{ID}`.
	ID string `json:"-"`
	// Token is the full cookie value (`<sid_hex>.<tag_hex>`). Issue
	// populates this; Validate leaves it empty because the caller
	// already holds the raw value.
	Token string `json:"-"`
	// AccountID is the owning account UUID encoded as a string. The
	// session store treats it as an opaque identifier.
	AccountID string `json:"account_id"`
	// IssuedAt is the wall clock time the session was first minted.
	IssuedAt time.Time `json:"issued_at"`
	// LastSeenAt is updated on every successful Validate call and is
	// used to enforce SessionAbsoluteIdle.
	LastSeenAt time.Time `json:"last_seen_at"`
	// ExpiresAt is the rolling expiration time. It is recomputed on
	// every Validate call and mirrors the Redis TTL.
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionStore issues, validates, refreshes, and revokes Dashboard
// sessions backed by Redis. It is safe for concurrent use; Redis
// commands handle their own locking.
type SessionStore struct {
	redis   *redisclient.Client
	hmacKey []byte
	now     func() time.Time
	rand    io.Reader
}

// NewSessionStore constructs a SessionStore. It panics if redis is nil
// or hmacKey is shorter than minHMACKeyBytes; both are programming
// errors that must surface at boot rather than at the first sign-in.
func NewSessionStore(redis *redisclient.Client, hmacKey []byte) *SessionStore {
	if redis == nil {
		panic("auth: NewSessionStore requires a non-nil redis client")
	}
	if len(hmacKey) < minHMACKeyBytes {
		panic(fmt.Sprintf("auth: NewSessionStore requires an hmacKey of at least %d bytes", minHMACKeyBytes))
	}
	keyCopy := make([]byte, len(hmacKey))
	copy(keyCopy, hmacKey)
	return &SessionStore{
		redis:   redis,
		hmacKey: keyCopy,
		now:     time.Now,
		rand:    rand.Reader,
	}
}

// Issue mints a fresh session for accountID and persists it in Redis.
// The returned Session has Token populated with the value the caller
// must hand to WriteCookie. Issue returns an error when the random
// source or Redis is unavailable; partial state is never written
// because the SET and SADD are pipelined as a single transaction.
func (s *SessionStore) Issue(ctx context.Context, accountID string) (*Session, error) {
	if accountID == "" {
		return nil, errors.New("auth: Issue requires a non-empty account id")
	}

	raw := make([]byte, rawSessionIDBytes)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return nil, fmt.Errorf("auth: read session entropy: %w", err)
	}
	sid := hex.EncodeToString(raw)
	tag := s.signSID(sid)
	token := sid + "." + hex.EncodeToString(tag)

	now := s.now()
	sess := &Session{
		ID:         sid,
		Token:      token,
		AccountID:  accountID,
		IssuedAt:   now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(SessionTTL),
	}
	payload, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("auth: encode session: %w", err)
	}

	rdb := s.redis.Underlying()
	pipe := rdb.TxPipeline()
	pipe.Set(ctx, sessionKey(sid), payload, SessionTTL)
	pipe.SAdd(ctx, accountSetKey(accountID), sid)
	// The pointer set is bumped to the same TTL on every Issue/Validate
	// so that orphaned sets cannot accumulate after a long quiet period.
	pipe.Expire(ctx, accountSetKey(accountID), SessionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("auth: persist session: %w", err)
	}
	return sess, nil
}

// Validate verifies the HMAC tag, fetches the Redis record, enforces
// the 12-hour absolute idle, and refreshes last_seen_at + TTL by
// another SessionTTL window. It returns the refreshed Session on
// success; on failure it returns one of the sentinel errors so the
// caller can map them to the right HTTP status.
//
// When the idle timeout has elapsed Validate also deletes the record
// from Redis as part of the call so the cookie cannot be re-used by
// shifting the system clock.
func (s *SessionStore) Validate(ctx context.Context, token string) (*Session, error) {
	sid, tag, err := splitToken(token)
	if err != nil {
		return nil, err
	}
	expected := s.signSID(sid)
	if subtle.ConstantTimeCompare(tag, expected) != 1 {
		return nil, ErrSessionInvalidSignature
	}

	rdb := s.redis.Underlying()
	payload, err := rdb.Get(ctx, sessionKey(sid)).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("auth: load session: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(payload, &sess); err != nil {
		return nil, fmt.Errorf("auth: decode session: %w", err)
	}
	sess.ID = sid
	sess.Token = token

	now := s.now()
	if now.Sub(sess.LastSeenAt) > SessionAbsoluteIdle {
		// Idle session: tear down and force a fresh sign-in. Failures
		// here are best-effort — the caller still gets ErrSessionIdle.
		_ = s.dropSession(ctx, sid, sess.AccountID)
		return nil, ErrSessionIdle
	}

	sess.LastSeenAt = now
	sess.ExpiresAt = now.Add(SessionTTL)
	encoded, err := json.Marshal(&sess)
	if err != nil {
		return nil, fmt.Errorf("auth: encode session: %w", err)
	}
	pipe := rdb.TxPipeline()
	pipe.Set(ctx, sessionKey(sid), encoded, SessionTTL)
	pipe.Expire(ctx, accountSetKey(sess.AccountID), SessionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("auth: refresh session: %w", err)
	}
	return &sess, nil
}

// Revoke deletes a single session by its full cookie token. The HMAC
// tag is verified first so an unauthenticated caller cannot use Revoke
// to probe for valid session ids.
//
// Revoke is idempotent: revoking an already-deleted session returns
// nil so the sign-out endpoint can be retried safely.
func (s *SessionStore) Revoke(ctx context.Context, token string) error {
	sid, tag, err := splitToken(token)
	if err != nil {
		return err
	}
	expected := s.signSID(sid)
	if subtle.ConstantTimeCompare(tag, expected) != 1 {
		return ErrSessionInvalidSignature
	}

	rdb := s.redis.Underlying()
	// Resolve account_id first so we can prune the pointer set; if the
	// session is already gone the pruning becomes a no-op.
	payload, err := rdb.Get(ctx, sessionKey(sid)).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil
		}
		return fmt.Errorf("auth: load session: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(payload, &sess); err != nil {
		return fmt.Errorf("auth: decode session: %w", err)
	}
	return s.dropSession(ctx, sid, sess.AccountID)
}

// RevokeAll deletes every live session belonging to accountID and
// removes the pointer set itself. It is the primary tool for the
// password-reset and MFA-rotation flows that must satisfy
// Requirement 3.10 ("invalidate all sessions of an Account when the
// Account changes its password or rotates its MFA secret").
//
// Stale sids that no longer have a backing `sess:{sid}` (because their
// TTL elapsed) are still removed from the pointer set so it cannot
// grow unbounded.
func (s *SessionStore) RevokeAll(ctx context.Context, accountID string) error {
	if accountID == "" {
		return errors.New("auth: RevokeAll requires a non-empty account id")
	}
	rdb := s.redis.Underlying()
	sids, err := rdb.SMembers(ctx, accountSetKey(accountID)).Result()
	if err != nil {
		return fmt.Errorf("auth: list account sessions: %w", err)
	}

	if len(sids) > 0 {
		pipe := rdb.TxPipeline()
		for _, sid := range sids {
			pipe.Del(ctx, sessionKey(sid))
		}
		pipe.Del(ctx, accountSetKey(accountID))
		if _, err := pipe.Exec(ctx); err != nil {
			return fmt.Errorf("auth: revoke account sessions: %w", err)
		}
		return nil
	}
	// No members: still ensure the set key itself is gone so callers
	// that inspect it directly observe a clean state.
	if err := rdb.Del(ctx, accountSetKey(accountID)).Err(); err != nil {
		return fmt.Errorf("auth: drop account session set: %w", err)
	}
	return nil
}

// WriteCookie sets the `__Host-xalgorix_session` cookie on w with the
// attributes required by Requirement 20.6 (Secure, HttpOnly,
// SameSite=Lax, Path=/, no Domain). The cookie value is the full
// `<sid>.<tag>` token returned by Issue.
//
// MaxAge mirrors SessionTTL so the browser drops the cookie at the
// same time the Redis record TTLs out, even if the user never visits
// again to trigger Revoke.
func (s *SessionStore) WriteCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})
}

// ClearCookie writes a zero-value `__Host-xalgorix_session` cookie
// with MaxAge=-1 so the browser removes its copy. It is the companion
// to Revoke for sign-out and password-change flows.
func (s *SessionStore) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// dropSession removes both the per-session record and the pointer-set
// entry in a single round trip. Callers must already have validated
// the sid; dropSession does not verify the HMAC tag.
func (s *SessionStore) dropSession(ctx context.Context, sid, accountID string) error {
	rdb := s.redis.Underlying()
	pipe := rdb.TxPipeline()
	pipe.Del(ctx, sessionKey(sid))
	if accountID != "" {
		pipe.SRem(ctx, accountSetKey(accountID), sid)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("auth: drop session: %w", err)
	}
	return nil
}

// signSID returns the HMAC-SHA256 tag of sid using the store's signing
// key. The output is the raw 32-byte digest; callers hex-encode it
// before placing it in the cookie token.
func (s *SessionStore) signSID(sid string) []byte {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(sid))
	return mac.Sum(nil)
}

// splitToken parses a "<sid_hex>.<tag_hex>" cookie value into its
// components. It rejects tokens whose halves are the wrong length so
// downstream code can rely on `sid` being exactly 64 hex characters
// and `tag` being exactly 32 raw bytes.
func splitToken(token string) (sid string, tag []byte, err error) {
	if token == "" {
		return "", nil, ErrSessionMalformedToken
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot == len(token)-1 {
		return "", nil, ErrSessionMalformedToken
	}
	sidHex := token[:dot]
	tagHex := token[dot+1:]
	if len(sidHex) != rawSessionIDBytes*2 {
		return "", nil, ErrSessionMalformedToken
	}
	if len(tagHex) != sha256.Size*2 {
		return "", nil, ErrSessionMalformedToken
	}
	if _, err := hex.DecodeString(sidHex); err != nil {
		return "", nil, ErrSessionMalformedToken
	}
	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", nil, ErrSessionMalformedToken
	}
	return sidHex, tagBytes, nil
}

// sessionKey returns the Redis key for a single session record.
func sessionKey(sid string) string { return "sess:" + sid }

// accountSetKey returns the Redis key for the per-account pointer set
// that lists every live session id belonging to accountID.
func accountSetKey(accountID string) string { return "sess_account:" + accountID }
