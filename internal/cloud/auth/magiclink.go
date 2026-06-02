package auth

// File magiclink.go implements task 2.6 of the xalgorix-saas spec:
//
//   - MagicLinkIssuer.Issue mints a single-use sign-in token that
//     embeds {account_id, jti, exp} in a JSON payload, signs the
//     payload with Ed25519, and returns the cookie/URL-safe form
//     "<payloadB64>.<sigB64>". The JTI is 16 random bytes encoded as
//     hex so it is also a safe Redis key suffix.
//   - MagicLinkIssuer.Consume verifies the Ed25519 signature, parses
//     the payload, refuses tokens whose `exp` is past the wall clock,
//     and atomically claims the JTI in Redis via
//     `SETNX magic:{jti} 1 EX 900`. The first claim wins; every
//     subsequent attempt returns ErrMagicLinkAlreadyUsed even if the
//     token would otherwise still be valid (Requirement 3.4 — "single
//     use", and the design's enumeration of single-use tokens
//     enforced by Redis).
//
// Token format and rationale.
//
// We do not use a JWT because the requirements specify a fixed payload
// shape and a fixed signature scheme; minting a JWT would add header
// fields (`alg`, `typ`) that are an attacker surface (`alg=none`
// confusion, key-id substitution) without buying anything. The payload
// is a small JSON object so that operators can inspect a captured token
// during incident response by base64-decoding the first half.
//
// Encoding uses base64.RawURLEncoding so tokens are safe in URL paths
// and query strings without further escaping. The separator is "." to
// match the JWT/PASETO convention so eyes scanning logs immediately
// recognise the shape.
//
// Single-use semantics.
//
// `SETNX magic:{jti} 1 EX 900` makes the consume operation atomic:
// at most one caller sees the SETNX return true. The TTL is set to
// the same 15-minute window as the token's `exp` so that a successful
// claim cannot be re-used even if the token's `exp` is bumped by a
// future signing key (the JTI namespace is shared across keys). After
// the TTL elapses Redis frees the key automatically; replays of an
// already-consumed token still fail because the original token is
// already past its `exp`.
//
// Requirements: 3.4

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// MagicLinkTTL is the wall-clock validity window of a freshly issued
// magic-link token. The Redis claim is held for the same duration so
// the token cannot outlive its single-use guarantee.
const MagicLinkTTL = 15 * time.Minute

// magicLinkJTIBytes is the entropy in a JTI before hex encoding.
// 16 bytes = 128 bits, which keeps the collision probability
// negligible across the lifetime of the platform.
const magicLinkJTIBytes = 16

// magicLinkKeyPrefix is the Redis key namespace for consumed JTIs.
// It is deliberately short to match the design.md spelling
// (`magic:{jti}`).
const magicLinkKeyPrefix = "magic:"

// Sentinel errors. The HTTP layer maps each to a specific 4xx response
// so users see distinct, debuggable failure messages.
var (
	// ErrMagicLinkInvalid is returned when a token cannot be parsed,
	// its signature is wrong, or its payload fails structural
	// validation. Treating malformed and forged tokens uniformly
	// avoids an oracle that distinguishes "wrong key" from "wrong
	// shape".
	ErrMagicLinkInvalid = errors.New("auth: magic link invalid")
	// ErrMagicLinkExpired is returned when the token's `exp` is in
	// the past. The Redis key is left untouched.
	ErrMagicLinkExpired = errors.New("auth: magic link expired")
	// ErrMagicLinkAlreadyUsed is returned when SETNX failed because
	// some other request already claimed the JTI.
	ErrMagicLinkAlreadyUsed = errors.New("auth: magic link already used")
)

// magicLinkPayload is the JSON object signed inside every token. It is
// kept minimal: anything else (org bindings, intended audience, IP
// hints) belongs in the session that gets minted when Consume returns.
type magicLinkPayload struct {
	AccountID string `json:"account_id"`
	JTI       string `json:"jti"`
	Exp       int64  `json:"exp"`
}

// MagicLinkIssuer mints and consumes single-use sign-in tokens. It is
// safe for concurrent use; the redis client and ed25519.Sign call are
// both goroutine-safe.
type MagicLinkIssuer struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	redis *redisclient.Client
	now   func() time.Time
	rand  io.Reader
}

// NewMagicLinkIssuer constructs a MagicLinkIssuer. It panics when
// redis is nil or priv is not a valid Ed25519 private key; both are
// configuration mistakes that must surface at boot rather than at the
// first sign-in attempt.
func NewMagicLinkIssuer(redis *redisclient.Client, priv ed25519.PrivateKey) *MagicLinkIssuer {
	if redis == nil {
		panic("auth: NewMagicLinkIssuer requires a non-nil redis client")
	}
	if len(priv) != ed25519.PrivateKeySize {
		panic(fmt.Sprintf(
			"auth: NewMagicLinkIssuer requires an Ed25519 private key of %d bytes, got %d",
			ed25519.PrivateKeySize, len(priv),
		))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		panic("auth: NewMagicLinkIssuer could not derive a public key from priv")
	}
	return &MagicLinkIssuer{
		priv:  priv,
		pub:   pub,
		redis: redis,
		now:   time.Now,
		rand:  rand.Reader,
	}
}

// Issue mints a fresh magic-link token for accountID. The returned
// token has the form "<payloadB64>.<sigB64>" using base64 RawURLEncoding
// so it can travel in a URL path without escaping.
//
// Issue returns an error only when accountID is empty or when the
// random source cannot supply 16 bytes. No Redis state is written —
// the JTI namespace is touched only by Consume.
func (m *MagicLinkIssuer) Issue(ctx context.Context, accountID string) (string, error) {
	if accountID == "" {
		return "", errors.New("auth: Issue requires a non-empty account id")
	}
	// ctx is accepted for symmetry with Consume and because future
	// signing-key lookups (KMS, HSM) will need it; today it is unused.
	_ = ctx

	jtiBytes := make([]byte, magicLinkJTIBytes)
	if _, err := io.ReadFull(m.rand, jtiBytes); err != nil {
		return "", fmt.Errorf("auth: read magic-link entropy: %w", err)
	}
	jti := hex.EncodeToString(jtiBytes)

	payload := magicLinkPayload{
		AccountID: accountID,
		JTI:       jti,
		Exp:       m.now().Add(MagicLinkTTL).Unix(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		// json.Marshal cannot fail on this struct; surface the error
		// anyway so a future field type change is caught loudly.
		return "", fmt.Errorf("auth: encode magic-link payload: %w", err)
	}
	sig := ed25519.Sign(m.priv, body)

	enc := base64.RawURLEncoding
	return enc.EncodeToString(body) + "." + enc.EncodeToString(sig), nil
}

// Consume validates token and atomically claims its JTI in Redis. On
// success it returns the embedded account_id; the caller can then
// mint a session via SessionStore.Issue.
//
// Validation order is fixed:
//
//  1. Structural parse and base64 decode (cheap, leaks nothing).
//  2. Ed25519 signature verification (cheap, constant time).
//  3. Payload JSON unmarshal and field shape checks.
//  4. Expiry check against the wall clock.
//  5. SETNX magic:{jti} with the same 15-minute TTL.
//
// We deliberately verify the signature before checking `exp` so that
// an unauthenticated probe cannot tell the difference between an
// expired-but-valid token and a forged one — both surface a 4xx but
// the timing and code paths converge on ErrMagicLinkInvalid for
// anything that is not signed by our key. The Redis SETNX comes last
// so a forged or expired token never touches the JTI namespace.
func (m *MagicLinkIssuer) Consume(ctx context.Context, token string) (string, error) {
	body, sig, err := splitMagicToken(token)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(m.pub, body, sig) {
		return "", ErrMagicLinkInvalid
	}

	var payload magicLinkPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", ErrMagicLinkInvalid
	}
	if payload.AccountID == "" || payload.JTI == "" || payload.Exp == 0 {
		return "", ErrMagicLinkInvalid
	}
	// JTI must be the exact hex shape Issue produced so an attacker
	// cannot smuggle Redis key glob characters or extra-long keys.
	if len(payload.JTI) != magicLinkJTIBytes*2 {
		return "", ErrMagicLinkInvalid
	}
	if _, err := hex.DecodeString(payload.JTI); err != nil {
		return "", ErrMagicLinkInvalid
	}

	if time.Unix(payload.Exp, 0).Before(m.now()) {
		return "", ErrMagicLinkExpired
	}

	acquired, err := m.redis.SetNX(ctx, magicLinkKeyPrefix+payload.JTI, "1", MagicLinkTTL)
	if err != nil {
		return "", fmt.Errorf("auth: claim magic-link jti: %w", err)
	}
	if !acquired {
		return "", ErrMagicLinkAlreadyUsed
	}
	return payload.AccountID, nil
}

// splitMagicToken parses a "<payloadB64>.<sigB64>" string into raw
// payload and signature bytes. It rejects any token that is not
// exactly two non-empty base64-RawURL segments separated by a dot, and
// any token whose signature is not the canonical Ed25519 size. All
// failures collapse to ErrMagicLinkInvalid so the caller cannot tell
// "wrong shape" from "wrong characters".
func splitMagicToken(token string) (body, sig []byte, err error) {
	if token == "" {
		return nil, nil, ErrMagicLinkInvalid
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot == len(token)-1 {
		return nil, nil, ErrMagicLinkInvalid
	}
	enc := base64.RawURLEncoding
	body, e := enc.DecodeString(token[:dot])
	if e != nil || len(body) == 0 {
		return nil, nil, ErrMagicLinkInvalid
	}
	sig, e = enc.DecodeString(token[dot+1:])
	if e != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrMagicLinkInvalid
	}
	return body, sig, nil
}
