package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// newMagicLinkIssuer wires a MagicLinkIssuer to a fresh miniredis and
// a fresh Ed25519 key pair so each test gets an isolated keyspace and
// signing material. The returned *miniredis.Miniredis is exposed so
// callers can inspect TTLs and trigger fast-forward.
func newMagicLinkIssuer(t *testing.T) (*miniredis.Miniredis, *MagicLinkIssuer, ed25519.PublicKey) {
	t.Helper()
	mr := miniredis.RunT(t)
	cli, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() {
		if cerr := cli.Close(); cerr != nil {
			t.Logf("redis close: %v", cerr)
		}
	})
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return mr, NewMagicLinkIssuer(cli, priv), pub
}

// TestNewMagicLinkIssuerPanicsOnBadInputs documents that the
// constructor fails fast on misconfiguration so we never silently
// produce an issuer that signs everything with the wrong key.
func TestNewMagicLinkIssuerPanicsOnNilRedis(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("nil redis must panic")
		}
	}()
	NewMagicLinkIssuer(nil, priv)
}

func TestNewMagicLinkIssuerPanicsOnShortKey(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	cli, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("undersized private key must panic")
		}
	}()
	NewMagicLinkIssuer(cli, ed25519.PrivateKey([]byte("too-short")))
}

// TestIssueAndConsumeHappyPath is the primary single-use round trip:
// a freshly issued token must consume exactly once and return the
// expected account id.
func TestMagicLinkIssueAndConsumeHappyPath(t *testing.T) {
	t.Parallel()
	_, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	const accountID = "acc-magic-1"
	token, err := issuer.Issue(ctx, accountID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.Contains(token, ".") {
		t.Fatalf("token must contain a dot separator, got %q", token)
	}

	got, err := issuer.Consume(ctx, token)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got != accountID {
		t.Fatalf("Consume account id = %q, want %q", got, accountID)
	}
}

// TestConsumeTwiceRejectedSingleUse exercises the headline guarantee
// from Requirement 3.4: a magic link is good for exactly one
// consumption. The second call must surface ErrMagicLinkAlreadyUsed.
func TestMagicLinkConsumeTwiceRejected(t *testing.T) {
	t.Parallel()
	_, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	token, err := issuer.Issue(ctx, "acc-once")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := issuer.Consume(ctx, token); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := issuer.Consume(ctx, token); !errors.Is(err, ErrMagicLinkAlreadyUsed) {
		t.Fatalf("second Consume = %v, want ErrMagicLinkAlreadyUsed", err)
	}
}

// TestExpiredTokenRejected proves the wall-clock check fires before
// SETNX so an expired token never burns a JTI claim. We drive expiry
// by overriding the issuer clock; injecting time keeps the test
// independent of real wall clock skew.
func TestMagicLinkExpiredTokenRejected(t *testing.T) {
	t.Parallel()
	_, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	// Anchor the issuer clock and mint a token at t0.
	t0 := time.Date(2025, 5, 1, 9, 0, 0, 0, time.UTC)
	issuer.now = func() time.Time { return t0 }
	token, err := issuer.Issue(ctx, "acc-expiry")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Move the issuer clock past the 15-minute TTL window.
	issuer.now = func() time.Time { return t0.Add(MagicLinkTTL + time.Second) }
	if _, err := issuer.Consume(ctx, token); !errors.Is(err, ErrMagicLinkExpired) {
		t.Fatalf("Consume(expired) = %v, want ErrMagicLinkExpired", err)
	}
}

// TestTamperedSignatureRejected flips a single byte of the signature
// segment and confirms Ed25519 verification rejects the token before
// any Redis traffic occurs. We then assert that the original token
// still consumes successfully — tampering must be a pure rejection,
// not a destructive mutation of issuer state.
func TestMagicLinkTamperedSignatureRejected(t *testing.T) {
	t.Parallel()
	mr, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	token, err := issuer.Issue(ctx, "acc-tamper")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tampered := flipMagicLinkSignatureByte(t, token)
	if tampered == token {
		t.Fatal("tamper helper returned an unchanged token")
	}
	if _, err := issuer.Consume(ctx, tampered); !errors.Is(err, ErrMagicLinkInvalid) {
		t.Fatalf("Consume(tampered) = %v, want ErrMagicLinkInvalid", err)
	}

	// No Redis state should have been touched by the rejected attempt.
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("rejected token leaked redis keys: %v", keys)
	}

	// The original token still works.
	got, err := issuer.Consume(ctx, token)
	if err != nil {
		t.Fatalf("Consume(original) after tamper: %v", err)
	}
	if got != "acc-tamper" {
		t.Fatalf("Consume(original) account id = %q", got)
	}
}

// TestMalformedTokensRejected covers structural failures: empty,
// missing dot, non-base64, wrong-size signature. Each one must
// surface ErrMagicLinkInvalid and must not write to Redis.
func TestMagicLinkMalformedTokensRejected(t *testing.T) {
	t.Parallel()
	mr, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	cases := []string{
		"",
		"no-dot",
		".only-sig",
		"only-payload.",
		"!!!.???",
		// Signature segment is base64 but the wrong length.
		base64.RawURLEncoding.EncodeToString([]byte(`{"account_id":"x","jti":"00","exp":1}`)) + ".YQ",
	}
	for _, tok := range cases {
		if _, err := issuer.Consume(ctx, tok); !errors.Is(err, ErrMagicLinkInvalid) {
			t.Fatalf("Consume(%q) = %v, want ErrMagicLinkInvalid", tok, err)
		}
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("malformed tokens leaked redis keys: %v", keys)
	}
}

// TestConsumeSetsRedisTTL verifies the SETNX uses a 15-minute TTL
// matching the token's `exp`. miniredis exposes the configured TTL so
// we can assert it directly.
func TestMagicLinkConsumeSetsRedisTTL(t *testing.T) {
	t.Parallel()
	mr, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	token, err := issuer.Issue(ctx, "acc-ttl")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := issuer.Consume(ctx, token); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// There should be exactly one magic:* key whose TTL is positive
	// and at most MagicLinkTTL.
	var jtiKey string
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "magic:") {
			jtiKey = k
			break
		}
	}
	if jtiKey == "" {
		t.Fatalf("expected a magic:* key in redis, got %v", mr.Keys())
	}
	ttl := mr.TTL(jtiKey)
	if ttl <= 0 || ttl > MagicLinkTTL {
		t.Fatalf("TTL on %s = %v, want (0, %v]", jtiKey, ttl, MagicLinkTTL)
	}
}

// TestForeignKeyRejected proves a token signed with a different
// Ed25519 key cannot be redeemed against our issuer. This is the
// realistic forge scenario: an attacker who has captured the
// Cloud_Platform public key but not its private key.
func TestMagicLinkForeignKeyRejected(t *testing.T) {
	t.Parallel()
	mr, issuer, _ := newMagicLinkIssuer(t)
	ctx := context.Background()

	// Mint a token with an unrelated key pair but a payload that
	// would otherwise pass shape checks.
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	jti := hex.EncodeToString(make([]byte, magicLinkJTIBytes))
	body, err := json.Marshal(magicLinkPayload{
		AccountID: "acc-attacker",
		JTI:       jti,
		Exp:       time.Now().Add(MagicLinkTTL).Unix(),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	sig := ed25519.Sign(attackerPriv, body)
	enc := base64.RawURLEncoding
	forged := enc.EncodeToString(body) + "." + enc.EncodeToString(sig)

	if _, err := issuer.Consume(ctx, forged); !errors.Is(err, ErrMagicLinkInvalid) {
		t.Fatalf("Consume(forged) = %v, want ErrMagicLinkInvalid", err)
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("forged token leaked redis keys: %v", keys)
	}
}

// TestIssueRequiresAccount documents that an empty account id is a
// programmer error: callers must always supply the owning account.
func TestMagicLinkIssueRequiresAccount(t *testing.T) {
	t.Parallel()
	_, issuer, _ := newMagicLinkIssuer(t)
	if _, err := issuer.Issue(context.Background(), ""); err == nil {
		t.Fatal("Issue with empty account id must return an error")
	}
}

// flipMagicLinkSignatureByte rewrites one byte of the signature
// segment of token in a way that keeps the segment a valid base64
// string but breaks the Ed25519 verification.
func flipMagicLinkSignatureByte(t *testing.T, token string) string {
	t.Helper()
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot == len(token)-1 {
		t.Fatalf("flipMagicLinkSignatureByte: malformed token %q", token)
	}
	sigB64 := token[dot+1:]
	raw, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("flipMagicLinkSignatureByte: decode sig: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("flipMagicLinkSignatureByte: empty signature")
	}
	raw[0] ^= 0x01
	return token[:dot+1] + base64.RawURLEncoding.EncodeToString(raw)
}
