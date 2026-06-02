// Redis client wrapper for the Xalgorix Cloud_Platform.
//
// This file implements task 1.15 from the `xalgorix-saas` spec:
//
//   - [Client] wraps `redis.UniversalClient` so the rest of the cloud
//     binary speaks a small, intent-revealing surface instead of the
//     raw client API. The underlying client may be a single-node,
//     sentinel-fronted, or cluster client; callers do not care.
//   - [New] constructs the wrapper from [Options], pings the server to
//     fail fast on misconfiguration, and returns a [Client] that owns
//     the underlying connection pool.
//   - [Client.XAdd], [Client.XRange] expose the per-scan replay stream
//     primitives used by `internal/cloud/worker` (telemetry pump) and
//     the API WebSocket coalescer (`XADD scans:replay:{scan_id} MAXLEN
//     ~ 10000 *` and the matching `XRANGE` on reconnect, per design.md).
//   - [Client.SetNX] is the single-use enforcement primitive used by
//     `auth/magiclink.go` (`SETNX magic:{jti} 1 EX 900`).
//   - [Client.Publish] / [Client.Subscribe] cover the Redis Pub/Sub
//     fan-out used by the WebSocket coalescer
//     (`ws:org:{org}:scan:{scan_id}`). [Client.Subscribe] returns a
//     buffered `<-chan *redis.Message` together with a cancel func so
//     callers cannot leak goroutines if they forget to unsubscribe.
//
// Requirements: 6.3, 14.1.

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Message re-exports `redis.Message` so callers do not need to import
// the upstream package directly when using [Client.Subscribe].
type Message = goredis.Message

// XMessage re-exports `redis.XMessage` so callers can read entries
// returned by [Client.XRange] without depending on the upstream client.
type XMessage = goredis.XMessage

// UniversalClient re-exports the upstream interface so callers can
// reach the full client surface for the small handful of commands not
// yet covered by helper methods on [Client].
type UniversalClient = goredis.UniversalClient

// Options configures [New]. It is a thin wrapper around
// `redis.UniversalOptions` that exposes only the fields the
// Cloud_Platform actually consumes today; ad-hoc tuning can be done
// through [Options.Tune].
type Options struct {
	// Addrs is either a single `host:port` (single-node / sentinel
	// proxy) or a seed list of cluster nodes. At least one entry is
	// required.
	Addrs []string
	// Username is the optional ACL username (Redis 6+).
	Username string
	// Password is the optional ACL password.
	Password string
	// DB selects the logical database for single-node deployments.
	// Cluster deployments ignore the field.
	DB int
	// MasterName, when non-empty, switches the underlying client to
	// sentinel mode and treats Addrs as the sentinel seed list.
	MasterName string
	// DialTimeout caps the time spent establishing a TCP connection.
	// Defaults to 5s when zero.
	DialTimeout time.Duration
	// ReadTimeout caps individual command reads. Defaults to 3s when
	// zero. Pub/Sub uses a longer internal timeout managed by the
	// upstream client.
	ReadTimeout time.Duration
	// WriteTimeout caps individual command writes. Defaults to 3s when
	// zero.
	WriteTimeout time.Duration
	// PoolSize is the maximum number of socket connections per node.
	// Zero falls back to the upstream default (`10 * NumCPU`).
	PoolSize int
	// Tune is invoked with the materialised `UniversalOptions` right
	// before the client is constructed so callers can override fields
	// not surfaced here (TLS config, dialers, retry policy). It is
	// optional.
	Tune func(*goredis.UniversalOptions)
}

// Client is the Cloud_Platform-facing Redis facade. It is safe for
// concurrent use; the underlying go-redis client maintains its own
// connection pool.
type Client struct {
	rdb goredis.UniversalClient
}

// New opens a Redis client using opts and verifies connectivity with a
// PING. The returned [Client] owns the connection pool; the caller must
// invoke [Client.Close] on shutdown.
//
// New returns an error when opts.Addrs is empty, when the underlying
// client cannot be constructed, or when the initial PING fails. The
// PING is bounded by ctx so callers can apply a startup deadline.
func New(ctx context.Context, opts Options) (*Client, error) {
	if len(opts.Addrs) == 0 {
		return nil, errors.New("cloud/redis: at least one address is required")
	}

	uo := &goredis.UniversalOptions{
		Addrs:        append([]string(nil), opts.Addrs...),
		Username:     opts.Username,
		Password:     opts.Password,
		DB:           opts.DB,
		MasterName:   opts.MasterName,
		DialTimeout:  defaultDuration(opts.DialTimeout, 5*time.Second),
		ReadTimeout:  defaultDuration(opts.ReadTimeout, 3*time.Second),
		WriteTimeout: defaultDuration(opts.WriteTimeout, 3*time.Second),
		PoolSize:     opts.PoolSize,
	}
	if opts.Tune != nil {
		opts.Tune(uo)
	}

	rdb := goredis.NewUniversalClient(uo)
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("cloud/redis: ping failed: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// NewWithClient wraps an already-constructed `redis.UniversalClient`.
// It is provided so tests can plug in a `miniredis`-backed client
// without going through [New]'s real PING — and so callers that want
// to share a client between packages can do so without surrendering
// type safety.
func NewWithClient(rdb goredis.UniversalClient) *Client {
	return &Client{rdb: rdb}
}

// Underlying exposes the wrapped `redis.UniversalClient`. It is meant
// for migration paths and tests; production code should prefer the
// helper methods on [Client] so we keep a small, auditable surface.
func (c *Client) Underlying() goredis.UniversalClient {
	return c.rdb
}

// Close releases the underlying connection pool. It is safe to call
// multiple times; subsequent calls return the upstream client's reply.
func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}

// Ping verifies connectivity. It is exposed primarily for the
// `/readyz` probe wired in Phase 1 task 1.14.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// XAdd appends an entry to the given stream and returns the assigned
// entry id. When maxLen is positive the call uses `MAXLEN ~ <maxLen>`
// (approximate trimming) to match the per-scan replay budget described
// in design.md (`scans:replay:{scan_id}` capped at 10,000). When
// maxLen is zero or negative the stream grows without bound.
//
// The values map is forwarded as-is to the upstream client; entry ids
// are assigned by the server (the wrapper always passes `*`). Callers
// must ensure values are encodable by the go-redis appendArg path
// (strings, byte slices, numbers, fmt.Stringer, encoding.BinaryMarshaler).
func (c *Client) XAdd(ctx context.Context, stream string, maxLen int64, values map[string]any) (string, error) {
	if stream == "" {
		return "", errors.New("cloud/redis: XAdd requires a non-empty stream")
	}
	if len(values) == 0 {
		return "", errors.New("cloud/redis: XAdd requires at least one value")
	}
	args := &goredis.XAddArgs{
		Stream: stream,
		Values: values,
	}
	if maxLen > 0 {
		args.MaxLen = maxLen
		args.Approx = true
	}
	id, err := c.rdb.XAdd(ctx, args).Result()
	if err != nil {
		return "", fmt.Errorf("cloud/redis: XAdd %q: %w", stream, err)
	}
	return id, nil
}

// XRange reads entries from stream within the inclusive id range
// [start, end]. When count is positive the call delegates to `XRANGE
// COUNT n` (via go-redis' `XRangeN`) so the WebSocket coalescer can
// bound its reconnect replay. A non-positive count returns the full
// range. The redis special ids "-" and "+" are accepted as start/end
// to mean "first" and "last".
func (c *Client) XRange(ctx context.Context, stream, start, end string, count int) ([]XMessage, error) {
	if stream == "" {
		return nil, errors.New("cloud/redis: XRange requires a non-empty stream")
	}
	if start == "" {
		start = "-"
	}
	if end == "" {
		end = "+"
	}

	var (
		msgs []goredis.XMessage
		err  error
	)
	if count > 0 {
		msgs, err = c.rdb.XRangeN(ctx, stream, start, end, int64(count)).Result()
	} else {
		msgs, err = c.rdb.XRange(ctx, stream, start, end).Result()
	}
	if err != nil {
		return nil, fmt.Errorf("cloud/redis: XRange %q: %w", stream, err)
	}
	return msgs, nil
}

// SetNX sets key to value if and only if it does not exist, with the
// provided ttl. It returns acquired=true when the key was created. A
// zero ttl persists the key indefinitely; callers that want a
// guaranteed expiry (magic links, idempotency tokens) MUST pass a
// positive duration.
func (c *Client) SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, errors.New("cloud/redis: SetNX requires a non-empty key")
	}
	acquired, err := c.rdb.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("cloud/redis: SetNX %q: %w", key, err)
	}
	return acquired, nil
}

// Publish posts payload onto channel via Redis Pub/Sub and returns
// nil on success. The number of receivers is intentionally not
// surfaced because the Cloud_Platform fan-out (the WebSocket
// coalescer) treats no-subscribers as a transient condition.
func (c *Client) Publish(ctx context.Context, channel string, payload []byte) error {
	if channel == "" {
		return errors.New("cloud/redis: Publish requires a non-empty channel")
	}
	if err := c.rdb.Publish(ctx, channel, payload).Err(); err != nil {
		return fmt.Errorf("cloud/redis: Publish %q: %w", channel, err)
	}
	return nil
}

// Subscription is the handle returned by [Client.Subscribe]. It owns
// the underlying `*redis.PubSub` and exposes only a receive-only
// message channel plus a [Subscription.Close] method.
type Subscription struct {
	pubsub *goredis.PubSub
	ch     <-chan *Message
}

// Channel returns the receive-only message channel. It is closed by
// the upstream client once [Subscription.Close] returns, which makes
// `for msg := range sub.Channel()` a correct pattern even after the
// caller cancels.
func (s *Subscription) Channel() <-chan *Message {
	return s.ch
}

// Close unsubscribes from every previously-subscribed channel and
// releases the connection back to the pool. It is safe to call
// multiple times; subsequent calls forward the upstream client's
// reply (typically `nil` after the first call).
func (s *Subscription) Close() error {
	if s == nil || s.pubsub == nil {
		return nil
	}
	return s.pubsub.Close()
}

// Subscribe joins one or more pub/sub channels and returns a managed
// [Subscription]. The returned channel is buffered (the upstream
// client uses an internal goroutine to pump messages from the wire)
// and the caller MUST invoke `Subscription.Close` on cleanup to avoid
// leaking the goroutine.
//
// Subscribe blocks until the SUBSCRIBE handshake completes or ctx is
// canceled, ensuring callers do not race a Publish issued immediately
// after the function returns.
func (c *Client) Subscribe(ctx context.Context, channels ...string) (*Subscription, error) {
	if len(channels) == 0 {
		return nil, errors.New("cloud/redis: Subscribe requires at least one channel")
	}
	for _, ch := range channels {
		if ch == "" {
			return nil, errors.New("cloud/redis: Subscribe channel must be non-empty")
		}
	}

	pubsub := c.rdb.Subscribe(ctx, channels...)
	// Wait for the SUBSCRIBE confirmation so callers cannot race a
	// Publish issued immediately after Subscribe returns. We use
	// ReceiveTimeout-style logic via Receive(ctx) which blocks until a
	// message of any kind arrives or ctx is done.
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		return nil, fmt.Errorf("cloud/redis: subscribe handshake: %w", err)
	}
	return &Subscription{pubsub: pubsub, ch: pubsub.Channel()}, nil
}

func defaultDuration(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
