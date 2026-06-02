package resources

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/semaphore"
)

// ── LLM in-flight cap (R3.3, R3.4) ──
//
// A process-global weighted semaphore bounds concurrent LLM requests so that a
// fleet of running scans cannot stampede the upstream model and starve the
// host of file descriptors, sockets, and HTTP/2 streams.
//
// The cap is initialized lazily on first use from the XALGORIX_LLM_MAX_INFLIGHT
// environment variable, falling back to 4 × EffectiveMaxInstances() with a
// floor of 1 when the env value is missing or non-positive.

var (
	// llmInFlight is the process-global weighted semaphore that bounds the
	// number of concurrent in-flight LLM requests.
	llmInFlight *semaphore.Weighted

	// llmOnce guards one-time initialization of llmInFlight and llmCap.
	llmOnce sync.Once

	// llmCap is the configured cap, exposed via LLMInFlightCap for diagnostics.
	// It is read atomically so callers do not need to take a lock.
	llmCap int64
)

// initLLMSemaphore reads XALGORIX_LLM_MAX_INFLIGHT and sizes llmInFlight.
//
// Resolution order:
//  1. If XALGORIX_LLM_MAX_INFLIGHT parses to a positive integer, use it.
//  2. Otherwise default to 4 × EffectiveMaxInstances(), with a floor of 1.
//
// The function is invoked exactly once via llmOnce; subsequent acquires reuse
// the semaphore and the cap value.
func initLLMSemaphore() {
	n, _ := strconv.Atoi(os.Getenv("XALGORIX_LLM_MAX_INFLIGHT"))
	if n <= 0 {
		eff, _ := EffectiveMaxInstances()
		if eff < 1 {
			eff = 1
		}
		n = 4 * eff
	}
	if n < 1 {
		n = 1
	}
	atomic.StoreInt64(&llmCap, int64(n))
	llmInFlight = semaphore.NewWeighted(int64(n))
}

// AcquireLLMSlot reserves one in-flight LLM slot, blocking until a slot is
// available or ctx is canceled.
//
// On success it returns a release function that callers MUST invoke exactly
// once (typically via defer) after the LLM call returns, freeing the slot for
// the next request.
//
// On context cancellation it returns a no-op release function and ctx.Err()
// without consuming a slot — semaphore.Weighted.Acquire guarantees that a
// failed acquire does not deduct from the semaphore, satisfying R3.4 / P3.4.
func AcquireLLMSlot(ctx context.Context) (func(), error) {
	llmOnce.Do(initLLMSemaphore)
	if err := llmInFlight.Acquire(ctx, 1); err != nil {
		return func() {}, err
	}
	return func() { llmInFlight.Release(1) }, nil
}

// LLMInFlightCap returns the configured maximum number of concurrent in-flight
// LLM requests for diagnostics and health reporting. The cap is finalized on
// first AcquireLLMSlot call; before that it reads as zero.
func LLMInFlightCap() int {
	return int(atomic.LoadInt64(&llmCap))
}
