// Command xalgorix-cloud is the multi-tenant SaaS entrypoint for the
// Xalgorix Cloud_Platform.
//
// It implements the binary described in design.md → Components and
// Interfaces → "cmd/xalgorix-cloud":
//
//	+------------+-------------------------------------------------+
//	| Flag       | Purpose                                         |
//	+------------+-------------------------------------------------+
//	| --mode api | Run API_Server only (default)                   |
//	| --mode    | Run Worker_Pool only (NATS consumer)            |
//	|   worker   |                                                 |
//	| --mode all | Run both in the same process (dev only)         |
//	+------------+-------------------------------------------------+
//
// Bootstrap order (task 1.14): the very first thing main does is call
// observability.MustInit so logger/metrics/tracer/Sentry are wired
// before any other runner runs and before any request is served. The
// shutdown function returned by MustInit is deferred from main so log
// buffers, trace exporters, and the Sentry queue are flushed during a
// graceful exit. This realises Requirement 12.1, 12.2, 12.3, 12.4, and
// 12.7.
//
// Requirements: 1.1, 1.9, 12.1, 12.2, 12.3, 12.4, 12.7
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/cloud/observability"
)

// mode enumerates the run-modes supported by `cmd/xalgorix-cloud`.
type mode string

const (
	modeAPI    mode = "api"
	modeWorker mode = "worker"
	modeAll    mode = "all"
)

// runAPI, runWorker, and runAll are package-level variables (not constants)
// so that the smoke tests added by task 0.6 can swap them out and verify
// that `--mode` dispatches to the correct constructor without actually
// starting any servers. The current implementations are intentional stubs;
// they are replaced in later phases of the implementation plan.
var (
	runAPI = func(stdout io.Writer, args []string) error {
		_, err := fmt.Fprintln(stdout, "xalgorix-cloud: API_Server mode (scaffold — not yet implemented)")
		return err
	}
	runWorker = func(stdout io.Writer, args []string) error {
		_, err := fmt.Fprintln(stdout, "xalgorix-cloud: Worker_Pool mode (scaffold — not yet implemented)")
		return err
	}
	runAll = func(stdout io.Writer, args []string) error {
		_, err := fmt.Fprintln(stdout, "xalgorix-cloud: API_Server + Worker_Pool combined mode (scaffold — not yet implemented)")
		return err
	}
)

// bootstrapObservability is the observability bootstrap hook used by
// main(). The smoke tests in main_test.go swap it for a no-op so flag
// parsing assertions do not have to pay the cost (or the side-effects)
// of standing up the real telemetry stack. Production code calls the
// real package init in `defaultBootstrapObservability`.
var bootstrapObservability = defaultBootstrapObservability

func defaultBootstrapObservability(ctx context.Context) func(context.Context) error {
	cfg := observability.Config{
		ServiceName:  envOrDefault("XALGORIX_SERVICE_NAME", "xalgorix-cloud"),
		Env:          envOrDefault("XALGORIX_ENV", "dev"),
		Version:      envOrDefault("XALGORIX_VERSION", "unknown"),
		OTLPEndpoint: os.Getenv("XALGORIX_OTLP_ENDPOINT"),
		SentryDSN:    os.Getenv("XALGORIX_SENTRY_DSN"),
		LogLevel:     envOrDefault("XALGORIX_LOG_LEVEL", "info"),
	}
	return observability.MustInit(ctx, cfg)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	// Observability comes online before anything else, so any error
	// hit during flag parsing or runner dispatch is visible in logs.
	bootCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	shutdown := bootstrapObservability(bootCtx)
	cancel()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = shutdown(shutdownCtx)
	}()

	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-cloud:", err)
		os.Exit(1)
	}
}

// run is the testable entrypoint. It parses the `--mode` flag and dispatches
// to the corresponding runner. It writes its own `flag.Usage` output to
// stderr and returns errors instead of calling os.Exit so unit tests can
// exercise it without taking down the test process.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("xalgorix-cloud", flag.ContinueOnError)
	fs.SetOutput(stderr)

	modeFlag := fs.String("mode", string(modeAPI), "run mode: api, worker, or all")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: xalgorix-cloud [--mode api|worker|all]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	switch mode(*modeFlag) {
	case modeAPI:
		return runAPI(stdout, fs.Args())
	case modeWorker:
		return runWorker(stdout, fs.Args())
	case modeAll:
		return runAll(stdout, fs.Args())
	default:
		return fmt.Errorf("invalid --mode %q (expected api, worker, or all)", *modeFlag)
	}
}
