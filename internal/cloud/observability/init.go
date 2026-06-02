// Init wires the four observability stacks called out in design.md
// (logging, metrics, tracing, error reporting) and Requirement 12 of
// `requirements.md`:
//
//   - structured zerolog JSON logger to stdout, stamped with the
//     correlation fields named in Requirement 12.1
//     (`timestamp`, `level`, `service`, `request_id`, `organization_id`,
//     `workspace_id`, `account_id`, `event`, `message`).
//   - a Prometheus registry exposed via Registry() so HTTP handlers and
//     the worker pool can register their own collectors and the
//     `/metrics` endpoint can scrape them (Requirement 12.2).
//   - an OpenTelemetry tracer provider that ships spans to Tempo via
//     OTLP HTTP or gRPC, tagged with `service.name`
//     (Requirement 12.3).
//   - a Sentry hub primed with `service`, `environment`, and `release`
//     tags so unhandled errors carry the same correlation context used
//     in logs (Requirement 12.4).
//
// `MustInit` is the very first call inside `cmd/xalgorix-cloud/main.go`
// and panics on a hard wiring failure (logger / metrics / tracer
// construction) but degrades gracefully — without panicking — when an
// optional sink is missing or temporarily unreachable: an unset
// `OTLPEndpoint` skips the tracer exporter, an unset `SentryDSN` runs
// Sentry in no-op mode, and an OTLP exporter that cannot be built does
// not bring the process down. This matches Requirement 12.7's "retain
// logs for 30 days, metrics for 13 months, traces for 7 days" — losing
// traces in a cold-start outage must not take the API_Server with it.
package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config carries the wiring inputs for MustInit. Every field is optional
// from the call-site's perspective: missing values fall back to the
// zero-value defaults documented per field. The intent is that
// `cmd/xalgorix-cloud/main.go` can read its environment, fill what is
// available, and hand the struct over without further validation.
type Config struct {
	// ServiceName is the value stamped onto every log line ("service"
	// field) and onto every OTel span as the `service.name` resource
	// attribute. Defaults to "xalgorix-cloud" when empty.
	ServiceName string
	// Env names the deployment environment (e.g. "dev", "staging",
	// "prod"). It becomes the "env" log field and the Sentry
	// `Environment`. Defaults to "dev".
	Env string
	// Version names the release that is running. It becomes the
	// "version" log field and the Sentry `Release`. Defaults to
	// "unknown".
	Version string
	// OTLPEndpoint is the host:port (and optional scheme) of the Tempo
	// OTLP receiver. Examples:
	//
	//   tempo.observability:4318       (defaults to OTLP/HTTP)
	//   http://tempo.observability:4318
	//   grpc://tempo.observability:4317
	//
	// When empty the tracer provider is constructed with no exporter
	// and spans go to /dev/null — the no-op cost stays bounded so we
	// never block the request path on a cold-start observability
	// failure.
	OTLPEndpoint string
	// SentryDSN points at the Sentry project. When empty, sentry-go is
	// initialised in no-op mode (events are dropped on the floor).
	SentryDSN string
	// LogLevel selects the zerolog level: "trace", "debug", "info",
	// "warn", "error". Defaults to "info" when empty or unparseable.
	LogLevel string
	// LogOutput is an optional writer override for the JSON logger.
	// When nil we write to os.Stdout, matching design.md's
	// "internal/cloud/observability → Logger: zerolog JSON to stdout".
	// The field exists so unit tests can capture output without
	// shelling out to the OS.
	LogOutput io.Writer
}

// registry is the process-wide Prometheus registry. We do not reuse
// prometheus.DefaultRegisterer because it auto-registers Go runtime and
// process collectors; we want the same observability for the runtime
// metrics but registered onto our own private registry so callers know
// the surface area is curated and consistent across replicas. The
// sync.Once guards against the (illegal but possible) case of MustInit
// being called twice in the same process — duplicate registrations of
// the standard collectors panic, and we want to surface a single,
// readable error rather than a stack trace.
var (
	registry      *prometheus.Registry
	registryOnce  sync.Once
	registrySetup error
)

// Registry returns the process-wide Prometheus registry. Callers must
// call MustInit before Registry; calling Registry first returns nil
// because we deliberately do not lazy-initialise — that would let
// metrics escape the bootstrap order documented in
// `cmd/xalgorix-cloud/main.go`.
func Registry() *prometheus.Registry {
	return registry
}

// Tracer returns a named tracer scoped to the package or component
// `name`. It is a thin convenience over otel.Tracer that keeps callers
// from importing the otel root package directly for the common case.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// MustInit wires the four pillars (logging, metrics, tracing, errors)
// and returns a shutdown function that flushes/closes them in reverse
// order. The shutdown function is safe to call exactly once and
// observes the supplied context's deadline so it can be wired straight
// into `defer shutdown(context.Background())` from main.
//
// MustInit panics only on logically impossible wiring failures
// (Prometheus collector registration). Sentry, OTLP, and any external
// network sink fail soft: we log a structured "observability_degraded"
// event and continue. This keeps the bootstrap order — observability
// first, runners second — robust against the very failures
// observability is supposed to surface.
func MustInit(ctx context.Context, cfg Config) func(context.Context) error {
	cfg = withDefaults(cfg)

	// 1. Logger.
	logger := buildLogger(cfg)
	log.Logger = logger
	zerolog.DefaultContextLogger = &logger

	// 2. Prometheus registry. Standard Go runtime + process collectors
	// are registered exactly once for the lifetime of the process.
	registryOnce.Do(func() {
		reg := prometheus.NewRegistry()
		if err := reg.Register(collectors.NewGoCollector()); err != nil {
			registrySetup = fmt.Errorf("register go collector: %w", err)
			return
		}
		if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
			registrySetup = fmt.Errorf("register process collector: %w", err)
			return
		}
		registry = reg
	})
	if registrySetup != nil {
		// Collector registration failures are programming errors
		// (duplicate metric, invalid descriptor) and should fail
		// loudly so they surface in CI, not in production.
		panic(registrySetup)
	}

	// 3. Tracer provider. Failures here downgrade to a no-op tracer
	// rather than panic — see package doc-comment.
	tp, traceShutdown := buildTracerProvider(ctx, cfg, logger)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// 4. Sentry hub. Same fail-soft contract as the tracer: a missing
	// or invalid DSN must not block boot.
	sentryShutdown := buildSentry(cfg, logger)

	logger.Info().
		Str("event", "observability_initialized").
		Str("service", cfg.ServiceName).
		Str("env", cfg.Env).
		Str("version", cfg.Version).
		Bool("otlp_enabled", cfg.OTLPEndpoint != "").
		Bool("sentry_enabled", cfg.SentryDSN != "").
		Msg("observability bootstrap complete")

	return func(shutdownCtx context.Context) error {
		var errs []error
		// Flush Sentry before the tracer so any error reported during
		// trace shutdown still gets through the network.
		if err := sentryShutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("sentry shutdown: %w", err))
		}
		if err := traceShutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("trace shutdown: %w", err))
		}
		return errors.Join(errs...)
	}
}

// withDefaults fills missing Config fields with their documented
// defaults. Kept as a separate helper so the test in init_test.go can
// pin the defaulted values without re-implementing the table.
func withDefaults(cfg Config) Config {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "xalgorix-cloud"
	}
	if cfg.Env == "" {
		cfg.Env = "dev"
	}
	if cfg.Version == "" {
		cfg.Version = "unknown"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	return cfg
}

// buildLogger constructs the zerolog logger that becomes the default
// for the process. The choice of UnixMicro timestamps mirrors what the
// existing self-hosted binary uses elsewhere in the repo and keeps log
// volume bounded.
func buildLogger(cfg Config) zerolog.Logger {
	out := cfg.LogOutput
	if out == nil {
		out = os.Stdout
	}
	level, err := zerolog.ParseLevel(strings.ToLower(cfg.LogLevel))
	if err != nil || level == zerolog.NoLevel {
		level = zerolog.InfoLevel
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano
	return zerolog.New(out).
		Level(level).
		With().
		Timestamp().
		Str("service", cfg.ServiceName).
		Str("env", cfg.Env).
		Str("version", cfg.Version).
		Logger()
}

// buildTracerProvider constructs an OTel tracer provider. The exporter
// is selected from the `OTLPEndpoint` field — when missing or
// unparseable we return a tracer provider with no exporter (spans are
// recorded into the void) and a no-op shutdown. This matches the
// fail-soft semantics documented in the Config godoc.
func buildTracerProvider(ctx context.Context, cfg Config, logger zerolog.Logger) (*sdktrace.TracerProvider, func(context.Context) error) {
	res, err := sdkresource.Merge(
		sdkresource.Default(),
		sdkresource.NewSchemaless(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.Version),
			semconv.DeploymentEnvironment(cfg.Env),
		),
	)
	if err != nil {
		// Schema mismatch is the only error sdkresource.Merge can
		// return; we degrade to a default resource and log the issue.
		logger.Warn().
			Str("event", "observability_degraded").
			Err(err).
			Msg("falling back to default OTel resource")
		res = sdkresource.Default()
	}

	if cfg.OTLPEndpoint == "" {
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res))
		return tp, tp.Shutdown
	}

	exporter, err := newOTLPExporter(ctx, cfg.OTLPEndpoint)
	if err != nil {
		logger.Warn().
			Str("event", "observability_degraded").
			Str("otlp_endpoint", cfg.OTLPEndpoint).
			Err(err).
			Msg("OTLP exporter unavailable — tracing disabled")
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res))
		return tp, tp.Shutdown
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
	)
	return tp, tp.Shutdown
}

// newOTLPExporter picks between OTLP/HTTP and OTLP/gRPC based on the
// endpoint's scheme and constructs the corresponding exporter. We use
// insecure transport by default because the in-cluster Tempo receiver
// is reached through a service mesh that already terminates TLS, and
// because requiring TLS at this seam would force every dev environment
// to provision a cert just to ship spans.
func newOTLPExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	scheme, host := splitOTLPEndpoint(endpoint)
	switch scheme {
	case "grpc":
		return otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(host),
			otlptracegrpc.WithInsecure(),
		)
	case "http", "":
		return otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(host),
			otlptracehttp.WithInsecure(),
		)
	default:
		// We only implement HTTP and gRPC OTLP transports. Anything
		// else is a configuration mistake worth surfacing.
		return nil, fmt.Errorf("unsupported OTLP scheme %q in endpoint %q", scheme, endpoint)
	}
}

// splitOTLPEndpoint accepts the four shapes documented on Config.OTLPEndpoint:
//
//	"tempo:4318"             → ("", "tempo:4318")
//	"http://tempo:4318"      → ("http", "tempo:4318")
//	"https://tempo:4318"     → ("http", "tempo:4318") // TLS handled at the mesh layer
//	"grpc://tempo:4317"      → ("grpc", "tempo:4317")
//
// Anything that fails url.Parse (or parses cleanly but yields an
// unsupported scheme) is returned as a non-empty scheme so the caller
// can reject it.
func splitOTLPEndpoint(endpoint string) (scheme, host string) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", ""
	}
	if !strings.Contains(endpoint, "://") {
		// Bare host:port form; default to OTLP/HTTP.
		return "", endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint, ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return "http", u.Host
	case "grpc":
		return "grpc", u.Host
	default:
		return strings.ToLower(u.Scheme), u.Host
	}
}

// buildSentry initialises the global Sentry hub. Returning a shutdown
// closure (rather than relying on sentry.Flush at process exit) lets
// the caller bound the wait time on a chosen context — important
// because Kubernetes preStop hooks have a strict deadline.
func buildSentry(cfg Config, logger zerolog.Logger) func(context.Context) error {
	if cfg.SentryDSN == "" {
		return func(context.Context) error { return nil }
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              cfg.SentryDSN,
		Environment:      cfg.Env,
		Release:          cfg.Version,
		ServerName:       cfg.ServiceName,
		AttachStacktrace: true,
	})
	if err != nil {
		logger.Warn().
			Str("event", "observability_degraded").
			Err(err).
			Msg("sentry init failed — continuing without error reporting")
		return func(context.Context) error { return nil }
	}
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("service", cfg.ServiceName)
		scope.SetTag("env", cfg.Env)
		scope.SetTag("version", cfg.Version)
	})
	return func(ctx context.Context) error {
		// Honour the caller-supplied deadline; if none, give Sentry a
		// generous five seconds to drain the queue.
		timeout := 5 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
				timeout = remaining
			}
		}
		if !sentry.Flush(timeout) {
			return errors.New("sentry flush timed out")
		}
		return nil
	}
}


