// Package otellogs wires the gate's slog output into an OpenTelemetry
// logs pipeline (OTLP/HTTP) alongside stdout. The gate logs exclusively
// through log/slog; the otelslog bridge turns every record into an OTel
// LogRecord (message -> body, level -> severity, key/values ->
// attributes) so no call sites change.
package otellogs

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	logsdk "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Config mirrors the [observability.otel_logs] config section.
type Config struct {
	Enabled        bool
	Endpoint       string // full OTLP/HTTP URL, e.g. http://collector:4318
	Headers        map[string]string
	Timeout        time.Duration
	MaxQueueSize   int           // 0 = SDK default
	FlushInterval  time.Duration // 0 = SDK default
	ServiceName    string        // resource service.name; required when enabled
	ServiceVersion string        // resource service.version; default "dev" if empty
}

// Setup builds the stdout+OTel fan-out handler and a shutdown function
// that flushes pending records. When disabled it returns stdout unchanged
// with a no-op shutdown. Exporting is asynchronous and batched; a full
// queue drops records inside the SDK without ever blocking a request.
func Setup(cfg Config, stdout slog.Handler, level slog.Level) (slog.Handler, func(context.Context) error, error) {
	if !cfg.Enabled {
		return stdout, func(context.Context) error { return nil }, nil
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, nil, fmt.Errorf("otel_logs: endpoint must be a full http(s) URL, got %q", cfg.Endpoint)
	}
	opts := []otlploghttp.Option{otlploghttp.WithEndpointURL(cfg.Endpoint)}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, otlploghttp.WithTimeout(cfg.Timeout))
	}
	exporter, err := otlploghttp.New(context.Background(), opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("otel_logs: exporter: %w", err)
	}

	var batchOpts []logsdk.BatchProcessorOption
	if cfg.MaxQueueSize > 0 {
		batchOpts = append(batchOpts, logsdk.WithMaxQueueSize(cfg.MaxQueueSize))
	}
	if cfg.FlushInterval > 0 {
		batchOpts = append(batchOpts, logsdk.WithExportInterval(cfg.FlushInterval))
	}
	provider := logsdk.NewLoggerProvider(
		logsdk.WithResource(resource.NewSchemaless(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(orDefault(cfg.ServiceVersion, "dev")),
		)),
		logsdk.WithProcessor(logsdk.NewBatchProcessor(exporter, batchOpts...)),
	)
	return Handler(provider, cfg.ServiceName, stdout, level), provider.Shutdown, nil
}

// Handler returns a fan-out handler: every record (at or above level) is
// delivered to both the stdout handler and an otelslog handler backed by
// provider. Split from Setup so tests can drive the bridge with an
// in-memory exporter.
func Handler(provider *logsdk.LoggerProvider, scope string, stdout slog.Handler, level slog.Level) slog.Handler {
	return &fanout{
		level: level,
		handlers: []slog.Handler{
			stdout,
			otelslog.NewHandler(scope, otelslog.WithLoggerProvider(provider)),
		},
	}
}

// fanout is slog's missing multi-handler with a single level gate.
type fanout struct {
	level    slog.Level
	handlers []slog.Handler
}

func (f *fanout) Enabled(_ context.Context, l slog.Level) bool { return l >= f.level }

func (f *fanout) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range f.handlers {
		if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &fanout{level: f.level, handlers: make([]slog.Handler, len(f.handlers))}
	for i, h := range f.handlers {
		next.handlers[i] = h.WithAttrs(attrs)
	}
	return next
}

func (f *fanout) WithGroup(name string) slog.Handler {
	next := &fanout{level: f.level, handlers: make([]slog.Handler, len(f.handlers))}
	for i, h := range f.handlers {
		next.handlers[i] = h.WithGroup(name)
	}
	return next
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
