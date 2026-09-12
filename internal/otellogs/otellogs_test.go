package otellogs

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	logsdk "go.opentelemetry.io/otel/sdk/log"
)

// captureExporter records everything the pipeline emits, standing in for
// the OTLP exporter so the slog->LogRecord mapping can be asserted.
type captureExporter struct {
	mu      sync.Mutex
	records []logsdk.Record
}

func (e *captureExporter) Export(_ context.Context, records []logsdk.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, records...)
	return nil
}

func (e *captureExporter) Shutdown(context.Context) error   { return nil }
func (e *captureExporter) ForceFlush(context.Context) error { return nil }

func (e *captureExporter) snapshot() []logsdk.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]logsdk.Record(nil), e.records...)
}

func newTestHandler(t *testing.T, level slog.Level) (*captureExporter, *slog.Logger, *bytesRecorder) {
	t.Helper()
	cap := &captureExporter{}
	provider := logsdk.NewLoggerProvider(
		logsdk.WithProcessor(logsdk.NewSimpleProcessor(cap)),
	)
	stdout := &bytesRecorder{Handler: slog.NewTextHandler(io.Discard, nil)}
	h := Handler(provider, "registry-gate", stdout, level)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return cap, slog.New(h), stdout
}

type bytesRecorder struct {
	slog.Handler
	mu    sync.Mutex
	count int
}

func (b *bytesRecorder) Handle(ctx context.Context, r slog.Record) error {
	b.mu.Lock()
	b.count++
	b.mu.Unlock()
	return b.Handler.Handle(ctx, r)
}

func TestSlogToOTelMapping(t *testing.T) {
	cap, logger, stdout := newTestHandler(t, slog.LevelInfo)
	logger.Log(context.Background(), slog.LevelInfo, "gate decision",
		"ip", "10.0.0.1", "subject", "3220106026",
		"scopes", "repository:docker.io/library/busybox", "decision", "allow_authed")

	records := cap.snapshot()
	if len(records) != 1 {
		t.Fatalf("captured %d records, want 1", len(records))
	}
	r := records[0]
	if r.Body().AsString() != "gate decision" {
		t.Errorf("body = %q", r.Body().AsString())
	}
	if r.SeverityText() != "INFO" || r.Severity() != 9 { // SeverityInfo
		t.Errorf("severity = %q(%d)", r.SeverityText(), r.Severity())
	}
	attrs := map[string]string{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		attrs[string(kv.Key)] = kv.Value.AsString()
		return true
	})
	for k, want := range map[string]string{
		"ip": "10.0.0.1", "subject": "3220106026",
		"scopes": "repository:docker.io/library/busybox", "decision": "allow_authed",
	} {
		if attrs[k] != want {
			t.Errorf("attr %s = %q, want %q", k, attrs[k], want)
		}
	}
	if stdout.count != 1 {
		t.Errorf("stdout received %d records, want 1 (fan-out)", stdout.count)
	}
}

func TestLevelGateFiltersBothSinks(t *testing.T) {
	cap, logger, stdout := newTestHandler(t, slog.LevelWarn)
	logger.Info("dropped by level", "k", "v")
	logger.Warn("kept", "k", "v")
	if n := len(cap.snapshot()); n != 1 {
		t.Errorf("otel captured %d, want 1", n)
	}
	if stdout.count != 1 {
		t.Errorf("stdout received %d, want 1", stdout.count)
	}
}

func TestSetupDisabledIsPassthrough(t *testing.T) {
	stdout := slog.NewTextHandler(io.Discard, nil)
	h, shutdown, err := Setup(Config{Enabled: false}, stdout, slog.LevelInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*slog.TextHandler); !ok {
		t.Fatalf("disabled Setup must return stdout unchanged, got %T", h)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("noop shutdown: %v", err)
	}
}

func TestSetupRejectsBadEndpoint(t *testing.T) {
	stdout := slog.NewTextHandler(io.Discard, nil)
	for _, bad := range []string{"", "collector:4318", "ftp://x", "http://"} {
		if _, _, err := Setup(Config{Enabled: true, Endpoint: bad, ServiceName: "registry-gate"}, stdout, slog.LevelInfo); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
}
