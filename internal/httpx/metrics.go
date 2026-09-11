package httpx

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Metrics is a dependency-free registry for the handful of counters and
// gauges registry-gate exposes in the Prometheus text exposition format
// on the metrics listener.
type Metrics struct {
	mu sync.Mutex

	decisions      map[string]uint64
	upstreamErrors uint64

	// Optional live suppliers for gauges (wired by main).
	whitelistSize       func() int
	whitelistReloadErrs func() int
}

// NewMetrics returns an empty metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{decisions: map[string]uint64{}}
}

// IncDecision increments the gate decision counter for decision
// (e.g. "allow_anon_by_rule").
func (m *Metrics) IncDecision(decision string) {
	m.mu.Lock()
	m.decisions[decision]++
	m.mu.Unlock()
}

// IncUpstreamError increments the counter of failed upstream (Harbor)
// forwarding attempts.
func (m *Metrics) IncUpstreamError() {
	m.mu.Lock()
	m.upstreamErrors++
	m.mu.Unlock()
}

// SetWhitelistSizeFunc registers the supplier for the whitelist size gauge.
func (m *Metrics) SetWhitelistSizeFunc(f func() int) {
	m.mu.Lock()
	m.whitelistSize = f
	m.mu.Unlock()
}

// SetWhitelistReloadErrorsFunc registers the supplier for the whitelist
// reload-error counter gauge.
func (m *Metrics) SetWhitelistReloadErrorsFunc(f func() int) {
	m.mu.Lock()
	m.whitelistReloadErrs = f
	m.mu.Unlock()
}

// Handler serves the metrics in Prometheus text format under /metrics.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		var b strings.Builder
		writeMetric := func(name, help, typ, body string) {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s", name, help, name, typ, body)
		}

		var body strings.Builder
		keys := make([]string, 0, len(m.decisions))
		for k := range m.decisions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&body, "%s{decision=%q} %d\n", "registry_gate_decisions_total", k, m.decisions[k])
		}
		writeMetric("registry_gate_decisions_total",
			"Gate decisions by outcome.", "counter", body.String())

		writeMetric("registry_gate_upstream_errors_total",
			"Failed or non-2xx upstream (Harbor) forwarding attempts.", "counter",
			fmt.Sprintf("registry_gate_upstream_errors_total %d\n", m.upstreamErrors))

		reloadErrs := 0
		if m.whitelistReloadErrs != nil {
			reloadErrs = m.whitelistReloadErrs()
		}
		writeMetric("registry_gate_whitelist_reload_errors_total",
			"Failed whitelist reload attempts.", "counter",
			fmt.Sprintf("registry_gate_whitelist_reload_errors_total %d\n", reloadErrs))

		size := 0
		if m.whitelistSize != nil {
			size = m.whitelistSize()
		}
		writeMetric("registry_gate_whitelist_entries",
			"Current number of whitelist entries.", "gauge",
			fmt.Sprintf("registry_gate_whitelist_entries %d\n", size))

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
}
