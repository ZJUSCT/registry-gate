package httpx

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWriteErrorSchema(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusUnauthorized, "UNAUTHORIZED", "please log in")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var got struct {
		Errors []map[string]any `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not json: %v (%s)", err, rec.Body.String())
	}
	if len(got.Errors) != 1 {
		t.Fatalf("errors len = %d, want 1", len(got.Errors))
	}
	if got.Errors[0]["code"] != "UNAUTHORIZED" || got.Errors[0]["message"] != "please log in" {
		t.Fatalf("bad error entry: %v", got.Errors[0])
	}
	if _, ok := got.Errors[0]["detail"]; ok {
		t.Fatal("unexpected detail field")
	}
}

func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies([]string{"10.0.0.0/8", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	untrusted := &ProxyChecker{}

	req := func(remote string, xff ...string) *http.Request {
		r := &http.Request{Header: http.Header{}, RemoteAddr: remote}
		if len(xff) > 0 {
			r.Header.Set("X-Forwarded-For", strings.Join(xff, ", "))
		}
		return r
	}

	tests := []struct {
		name    string
		checker *ProxyChecker
		remote  string
		xff     []string
		want    string
	}{
		{"no xff", trusted, "192.0.2.10:4444", nil, "192.0.2.10"},
		{"no xff untrusted checker", untrusted, "192.0.2.10:4444", nil, "192.0.2.10"},
		{"peer trusted, one hop", trusted, "10.1.2.3:1000", []string{"192.0.2.10"}, "192.0.2.10"},
		{"peer trusted, chain", trusted, "10.1.2.3:1000", []string{"192.0.2.10", "10.9.9.9", "10.8.8.8"}, "192.0.2.10"},
		{"all hops trusted -> leftmost", trusted, "10.1.2.3:1000", []string{"10.0.0.1", "10.0.0.2"}, "10.0.0.1"},
		{"untrusted peer ignores xff", untrusted, "203.0.113.5:80", []string{"1.1.1.1"}, "203.0.113.5"},
		{"ipv6 peer trusted", trusted, "[fd00::1]:999", []string{"2001:db8::7"}, "2001:db8::7"},
		{"ipv6 in xff", trusted, "10.0.0.5:1", []string{"[2001:db8::9]:1234", "garbage"}, "2001:db8::9"},
		{"garbage only in xff", trusted, "10.0.0.5:1", []string{"not-an-ip"}, "10.0.0.5"},
		{"multiple xff headers", trusted, "10.0.0.5:1", []string{"a"}, "10.0.0.5"},
	}
	tests[len(tests)-1].xff = nil
	// The last case is exercised separately in TestClientIPMultipleHeaders.
	tests = tests[:len(tests)-1]

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.checker.ClientIP(req(tt.remote, tt.xff...)); got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIPMultipleHeaders(t *testing.T) {
	trusted, _ := ParseTrustedProxies([]string{"10.0.0.0/8"})
	r := &http.Request{Header: http.Header{}, RemoteAddr: "10.0.0.5:1"}
	r.Header.Add("X-Forwarded-For", "192.0.2.1, 10.0.0.9")
	r.Header.Add("X-Forwarded-For", "198.51.100.7")
	// Hops: [192.0.2.1, 10.0.0.9, 198.51.100.7]; rightmost untrusted = 198.51.100.7.
	if got := trusted.ClientIP(r); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want 198.51.100.7", got)
	}
}

func TestParseTrustedProxiesInvalid(t *testing.T) {
	if _, err := ParseTrustedProxies([]string{"10.0.0.0/8", "nope"}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}

func TestRequestLogger(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	})
	rec := httptest.NewRecorder()
	RequestLogger(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, inner).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status passthrough = %d", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	Healthz().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestParseRate(t *testing.T) {
	tests := []struct {
		in       string
		count    int
		window   time.Duration
		wantFail bool
	}{
		{"20/min", 20, time.Minute, false},
		{"10/s", 10, time.Second, false},
		{"1/hour", 1, time.Hour, false},
		{"5/day", 5, 24 * time.Hour, false},
		{"0/min", 0, 0, true},
		{"-1/min", 0, 0, true},
		{"20", 0, 0, true},
		{"20/fortnight", 0, 0, true},
		{"x/min", 0, 0, true},
	}
	for _, tt := range tests {
		r, err := ParseRate(tt.in)
		if tt.wantFail {
			if err == nil {
				t.Errorf("ParseRate(%q) accepted", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRate(%q): %v", tt.in, err)
			continue
		}
		if r.Count != tt.count || r.Window != tt.window {
			t.Errorf("ParseRate(%q) = %+v", tt.in, r)
		}
	}
}

func TestLimiterSlidingWindow(t *testing.T) {
	l := NewLimiter(Rate{Count: 3, Window: 100 * time.Millisecond})
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("event %d denied", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th event in window allowed")
	}
	if !l.Allow("other") {
		t.Fatal("different key denied")
	}
	time.Sleep(150 * time.Millisecond)
	if !l.Allow("k") {
		t.Fatal("event after window expiry denied")
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter(Rate{Count: 100, Window: time.Minute})
	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if l.Allow("k") {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("allowed = %d, want 100", allowed)
	}
}

func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	m.SetWhitelistSizeFunc(func() int { return 42 })
	m.SetWhitelistReloadErrorsFunc(func() int { return 3 })
	m.IncDecision("allow_anon_by_rule")
	m.IncDecision("allow_anon_by_rule")
	m.IncDecision("deny_not_whitelisted")
	m.IncUpstreamError()

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`registry_gate_decisions_total{decision="allow_anon_by_rule"} 2`,
		`registry_gate_decisions_total{decision="deny_not_whitelisted"} 1`,
		"registry_gate_upstream_errors_total 1",
		"registry_gate_whitelist_reload_errors_total 3",
		"registry_gate_whitelist_entries 42",
		"# TYPE registry_gate_decisions_total counter",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q:\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q", ct)
	}
}
