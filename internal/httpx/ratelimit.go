package httpx

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rate is a rate limit such as "20/min": Count events per Window.
type Rate struct {
	Count  int
	Window time.Duration
}

// ParseRate parses strings like "20/min", "10/s", "100/hour", "5/day".
// Units: s(ec), m(in), h(our), d(ay).
func ParseRate(s string) (Rate, error) {
	countStr, unit, ok := strings.Cut(s, "/")
	if !ok {
		return Rate{}, fmt.Errorf("httpx: bad rate %q: want \"<count>/<unit>\" e.g. \"20/min\"", s)
	}
	count, err := strconv.Atoi(strings.TrimSpace(countStr))
	if err != nil || count <= 0 {
		return Rate{}, fmt.Errorf("httpx: bad rate count in %q", s)
	}
	var window time.Duration
	switch strings.TrimSpace(unit) {
	case "s", "sec", "second":
		window = time.Second
	case "m", "min", "minute":
		window = time.Minute
	case "h", "hour":
		window = time.Hour
	case "d", "day":
		window = 24 * time.Hour
	default:
		return Rate{}, fmt.Errorf("httpx: bad rate unit %q in %q", unit, s)
	}
	return Rate{Count: count, Window: window}, nil
}

func (r Rate) String() string {
	return fmt.Sprintf("%d/%s", r.Count, r.Window)
}

// Limiter is an in-memory per-key sliding-window rate limiter. It is safe
// for concurrent use and has no external dependencies.
type Limiter struct {
	mu     sync.Mutex
	rate   Rate
	events map[string][]time.Time
	// lastSweep amortizes garbage collection of empty buckets.
	lastSweep time.Time
}

// NewLimiter returns a limiter enforcing rate per key. A zero Count admits
// nothing; callers should pass a sane Rate.
func NewLimiter(rate Rate) *Limiter {
	return &Limiter{
		rate:      rate,
		events:    map[string][]time.Time{},
		lastSweep: time.Now(),
	}
}

// Allow records one event for key and reports whether it is within the
// limit. Events older than the window are forgotten.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.rate.Window)

	l.mu.Lock()
	defer l.mu.Unlock()

	ev := l.prune(l.events[key], cutoff)
	if len(ev) >= l.rate.Count {
		l.events[key] = ev
		return false
	}
	l.events[key] = append(ev, now)

	if now.Sub(l.lastSweep) > l.rate.Window {
		for k, v := range l.events {
			if kept := l.prune(v, cutoff); len(kept) == 0 {
				delete(l.events, k)
			} else {
				l.events[k] = kept
			}
		}
		l.lastSweep = now
	}
	return true
}

// prune drops timestamps not after cutoff. It keeps slice capacity; the
// sweep in Allow deletes fully-expired keys to bound memory.
func (l *Limiter) prune(ev []time.Time, cutoff time.Time) []time.Time {
	for len(ev) > 0 && !ev[0].After(cutoff) {
		ev = ev[1:]
	}
	return ev
}
