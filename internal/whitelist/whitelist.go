// Package whitelist loads, matches and hot-reloads the anonymous pull
// whitelist.
//
// The file format is the DaoCloud "allows" list: one image reference per
// line, with the following semantics (identical to DaoCloud
// hack/verify-allows.sh):
//
//	host/path/**   recursive prefix match (remainder may contain "/")
//	host/path/*    prefix match where the remainder contains no "/"
//	host/path      exact string equality
//
// Blank lines and lines starting with "#" are ignored. A line containing
// ":" is a validation error (whitelist entries never carry tags). Note the
// deliberate gotcha: "docker.io/*" does NOT match "docker.io/library/nginx"
// because the remainder "library/nginx" contains a "/".
package whitelist

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

// rule is one compiled wildcard entry. prefix always ends in "/".
type rule struct {
	prefix    string
	recursive bool
	line      string
}

// table is an immutable compiled whitelist.
type table struct {
	exact map[string]string
	rules []rule
	lines []string // deduplicated, in insertion order
}

// List is a concurrency-safe whitelist with optional hot reload.
// Create with New. The zero value is not usable.
type List struct {
	files  []string
	inline []string

	mu  sync.RWMutex
	tab *table

	reloadErrs atomic.Int64

	logger    *slog.Logger
	hotReload bool

	watcher  *fsnotify.Watcher
	stop     chan struct{}
	stopOnce sync.Once
	sighup   chan os.Signal
}

// Option configures a List.
type Option func(*List)

// WithLogger sets the logger used for reload events (default slog.Default).
func WithLogger(l *slog.Logger) Option {
	return func(li *List) {
		if l != nil {
			li.logger = l
		}
	}
}

// WithHotReload enables or disables background reloading (fsnotify file
// watching plus SIGHUP). Default enabled.
func WithHotReload(on bool) Option {
	return func(li *List) { li.hotReload = on }
}

// New parses files (in order) plus inline entries into one deduplicated
// whitelist. All sources must be valid, otherwise New fails. When hot
// reload is enabled a background goroutine reloads on file change and on
// SIGHUP; call Close to stop it.
func New(files, inline []string, opts ...Option) (*List, error) {
	l := &List{
		files:     append([]string(nil), files...),
		inline:    append([]string(nil), inline...),
		logger:    slog.Default(),
		hotReload: true,
		stop:      make(chan struct{}),
	}
	for _, o := range opts {
		o(l)
	}
	tab, err := parseAll(files, inline, os.ReadFile)
	if err != nil {
		return nil, err
	}
	l.tab = tab
	l.logger.Info("whitelist loaded", "entries", len(tab.lines), "files", len(files), "inline", len(inline))
	if l.hotReload {
		l.startWatcher()
		l.sighup = make(chan os.Signal, 1)
		signal.Notify(l.sighup, syscall.SIGHUP)
		go l.sighupLoop()
	}
	return l, nil
}

// Match reports whether name is whitelisted and returns the matching line.
func (l *List) Match(name string) (line string, ok bool) {
	if name == "" {
		return "", false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if line, ok := l.tab.exact[name]; ok {
		return line, true
	}
	for _, r := range l.tab.rules {
		if !strings.HasPrefix(name, r.prefix) {
			continue
		}
		if r.recursive || !strings.Contains(name[len(r.prefix):], "/") {
			return r.line, true
		}
	}
	return "", false
}

// Size returns the number of distinct whitelist entries.
func (l *List) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.tab.lines)
}

// ReloadErrors returns the number of failed reload attempts since startup.
func (l *List) ReloadErrors() int { return int(l.reloadErrs.Load()) }

// Reload re-reads all sources. If any source is invalid the previous table
// is kept, the error is logged, the reload-error counter incremented and
// the error returned.
func (l *List) Reload() error {
	tab, err := parseAll(l.files, l.inline, os.ReadFile)
	if err != nil {
		l.reloadErrs.Add(1)
		l.logger.Error("whitelist reload failed, keeping previous table", "error", err)
		return err
	}
	l.mu.Lock()
	l.tab = tab
	l.mu.Unlock()
	l.logger.Info("whitelist reloaded", "entries", len(tab.lines))
	return nil
}

// Close stops background reloading. The List stays usable for matching.
func (l *List) Close() {
	l.stopOnce.Do(func() {
		close(l.stop)
		if l.watcher != nil {
			_ = l.watcher.Close()
		}
		if l.sighup != nil {
			signal.Stop(l.sighup)
		}
	})
}

// startWatcher watches the directories containing the whitelist files
// (directory watches survive the atomic rename editors use) and reloads
// whenever one of the files changes. Watch setup failures are logged, not
// fatal: SIGHUP-triggered reload keeps working.
func (l *List) startWatcher() {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		l.logger.Error("whitelist: fsnotify unavailable, falling back to SIGHUP-only reload", "error", err)
		return
	}
	dirs := map[string]bool{}
	for _, f := range l.files {
		dirs[dirOf(f)] = true
	}
	for dir := range dirs {
		if err := w.Add(dir); err != nil {
			l.logger.Error("whitelist: cannot watch directory, SIGHUP reload still available", "dir", dir, "error", err)
		}
	}
	l.watcher = w
	go l.watchLoop()
}

func (l *List) watchLoop() {
	for {
		select {
		case <-l.stop:
			return
		case ev, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			if l.isWatchedFile(ev.Name) {
				_ = l.Reload()
			}
		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			l.logger.Error("whitelist: watch error", "error", err)
		}
	}
}

func (l *List) isWatchedFile(name string) bool {
	for _, f := range l.files {
		if f == name {
			return true
		}
	}
	return false
}

func (l *List) sighupLoop() {
	for {
		select {
		case <-l.stop:
			return
		case <-l.sighup:
			// Already logged and counted in Reload on failure.
			_ = l.Reload()
		}
	}
}

// dirOf returns the directory part of a path ("." for bare names).
func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if i == 0 {
			return "/"
		}
		return path[:i]
	}
	return "."
}

// parseAll merges all sources (files first, then inline) into one
// deduplicated table. Any invalid line aborts the whole parse.
func parseAll(files, inline []string, readFile func(string) ([]byte, error)) (*table, error) {
	tab := &table{exact: map[string]string{}}
	seen := map[string]bool{}
	add := func(line, origin string, no int) error {
		if line == "" || strings.HasPrefix(line, "#") {
			return nil
		}
		if strings.Contains(line, ":") {
			return fmt.Errorf("%s:%d: line %q contains ':' (tags are not allowed)", origin, no, line)
		}
		if seen[line] {
			return nil
		}
		seen[line] = true
		switch {
		case strings.HasSuffix(line, "/**"):
			prefix := strings.TrimSuffix(line, "**") // "host/path/"
			if !strings.HasSuffix(prefix, "/") {
				return fmt.Errorf("%s:%d: line %q: '/' expected before '**'", origin, no, line)
			}
			tab.rules = append(tab.rules, rule{prefix: prefix, recursive: true, line: line})
		case strings.HasSuffix(line, "/*"):
			prefix := strings.TrimSuffix(line, "*") // "host/path/"
			if !strings.HasSuffix(prefix, "/") {
				return fmt.Errorf("%s:%d: line %q: '/' expected before '*'", origin, no, line)
			}
			tab.rules = append(tab.rules, rule{prefix: prefix, recursive: false, line: line})
		default:
			tab.exact[line] = line
		}
		tab.lines = append(tab.lines, line)
		return nil
	}
	for _, f := range files {
		data, err := readFile(f)
		if err != nil {
			return nil, fmt.Errorf("whitelist: read %s: %w", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if err := add(strings.TrimSpace(line), f, i+1); err != nil {
				return nil, err
			}
		}
	}
	for i, line := range inline {
		if err := add(strings.TrimSpace(line), "<inline>", i+1); err != nil {
			return nil, err
		}
	}
	return tab, nil
}
