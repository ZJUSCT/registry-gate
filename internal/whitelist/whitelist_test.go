package whitelist

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func mustNew(t *testing.T, files, inline []string) *List {
	t.Helper()
	l, err := New(files, inline, WithHotReload(false))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(l.Close)
	return l
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMatchSemantics(t *testing.T) {
	l := mustNew(t, nil, []string{
		"docker.io/*",
		"docker.elastic.co/**",
		"quay.io/prometheus/node-exporter",
	})
	tests := []struct {
		name string
		line string // expected matching line ("" = no match)
	}{
		// The DaoCloud gotcha: "*" is exactly one more segment.
		{"docker.io/portainer", "docker.io/*"},
		{"docker.io/library/nginx", ""}, // remainder "library/nginx" has "/"
		{"docker.io", ""},               // no trailing segment at all
		{"docker.io/a/b", ""},
		// "**" is a recursive prefix.
		{"docker.elastic.co/kibana/kibana", "docker.elastic.co/**"},
		{"docker.elastic.co/elasticsearch/elasticsearch", "docker.elastic.co/**"},
		{"docker.elastic.co/logstash", "docker.elastic.co/**"},
		{"docker.elastic.co", ""}, // prefix requires the trailing "/"
		// Exact match only.
		{"quay.io/prometheus/node-exporter", "quay.io/prometheus/node-exporter"},
		{"quay.io/prometheus/node-exporter:latest", ""}, // never matches; also invalid input
		{"quay.io/prometheus/alertmanager", ""},
		// Case-sensitive, no substring magic.
		{"DOCKER.IO/portainer", ""},
		{"evil.com/x/docker.io/portainer", ""},
		{"", ""},
	}
	for _, tt := range tests {
		line, ok := l.Match(tt.name)
		if tt.line == "" {
			if ok {
				t.Errorf("Match(%q) = %q, want no match", tt.name, line)
			}
			continue
		}
		if !ok || line != tt.line {
			t.Errorf("Match(%q) = (%q, %v), want (%q, true)", tt.name, line, ok, tt.line)
		}
	}
}

func TestParseSkipsBlankAndComments(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "\n# comment\n   \n  # indented comment\n\nquay.io/calico/node\n\n")
	l := mustNew(t, []string{f}, nil)
	if got := l.Size(); got != 1 {
		t.Fatalf("Size = %d, want 1", got)
	}
	if _, ok := l.Match("quay.io/calico/node"); !ok {
		t.Fatal("entry not matched")
	}
}

func TestParseRejectsColon(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "docker.io/library/nginx:1.27\n")
	if _, err := New([]string{f}, nil, WithHotReload(false)); err == nil {
		t.Fatal("line with ':' accepted")
	}
	if _, err := New(nil, []string{"ok.com/x", "bad:tag"}, WithHotReload(false)); err == nil {
		t.Fatal("inline line with ':' accepted")
	}
}

func TestParseMissingFile(t *testing.T) {
	if _, err := New([]string{"/nonexistent/whitelist.txt"}, nil, WithHotReload(false)); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestMergeAndDedup(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "1.txt")
	f2 := filepath.Join(dir, "2.txt")
	writeFile(t, f1, "a.io/x\nshared.io/y\n")
	writeFile(t, f2, "shared.io/y\nb.io/**\n")
	l := mustNew(t, []string{f1, f2}, []string{"shared.io/y", "c.io/z"})
	want := 4 // a.io/x, shared.io/y, b.io/**, c.io/z
	if got := l.Size(); got != want {
		t.Fatalf("Size = %d, want %d", got, want)
	}
	for _, name := range []string{"a.io/x", "shared.io/y", "b.io/any/deep/path", "c.io/z"} {
		if _, ok := l.Match(name); !ok {
			t.Errorf("%q not matched", name)
		}
	}
}

func TestReloadKeepsOldTableOnInvalid(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "docker.io/library/nginx\n")
	l := mustNew(t, []string{f}, nil)

	// Corrupt the file; reload must fail and keep the old table.
	writeFile(t, f, "docker.io/library/nginx\nbroken:line\n")
	if err := l.Reload(); err == nil {
		t.Fatal("reload accepted invalid content")
	}
	if got := l.ReloadErrors(); got != 1 {
		t.Fatalf("ReloadErrors = %d, want 1", got)
	}
	if _, ok := l.Match("docker.io/library/nginx"); !ok {
		t.Fatal("old table not kept after failed reload")
	}

	// Fix the file; reload succeeds.
	writeFile(t, f, "docker.io/library/redis\n")
	if err := l.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := l.Match("docker.io/library/nginx"); ok {
		t.Fatal("stale entry still matches after reload")
	}
	if _, ok := l.Match("docker.io/library/redis"); !ok {
		t.Fatal("new entry not matched after reload")
	}
	if got := l.ReloadErrors(); got != 1 {
		t.Fatalf("ReloadErrors = %d, want still 1", got)
	}
}

func TestHotReloadOnSIGHUP(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "a.io/x\n")
	l, err := New([]string{f}, nil, WithHotReload(true))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	writeFile(t, f, "b.io/y\n")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := l.Match("b.io/y"); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("SIGHUP reload did not apply new entry")
}

func TestHotReloadOnFileChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "a.io/x\n")
	l, err := New([]string{f}, nil, WithHotReload(true))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	writeFile(t, f, "a.io/x\nc.io/z\n")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := l.Match("c.io/z"); ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("fsnotify did not pick up in-place file change")
}

func TestHotReloadOnAtomicRename(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "a.io/x\n")
	l, err := New([]string{f}, nil, WithHotReload(true))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Editors replace files via rename; the directory watch must catch it.
	tmp := filepath.Join(dir, ".a.txt.tmp")
	writeFile(t, tmp, "renamed.io/y\n")
	if err := os.Rename(tmp, f); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := l.Match("renamed.io/y"); ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("fsnotify did not pick up renamed file")
}

func TestConcurrentMatchAndReload(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	writeFile(t, f, "a.io/x\n")
	l := mustNew(t, []string{f}, nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					l.Match("a.io/x")
					l.Size()
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		writeFile(t, f, "a.io/x\nb.io/"+string(rune('a'+i%26))+"\n")
		if err := l.Reload(); err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestBareStarIsExact(t *testing.T) {
	// A bare "*" is not of the "host/path/*" form; per SPEC it is an exact
	// string equality entry (and therefore matches nothing useful).
	l := mustNew(t, nil, []string{"*"})
	if line, ok := l.Match("*"); !ok || line != "*" {
		t.Fatalf("Match(\"*\") = (%q, %v), want exact hit", line, ok)
	}
	if _, ok := l.Match("docker.io"); ok {
		t.Fatal("bare '*' must not act as a wildcard")
	}
}
