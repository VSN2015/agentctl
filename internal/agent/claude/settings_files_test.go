package claude

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within fails the test if f does not return in time; a blocked reader is left behind.
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not return")
	}
}

func TestLoadRefusesFIFOAndDirectoryAndOversizeSettings(t *testing.T) {
	proj := t.TempDir()
	cfg := t.TempDir()
	fifo := filepath.Join(proj, ".claude", "settings.json")
	put(t, filepath.Join(proj, ".claude", "keep"), "")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	put(t, filepath.Join(proj, ".claude", "settings.local.json"), strings.Repeat(" ", 1<<20)+`{"permissions":{"allow":["Bash"]}}`)
	if err := mkdir(filepath.Join(cfg, "settings.json")); err != nil {
		t.Fatal(err)
	}
	var s Settings
	within(t, func() { s = Load(cfg, proj, nil) })
	if len(s.Sources) != 0 || len(s.Allow) != 0 || len(s.Notes) != 3 {
		t.Fatalf("%+v", s)
	}
	for _, n := range s.Notes {
		if !strings.HasPrefix(n, "settings file unreadable or invalid, skipped: ") {
			t.Errorf("note %q", n)
		}
	}
}

func mkdir(p string) error { return os.MkdirAll(p, 0o755) }
