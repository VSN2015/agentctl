package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/run"
)

func emptyHomeIO(t *testing.T) (IO, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	env := map[string]string{"HOME": dir, "CLAUDE_CONFIG_DIR": dir, "AWS_CONFIG_FILE": filepath.Join(dir, "a"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "b"), "GH_CONFIG_DIR": dir, "XDG_CONFIG_HOME": dir,
		"HISTFILE": filepath.Join(dir, "h"), "ZDOTDIR": dir}
	io, out, errb := newIO()
	io.Getenv = func(k string) string { return env[k] }
	io.Home, io.Cwd = dir, dir
	return io, out, errb
}

func TestDefaultExecEmptyHomeOffline(t *testing.T) {
	for _, cmd := range []string{"doctor", "inventory"} {
		io, out, errb := emptyHomeIO(t)
		got := defaultExec(context.Background(), run.Options{Command: cmd, Offline: true, Since: 720 * 3600e9}, io)
		if got != 0 || !strings.Contains(out.String(), "No credentials found.") || errb.Len() != 0 {
			t.Errorf("%s: exit %d out %q err %q", cmd, got, out, errb)
		}
	}
	io, out, _ := emptyHomeIO(t)
	if got := defaultExec(context.Background(), run.Options{Command: "doctor", Offline: true, JSON: true, Since: 720 * 3600e9}, io); got != 0 {
		t.Fatalf("json exit %d", got)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.SchemaVersion != 1 {
		t.Errorf("json %v %q", err, out)
	}
}

func TestDefaultExecNoTerminalWithoutFlagsExit2(t *testing.T) {
	io, out, errb := emptyHomeIO(t)
	// a credential from the environment makes a provider present, so the prompt would be needed
	base := io.Getenv
	io.Getenv = func(k string) string {
		if k == "AWS_ACCESS_KEY_ID" {
			return "AKIAEXAMPLEEXAMPLE1"
		}
		if k == "AWS_SECRET_ACCESS_KEY" {
			return "canary-not-a-secret"
		}
		return base(k)
	}
	got := defaultExec(context.Background(), run.Options{Command: "inventory", Since: 720 * 3600e9}, io)
	if got != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "--yes") || strings.Contains(errb.String(), "canary") {
		t.Errorf("exit %d out %q err %q", got, out, errb)
	}
}

func TestBuildDepsEmptyHomeReadsNothingFromCwd(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".zsh_history"), []byte(": 1700000000:0;aws s3 ls\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	io, _, _ := newIO()
	io.Cwd = cwd
	d := buildDeps(context.Background(), run.Options{Command: "doctor"}, io)
	if len(d.Agents) != 0 || len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "home directory") {
		t.Errorf("agents %d notes %v", len(d.Agents), d.Notes)
	}
	if h := d.Dev(); h.Unread != 0 {
		t.Errorf("history = %+v", h)
	}
	if _, ok := d.Dev().Lookup("aws", ""); ok {
		t.Error("history read from the current directory")
	}
}

// a blocked read left behind at process exit is acceptable; the caller must not wait for it
func TestCancellableConfirmReturnsPromptlyOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	block := make(chan struct{})
	defer close(block)
	done := make(chan error, 1)
	go func() {
		_, err := cancellable(ctx, func() (bool, error) { <-block; return true, nil })
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirm did not return after cancel")
	}
	if ok, err := cancellable(context.Background(), func() (bool, error) { return true, nil }); !ok || err != nil {
		t.Errorf("normal answer: %v %v", ok, err)
	}
}

func TestBuildDepsConfirmIsCancellable(t *testing.T) {
	cio, _, _ := emptyHomeIO(t)
	pr, pw := io.Pipe() // a terminal that never answers
	defer pw.Close()
	cio.In, cio.InIsTTY = pr, true
	ctx, cancel := context.WithCancel(context.Background())
	d := buildDeps(ctx, run.Options{Command: "inventory"}, cio)
	done := make(chan error, 1)
	go func() { _, err := d.Confirm([]string{"AWS"}); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Confirm did not return after cancel")
	}
}

func TestBuildDepsProgressOnlyOnNonDumbErrTerminal(t *testing.T) {
	for _, c := range []struct {
		tty  bool
		term string
		want bool
	}{{true, "xterm", true}, {true, "dumb", false}, {false, "xterm", false}} {
		io, _, _ := newIO()
		io.ErrIsTTY = c.tty
		io.Getenv = func(k string) string {
			if k == "TERM" {
				return c.term
			}
			return ""
		}
		if d := buildDeps(context.Background(), run.Options{Command: "doctor"}, io); (d.Progress != nil) != c.want {
			t.Errorf("tty %v term %q: progress set %v", c.tty, c.term, d.Progress != nil)
		}
	}
}
