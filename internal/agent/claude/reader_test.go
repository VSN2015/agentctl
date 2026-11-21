package claude

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/usage"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func ts(t time.Time) string { return t.Format(time.RFC3339Nano) }

// rec builds one synthetic assistant record holding one tool_use.
func rec(at time.Time, id, name string, input map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"type": "assistant", "timestamp": ts(at),
		"message": map[string]any{"content": []any{
			map[string]any{"type": "tool_use", "id": id, "name": name, "input": input},
		}},
	})
	return string(b)
}

func bash(at time.Time, id, cmd string) string {
	return rec(at, id, "Bash", map[string]any{"command": cmd})
}

func write(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, dir string, since time.Time) usage.Usage {
	t.Helper()
	u, err := readUsage(context.Background(), dir, since, now)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestReadShellAndMCPAcrossProjects(t *testing.T) {
	dir := t.TempDir()
	t1, t2 := now.Add(-2*time.Hour), now.Add(-time.Hour)
	p := filepath.Join(dir, "projects")
	write(t, filepath.Join(p, "-a", "s1.jsonl"),
		bash(t1, "u1", "aws s3 ls --profile prod"), bash(t1, "u2", "git status"))
	write(t, filepath.Join(p, "-b", "s2", "subagents", "x.jsonl"),
		rec(t2, "u3", "mcp__fs__read_file", map[string]any{"path": "/x"}))
	u := read(t, dir, now.Add(-24*time.Hour))
	if len(u.Shell) != 1 || u.Shell[0].Tool != "aws" || u.Shell[0].Target != "prod" || !u.Shell[0].At.Equal(t1) {
		t.Errorf("Shell = %+v", u.Shell)
	}
	if len(u.MCP) != 1 || u.MCP[0].Server != "fs" || u.MCP[0].Tool != "read_file" || !u.MCP[0].At.Equal(t2) {
		t.Errorf("MCP = %+v", u.MCP)
	}
	if got := u.Calls("aws"); len(got) != 1 {
		t.Errorf("Calls(aws) = %+v", got)
	}
}

func TestReadWindowAndBoundary(t *testing.T) {
	dir := t.TempDir()
	since := now.Add(-time.Hour)
	write(t, filepath.Join(dir, "projects", "-a", "s.jsonl"),
		bash(since, "u1", "aws s3 ls --profile at"),
		bash(since.Add(-time.Nanosecond), "u2", "aws s3 ls --profile before"),
		bash(now.Add(25*time.Hour), "u3", "aws s3 ls --profile future"))
	u := read(t, dir, since)
	if len(u.Shell) != 1 || u.Shell[0].Target != "at" {
		t.Errorf("Shell = %+v", u.Shell)
	}
}

func TestReadDeduplicatesToolUseIDs(t *testing.T) {
	dir := t.TempDir()
	at := now.Add(-time.Hour)
	r := bash(at, "same", "aws s3 ls")
	write(t, filepath.Join(dir, "projects", "-a", "s1.jsonl"), r, r)
	write(t, filepath.Join(dir, "projects", "-b", "s2.jsonl"), r)
	if u := read(t, dir, now.Add(-time.Hour*2)); len(u.Shell) != 1 {
		t.Errorf("Shell = %+v, want one call", u.Shell)
	}
}

func TestReadSurvivesBadLines(t *testing.T) {
	dir := t.TempDir()
	at := now.Add(-time.Hour)
	big := `{"type":"assistant","note":"tool_use","pad":"` + strings.Repeat("x", 5<<20) + `"}`
	write(t, filepath.Join(dir, "projects", "-a", "s.jsonl"),
		bash(at, "u1", "aws s3 ls --profile one"), big, "not json tool_use", "",
		`{"type":"user","message":{"content":"tool_use text"}}`,
		bash(at, "u2", "aws s3 ls --profile two"),
		`{"type":"assistant","message":{"content":[{"type":"tool_use","id":"u3","na`)
	u := read(t, dir, now.Add(-2*time.Hour))
	if len(u.Shell) != 2 {
		t.Errorf("Shell = %+v, want 2", u.Shell)
	}
}

func TestReadHistoryStart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "projects", "-a")
	old := now.Add(-10 * 24 * time.Hour)
	write(t, filepath.Join(p, "old.jsonl"), bash(old, "u1", "aws s3 ls"))
	write(t, filepath.Join(p, "new.jsonl"), bash(now.Add(-time.Hour), "u2", "aws s3 ls"))
	// stale file: mtime before the window, so not parsed for calls
	ancient := now.Add(-40 * 24 * time.Hour)
	write(t, filepath.Join(p, "ancient.jsonl"), bash(ancient, "u3", "aws s3 ls --profile stale"))
	if err := os.Chtimes(filepath.Join(p, "ancient.jsonl"), ancient, ancient); err != nil {
		t.Fatal(err)
	}
	since := now.Add(-30 * 24 * time.Hour)
	u := read(t, dir, since)
	if !u.HistoryStart.Equal(ancient) {
		t.Errorf("HistoryStart = %v, want %v", u.HistoryStart, ancient)
	}
	if len(u.Shell) != 2 {
		t.Errorf("Shell = %+v, want 2 (stale file not parsed)", u.Shell)
	}
	if got := u.HistoryDays(now); got != 40 {
		t.Errorf("HistoryDays = %d, want 40", got)
	}
	// without the ancient file the oldest record is 10 days back
	os.Remove(filepath.Join(p, "ancient.jsonl"))
	if got := read(t, dir, since).HistoryDays(now); got != 10 {
		t.Errorf("HistoryDays = %d, want 10", got)
	}
}

func TestReadMissingOrEmptyDir(t *testing.T) {
	base := t.TempDir()
	check := func(name, dir string) {
		u, err := readUsage(context.Background(), dir, now.Add(-time.Hour), now)
		if err != nil || !u.HistoryStart.IsZero() || u.HistoryDays(now) != 0 || len(u.Shell)+len(u.MCP) != 0 {
			t.Errorf("%s: u=%+v err=%v", name, u, err)
		}
	}
	check("absent", filepath.Join(base, "nope"))
	check("no projects", base)
	os.Mkdir(filepath.Join(base, "projects"), 0o755)
	check("empty projects", base)
	locked := filepath.Join(base, "projects", "-locked")
	os.Mkdir(locked, 0o755)
	os.Chmod(locked, 0)
	defer os.Chmod(locked, 0o755)
	check("unreadable project", base)
}

func TestReadNeverRetainsCommandText(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "projects", "-a", "s.jsonl"),
		bash(now.Add(-time.Minute), "u1", "echo CANARY-SECRET-DO-NOT-PRINT; aws s3 ls"))
	u := read(t, dir, now.Add(-time.Hour))
	if len(u.Shell) == 0 {
		t.Fatal("expected an aws call")
	}
	if s := fmt.Sprintf("%+v", u); strings.Contains(s, "CANARY") {
		t.Errorf("command text retained: %s", s)
	}
}

func TestReadStopsOnCancelledContext(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "projects", "-a", "s.jsonl"), bash(now, "u1", "aws s3 ls"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readUsage(ctx, dir, now.Add(-time.Hour), now); err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// denied makes path unreadable, skipping the test where that has no effect (root).
func denied(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o755) })
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("permissions not enforced (running as root?)")
	} else if _, err := os.ReadDir(path); err == nil {
		t.Skip("permissions not enforced (running as root?)")
	}
}

func TestReadCountsUnreadableDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "projects")
	write(t, filepath.Join(p, "-ok", "s.jsonl"), bash(now.Add(-time.Minute), "u1", "aws s3 ls --profile prod"))
	locked := filepath.Join(p, "-locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	denied(t, locked)
	u := read(t, dir, now.Add(-time.Hour))
	if u.Unread != 1 || len(u.Calls("aws")) != 1 {
		t.Errorf("Unread=%d Shell=%+v, want 1 and one call", u.Unread, u.Shell)
	}
}

func TestReadCountsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "projects", "-a")
	write(t, filepath.Join(p, "ok.jsonl"), bash(now.Add(-time.Minute), "u1", "aws s3 ls"))
	write(t, filepath.Join(p, "bad.jsonl"), bash(now.Add(-time.Minute), "u2", "aws s3 ls --profile prod"))
	if err := os.Chmod(filepath.Join(p, "bad.jsonl"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(p, "bad.jsonl")); err == nil {
		t.Skip("permissions not enforced (running as root?)")
	}
	u := read(t, dir, now.Add(-time.Hour))
	if u.Unread != 1 || len(u.Calls("aws")) != 1 {
		t.Errorf("Unread=%d Shell=%+v, want 1 and one call", u.Unread, u.Shell)
	}
}

func TestReadCleanTreeHasNoUnread(t *testing.T) {
	dir := t.TempDir()
	if u := read(t, dir, now.Add(-time.Hour)); u.Unread != 0 {
		t.Errorf("missing root: Unread=%d", u.Unread)
	}
	write(t, filepath.Join(dir, "projects", "-a", "s.jsonl"), bash(now.Add(-time.Minute), "u1", "aws s3 ls"), "garbage tool_use")
	if u := read(t, dir, now.Add(-time.Hour)); u.Unread != 0 {
		t.Errorf("clean tree: Unread=%d", u.Unread)
	}
}
