package claude

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
)

func TestAgentName(t *testing.T) {
	if got := New(t.TempDir(), t.TempDir(), "/h", "test").Name(); got != "claude-code" {
		t.Errorf("Name = %q", got)
	}
}

func TestAgentClassifyStampsAgentName(t *testing.T) {
	cfg := t.TempDir()
	put(t, filepath.Join(cfg, "settings.json"), perms([]string{"Bash(aws:*)"}, nil, []string{"Read(~/.aws/**)"}, ""))
	c := awsCred("/h/.aws/credentials")
	want, blocked := Load(cfg, t.TempDir(), nil).Classify(c, "/h")
	got := New(cfg, t.TempDir(), "/h", "test").Classify(c)
	if got != (model.AgentState{Agent: "claude-code", Access: want, FileBlocked: blocked}) || want != model.AccessAllowed || !blocked {
		t.Errorf("got %+v", got)
	}
}

func TestAgentReadUsageUsesConfigDir(t *testing.T) {
	cfg := t.TempDir()
	at := now.Add(-time.Hour)
	write(t, filepath.Join(cfg, "projects", "p", "s.jsonl"), bash(at, "t1", "aws s3 ls"))
	u, err := New(cfg, t.TempDir(), "/h", "test").ReadUsage(context.Background(), now.Add(-24*time.Hour), now)
	if err != nil || u.Agent != "claude-code" || len(u.Shell) != 1 || u.Unread != 0 {
		t.Errorf("u=%+v err=%v", u, err)
	}
	u, err = New(filepath.Join(cfg, "nope"), t.TempDir(), "/h", "test").ReadUsage(context.Background(), now.Add(-24*time.Hour), now)
	if err != nil || len(u.Shell) != 0 || len(u.MCP) != 0 || u.Unread != 0 || !u.HistoryStart.IsZero() {
		t.Errorf("missing dir: u=%+v err=%v", u, err)
	}
}

func TestAgentBlockAdvice(t *testing.T) {
	a := New(t.TempDir(), t.TempDir(), "/h", "test")
	if got, want := a.BlockAdvice("aws"), `deny "Bash(aws:*)" in ~/.claude/settings.json`; got != want {
		t.Errorf("got %q", got)
	}
	if got := a.BlockAdvice("gh"); !strings.Contains(got, `"Bash(gh:*)"`) {
		t.Errorf("got %q", got)
	}
}

func TestAgentPosture(t *testing.T) {
	cfg, proj := t.TempDir(), t.TempDir()
	put(t, filepath.Join(cfg, "settings.json"), perms([]string{"Bash"}, nil, nil, ""))
	bad := put(t, filepath.Join(proj, ".claude", "settings.json"), `{CANARY`)
	p := New(cfg, proj, "/h", "test").Posture()
	if !p.UnrestrictedShell || len(p.Notes) != 1 || !strings.Contains(p.Notes[0], bad) || strings.Contains(p.Notes[0], "CANARY") {
		t.Errorf("posture = %+v", p)
	}
}
