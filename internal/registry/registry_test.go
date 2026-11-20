package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/scan"
)

func TestRegistryEveryScannerHasToolRule(t *testing.T) {
	scanners := map[string]bool{}
	for _, s := range Scanners(scan.ExecRunner{}) {
		if scanners[s.Name()] {
			t.Errorf("duplicate scanner %q", s.Name())
		}
		scanners[s.Name()] = true
	}
	ruleTools := map[string]bool{}
	for _, r := range ToolRules() {
		if ruleTools[r.Tool()] {
			t.Errorf("duplicate rule %q", r.Tool())
		}
		ruleTools[r.Tool()] = true
	}
	if len(scanners) == 0 || len(scanners) != len(ruleTools) {
		t.Fatalf("scanners %v, rules %v", scanners, ruleTools)
	}
	for n := range scanners {
		if !ruleTools[n] {
			t.Errorf("scanner %q has no tool rule", n)
		}
	}
}

func TestRegistryAgents(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfgdir")
	proj := filepath.Join(cfg, "projects", "p")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"timestamp":"2026-01-02T03:04:05Z","message":{"content":[]}}` + "\n"
	if err := os.WriteFile(filepath.Join(proj, "s.jsonl"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	read := func(env map[string]string) bool {
		as := Agents(AgentParams{Getenv: func(k string) string { return env[k] }, Home: filepath.Join(dir, "home"), Cwd: dir, GOOS: "linux"})
		if len(as) != 1 || as[0].Name() != "claude-code" {
			t.Fatalf("agents = %v", as)
		}
		u, err := as[0].ReadUsage(context.Background(), now.Add(-time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
		return !u.HistoryStart.IsZero()
	}
	if read(nil) {
		t.Error("default config dir should be <home>/.claude, which is empty")
	}
	if !read(map[string]string{"CLAUDE_CONFIG_DIR": cfg}) {
		t.Error("CLAUDE_CONFIG_DIR not honoured")
	}
}
