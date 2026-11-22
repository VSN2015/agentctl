package run_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/agent"
	"github.com/VSN2015/agentctl/internal/agent/claude"
	"github.com/VSN2015/agentctl/internal/confirm"
	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/registry"
	"github.com/VSN2015/agentctl/internal/run"
	"github.com/VSN2015/agentctl/internal/scan"
)

// runLocal runs the real registry over dir with every config path inside dir and DOCKER_HOST
// pointing at a missing socket, so it never reads this machine's state. extraEnv overrides.
func runLocal(t *testing.T, dir string, extraEnv map[string]string, o run.Options) (code int, out, errb string) {
	t.Helper()
	env := map[string]string{"HOME": dir, "CLAUDE_CONFIG_DIR": filepath.Join(dir, ".claude"),
		"AWS_CONFIG_FILE": filepath.Join(dir, "a"), "AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "b"),
		"GH_CONFIG_DIR": dir, "XDG_CONFIG_HOME": dir, "HISTFILE": filepath.Join(dir, "h"), "ZDOTDIR": dir,
		"KUBECONFIG": filepath.Join(dir, "kube"), "DOCKER_HOST": "unix://" + filepath.Join(dir, "missing.sock")}
	for k, v := range extraEnv {
		env[k] = v
	}
	getenv := func(k string) string { return env[k] }
	var ob, eb bytes.Buffer
	d := run.Deps{
		Scanners: registry.Scanners(scan.ExecRunner{}),
		Rules:    registry.ToolRules(),
		Agents:   []agent.Agent{claude.New(filepath.Join(dir, ".claude"), dir, dir, "")},
		Dev:      func() devuse.History { return devuse.Read(dir, getenv) },
		Env:      scan.Env{Home: dir, SysRoot: dir, Getenv: getenv},
		Now:      time.Now,
		Confirm: func(p []string) (bool, error) {
			return confirm.Online(strings.NewReader(""), &eb, false, o.Offline, o.Yes, p)
		},
		Out: &ob, Err: &eb,
	}
	return run.Execute(context.Background(), o, d), ob.String(), eb.String()
}

func dockerSocket(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ac")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	p := filepath.Join(d, "d.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return p
}

func TestE2EDockerSocketIsHigh(t *testing.T) {
	sock := dockerSocket(t)
	env := map[string]string{"DOCKER_HOST": "unix://" + sock}
	o := run.Options{Command: "doctor", Offline: true, Since: 720 * time.Hour}
	code, out, _ := runLocal(t, t.TempDir(), env, o)
	if code != 1 || !strings.Contains(out, "Docker") || !strings.Contains(out, "socket reachable") {
		t.Errorf("exit %d out %q", code, out)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(`{"permissions":{"deny":["Bash(docker:*)"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	o.JSON = true
	code, out, _ = runLocal(t, dir, env, o)
	var doc struct {
		Findings []struct{ Tool, Access string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 {
		t.Fatalf("exit %d err %v out %q", code, err, out)
	}
	found := false
	for _, f := range doc.Findings {
		if f.Tool == "docker" {
			found = true
			if f.Access != "denied" {
				t.Errorf("access %q", f.Access)
			}
		}
	}
	if !found {
		t.Errorf("no docker finding: %q", out)
	}
}

func TestE2ELocalOnlyNeedsNoPrompt(t *testing.T) {
	env := map[string]string{"DOCKER_HOST": "unix://" + dockerSocket(t)}
	code, out, errb := runLocal(t, t.TempDir(), env, run.Options{Command: "doctor", Since: 720 * time.Hour})
	if code != 1 || strings.Contains(errb, "--yes") || out == "" {
		t.Errorf("exit %d out %q err %q", code, out, errb)
	}
}

func TestE2EDockerNotFoundWhenHostMissing(t *testing.T) {
	code, out, _ := runLocal(t, t.TempDir(), nil, run.Options{Command: "doctor", Offline: true, JSON: true, Since: 720 * time.Hour})
	var doc struct {
		Credentials []struct{ Tool string } `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 {
		t.Fatalf("exit %d err %v out %q", code, err, out)
	}
	for _, c := range doc.Credentials {
		if c.Tool == "docker" {
			t.Errorf("docker found: %+v", c)
		}
	}
}

func TestE2EKubectlProductionContext(t *testing.T) {
	const canary = "KUBE-TOKEN-CANARY-9f3a"
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".kube", "config")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: dev\n" +
		"contexts:\n- name: dev\n  context: {cluster: c-dev, user: u}\n- name: production\n  context: {cluster: c-prod, user: u}\n" +
		"clusters:\n- name: c-dev\n  cluster: {server: https://dev.invalid}\n- name: c-prod\n  cluster: {server: https://prod.invalid}\n" +
		"users:\n- name: u\n  user: {token: " + canary + "}\n"
	if err := os.WriteFile(cfg, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-40 * 24 * time.Hour)
	line := func(ts time.Time, cmd string) string {
		b, _ := json.Marshal(map[string]any{"type": "assistant", "timestamp": ts.Format(time.RFC3339Nano),
			"message": map[string]any{"content": []any{map[string]any{"type": "tool_use", "id": "u" + cmd, "name": "Bash",
				"input": map[string]any{"command": cmd}}}}})
		return string(b)
	}
	session := filepath.Join(dir, ".claude", "projects", "-p", "s.jsonl")
	if err := os.MkdirAll(filepath.Dir(session), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(lines ...string) {
		if err := os.WriteFile(session, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type finding struct {
		ID      string
		Rules   []string
		Details []string
	}
	doctor := func() map[string]finding {
		o := run.Options{Command: "doctor", Offline: true, JSON: true, Since: 720 * time.Hour}
		code, out, _ := runLocal(t, dir, map[string]string{"KUBECONFIG": cfg}, o)
		if code != 0 || strings.Contains(out, canary) {
			t.Fatalf("exit %d out %q", code, out)
		}
		var doc struct{ Findings []finding }
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		m := map[string]finding{}
		for _, f := range doc.Findings {
			m[f.ID] = f
		}
		return m
	}
	has := func(ss []string, s string) bool {
		for _, x := range ss {
			if strings.Contains(x, s) {
				return true
			}
		}
		return false
	}

	write(line(at, "ls"))
	m := doctor()
	if f := m["claude-code:kubectl:production"]; !has(f.Rules, "kubectl.production-context") {
		t.Errorf("production: %+v", f)
	}
	if f := m["claude-code:kubectl:dev"]; !has(f.Rules, "usage.unused") {
		t.Errorf("dev: %+v", f)
	}

	write(line(at, "ls"), line(time.Now().Add(-time.Hour), "kubectl get pods"))
	f := doctor()["claude-code:kubectl:dev"]
	if !has(f.Details, "Agent ran kubectl 1 time without naming a context") || has(f.Rules, "usage.unused") {
		t.Errorf("dev unnamed: %+v", f)
	}
}

func TestE2EMCPServers(t *testing.T) {
	const canary = "MCP-ENV-CANARY-4c1d"
	dir := t.TempDir()
	cl := filepath.Join(dir, ".claude")
	session := filepath.Join(cl, "projects", "-p", "s.jsonl")
	if err := os.MkdirAll(filepath.Dir(session), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"mcpServers":{"filesystem":{"command":"npx","args":["-y","fs"]},` +
		`"idle":{"command":"idle-mcp","env":{"TOKEN":"` + canary + `"}},"blocked":{"command":"blocked-mcp"}}}`
	for p, body := range map[string]string{
		filepath.Join(cl, ".claude.json"):  cfg,
		filepath.Join(cl, "settings.json"): `{"permissions":{"deny":["mcp__blocked"]}}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := func(ts time.Time, id string) string {
		b, _ := json.Marshal(map[string]any{"type": "assistant", "timestamp": ts.Format(time.RFC3339Nano),
			"message": map[string]any{"content": []any{map[string]any{"type": "tool_use", "id": id,
				"name": "mcp__filesystem__read_file", "input": map[string]any{}}}}})
		return string(b)
	}
	write := func(first time.Time) {
		now := time.Now()
		lines := []string{rec(first, "m0"), rec(now.Add(-3*time.Hour), "m1"), rec(now.Add(-2*time.Hour), "m2"), rec(now.Add(-time.Hour), "m3")}
		if err := os.WriteFile(session, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type finding struct {
		ID, Severity, Access, Used string
		Rules, Advice              []string
	}
	doctor := func() map[string]finding {
		o := run.Options{Command: "doctor", Offline: true, JSON: true, Since: 720 * time.Hour}
		code, out, errb := runLocal(t, dir, nil, o)
		if code != 0 || strings.Contains(out+errb, canary) {
			t.Fatalf("exit %d out %q err %q", code, out, errb)
		}
		var doc struct{ Findings []finding }
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		m := map[string]finding{}
		for _, f := range doc.Findings {
			m[f.ID] = f
		}
		return m
	}

	write(time.Now().Add(-40 * 24 * time.Hour))
	m := doctor()
	if f := m["claude-code:mcp:filesystem"]; f.Severity != "OK" || f.Used != "3" {
		t.Errorf("filesystem: %+v", f)
	}
	f := m["claude-code:mcp:idle"]
	if len(f.Rules) != 1 || f.Rules[0] != "usage.unused" || !strings.Contains(strings.Join(f.Advice, "\n"), `deny "mcp__idle" in ~/.claude/settings.json`) {
		t.Errorf("idle: %+v", f)
	}
	if f := m["claude-code:mcp:blocked"]; f.Access != "denied" {
		t.Errorf("blocked: %+v", f)
	}
	mcpGroup := regexp.MustCompile(`(?m)^MCP$\n(?:  .*\n)*?  filesystem - stdio$`)
	code, out, errb := runLocal(t, dir, nil, run.Options{Command: "inventory", Offline: true, Since: 720 * time.Hour})
	if code != 0 || !mcpGroup.MatchString(out) || strings.Contains(out+errb, canary) {
		t.Errorf("inventory exit %d out %q err %q", code, out, errb)
	}
	// the matcher must not be satisfied by a path that merely contains the test name
	if mcpGroup.MatchString("Note: /tmp/TestE2EMCPServers/x\nNo credentials found.\n") {
		t.Error("MCP group matcher accepts output without an MCP group")
	}
	code, text, errb := runLocal(t, dir, nil, run.Options{Command: "doctor", Offline: true, Since: 720 * time.Hour})
	if code != 0 || strings.Contains(text+errb, canary) {
		t.Errorf("doctor text exit %d out %q err %q", code, text, errb)
	}
	t.Logf("doctor text:\n%s", text)

	write(time.Now().Add(-5 * 24 * time.Hour))
	if f := doctor()["claude-code:mcp:idle"]; f.Used != "0?" {
		t.Errorf("short history idle: %+v", f)
	}
}
