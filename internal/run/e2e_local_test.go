package run_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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
