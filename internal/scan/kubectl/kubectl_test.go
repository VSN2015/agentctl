package kubectl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scanner(t *testing.T) *Scanner {
	s := New()
	s.saToken = filepath.Join(t.TempDir(), "none")
	return s
}

func env(home string, vars map[string]string) scan.Env {
	return scan.Env{Home: home, Getenv: func(k string) string { return vars[k] }}
}

func cfg(pairs ...string) string {
	var b strings.Builder
	b.WriteString("contexts:\n")
	for i := 0; i < len(pairs); i += 2 {
		b.WriteString("- name: \"" + pairs[i] + "\"\n  context:\n    cluster: \"" + pairs[i+1] + "\"\n")
	}
	return b.String()
}

func TestIsProd(t *testing.T) {
	for s, want := range map[string]bool{
		"prod": true, "production": true, "Prod-eu": true, "prod-cluster": true, "product-x": true,
		"nonprod": false, "non-prod": false, "NON_PRODUCTION": false, "dev": false, "": false,
		"nonprod-to-prod": true,
	} {
		if got := isProd(s); got != want {
			t.Errorf("isProd(%q)=%v want %v", s, got, want)
		}
	}
}

func TestDiscoverContexts(t *testing.T) {
	home := t.TempDir()
	p := write(t, home, ".kube/config", cfg("dev", "dev-1", "production", "c1", "Prod-eu", "c2",
		"staging", "prod-cluster", "nonprod", "x", "non-prod", "x", "NON_PRODUCTION", "x", "nonprod-to-prod", "x"))
	creds, err := scanner(t).Discover(env(home, nil))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, c := range creds {
		kinds[c.ID] = c.Kind
		if len(c.Files) != 1 || c.Files[0] != p || c.Tool != "kubectl" || c.Source != "file" {
			t.Errorf("bad credential %+v", c)
		}
		if c.ID == "staging" && c.Identity != "prod-cluster" {
			t.Errorf("identity %q", c.Identity)
		}
	}
	want := map[string]string{"dev": "context", "production": "production-context", "Prod-eu": "production-context",
		"staging": "production-context", "nonprod": "context", "non-prod": "context", "NON_PRODUCTION": "context",
		"nonprod-to-prod": "production-context"}
	if len(kinds) != len(want) {
		t.Fatalf("got %v", kinds)
	}
	for k, v := range want {
		if kinds[k] != v {
			t.Errorf("%s: %q want %q", k, kinds[k], v)
		}
	}
	for i := 1; i < len(creds); i++ {
		if creds[i-1].ID > creds[i].ID {
			t.Error("not sorted")
		}
	}
}

func TestDiscoverKubeconfigList(t *testing.T) {
	home, d := t.TempDir(), t.TempDir()
	write(t, home, ".kube/config", cfg("homectx", "h"))
	a := write(t, d, "a", cfg("same", "ca"))
	b := write(t, d, "b", cfg("same", "cb", "other", "cb"))
	list := a + string(os.PathListSeparator) + filepath.Join(d, "missing") + string(os.PathListSeparator) + b
	creds, err := scanner(t).Discover(env(home, map[string]string{"KUBECONFIG": list}))
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Fatalf("got %+v", creds)
	}
	for _, c := range creds {
		if c.ID == "homectx" {
			t.Error("KUBECONFIG must override home file")
		}
		if c.ID == "same" && (c.Files[0] != a || c.Identity != "ca") {
			t.Errorf("first definition must win: %+v", c)
		}
	}
}

func TestDiscoverNeverReturnsSecrets(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".kube/config", `
clusters:
- name: c
  cluster:
    server: https://CANARY-server.example
users:
- name: u
  user:
    token: CANARY-token
    client-key-data: CANARY-key
    exec:
      command: x
      args: [CANARY-arg]
    auth-provider:
      config:
        access-token: CANARY-ap
contexts:
- name: ctx
  context:
    cluster: c
    user: u
`)
	creds, err := scanner(t).Discover(env(home, nil))
	out, _ := json.Marshal(creds)
	text := string(out)
	if err != nil {
		text += err.Error()
	}
	if len(creds) != 1 || strings.Contains(text, "CANARY") {
		t.Fatalf("creds=%d text=%s", len(creds), text)
	}
}

func TestDiscoverBadFiles(t *testing.T) {
	d := t.TempDir()
	good := write(t, d, "good", cfg("ok", "c"))
	bad := []string{
		write(t, d, "yamlbad", "contexts: [CANARY-oops\n  : {"),
		write(t, d, "scalar", "CANARY-scalar"),
		filepath.Join(d, "adir"),
		write(t, d, "big", "#"+strings.Repeat("x", 1<<20+10)),
		"relative/CANARY-path",
	}
	if err := os.Mkdir(bad[2], 0o700); err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathListSeparator)
	creds, err := scanner(t).Discover(env("", map[string]string{"KUBECONFIG": strings.Join(append(bad, good), sep)}))
	if len(creds) != 1 || creds[0].ID != "ok" {
		t.Fatalf("got %+v", creds)
	}
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(strings.ReplaceAll(err.Error(), "relative/CANARY-path", ""), "CANARY") {
		t.Errorf("error leaks content: %v", err)
	}
	for _, f := range []string{write(t, d, "empty", ""), filepath.Join(d, "missing")} {
		if creds, err := scanner(t).Discover(env("", map[string]string{"KUBECONFIG": f})); err != nil || len(creds) != 0 {
			t.Errorf("%s: %v %v", f, creds, err)
		}
	}
}

func TestDiscoverHostileNames(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".kube/config", cfg(`prod\u001b[31m‮`, "c"))
	creds, err := scanner(t).Discover(env(home, nil))
	if err != nil || len(creds) != 1 {
		t.Fatalf("%v %v", creds, err)
	}
	for _, r := range creds[0].Label {
		if r < 0x20 || r == 0x7f || r == 0x202e {
			t.Errorf("label %q has %U", creds[0].Label, r)
		}
	}
	if creds[0].Kind != "production-context" {
		t.Error(creds[0].Kind)
	}
}

func TestDiscoverServiceAccount(t *testing.T) {
	s := New()
	s.saToken = write(t, t.TempDir(), "token", "CANARY-sa")
	creds, err := s.Discover(env("", map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}))
	out, _ := json.Marshal(creds)
	if err != nil || len(creds) != 1 || creds[0].ID != "serviceaccount:in-cluster" || creds[0].Kind != "serviceaccount" ||
		len(creds[0].Notes) != 1 || strings.Contains(string(out), "CANARY") {
		t.Fatalf("%s %v", out, err)
	}
	if creds, _ := s.Discover(env("", nil)); len(creds) != 0 {
		t.Error("env unset must give none")
	}
	s.saToken = filepath.Join(t.TempDir(), "missing")
	if creds, _ := s.Discover(env("", map[string]string{"KUBERNETES_SERVICE_HOST": "x"})); len(creds) != 0 {
		t.Error("missing file must give none")
	}
}

func TestResolveSkips(t *testing.T) {
	_, err := New().Resolve(context.Background(), model.Credential{})
	var se *scan.SkipError
	if !errors.As(err, &se) {
		t.Fatalf("got %v", err)
	}
}
