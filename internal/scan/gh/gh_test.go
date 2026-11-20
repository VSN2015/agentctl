package gh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

const canary = "CANARY-SECRET-DO-NOT-PRINT"

const basicHosts = `github.com:
  git_protocol: https
  user: alice
  oauth_token: ` + canary + `
  users:
    alice:
      oauth_token: ` + canary + `
ghe.example.com:
  user: bob
`

// writeHosts writes a synthetic hosts file under dir/gh and returns its path.
func writeHosts(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "gh", "hosts.yml")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func envOf(home string, vars map[string]string) scan.Env {
	return scan.Env{Home: home, Getenv: func(k string) string { return vars[k] }}
}

func ids(cs []model.Credential) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

func TestDiscoverHosts(t *testing.T) {
	home := t.TempDir()
	p := writeHosts(t, filepath.Join(home, ".config"), basicHosts)
	creds, err := New(nil).Discover(envOf(home, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"ghe.example.com", "github.com"}) {
		t.Fatalf("ids = %v", got)
	}
	for _, c := range creds {
		want := map[string]string{"github.com": "alice", "ghe.example.com": "bob"}[c.ID]
		if c.Identity != want || c.Kind != "file-host" || c.Tool != "gh" || !reflect.DeepEqual(c.Files, []string{p}) {
			t.Errorf("%s: %+v", c.ID, c)
		}
	}
	if s := fmt.Sprintf("%+v", creds); strings.Contains(s, canary) {
		t.Fatalf("token leaked: %s", s)
	}
}

func TestDiscoverConfigDirPrecedence(t *testing.T) {
	home, xdg, gd := t.TempDir(), t.TempDir(), t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), "home.example.com:\n  user: a\n")
	run := func(vars map[string]string) []string {
		cs, err := New(nil).Discover(envOf(home, vars))
		if err != nil {
			t.Fatal(err)
		}
		return ids(cs)
	}
	if got := run(nil); !reflect.DeepEqual(got, []string{"home.example.com"}) {
		t.Fatalf("home: %v", got)
	}
	if err := os.MkdirAll(filepath.Join(xdg, "gh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, "gh", "hosts.yml"), []byte("xdg.example.com:\n  user: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run(map[string]string{"XDG_CONFIG_HOME": xdg}); !reflect.DeepEqual(got, []string{"xdg.example.com"}) {
		t.Fatalf("xdg: %v", got)
	}
	if err := os.WriteFile(filepath.Join(gd, "hosts.yml"), []byte("gd.example.com:\n  user: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run(map[string]string{"XDG_CONFIG_HOME": xdg, "GH_CONFIG_DIR": gd}); !reflect.DeepEqual(got, []string{"gd.example.com"}) {
		t.Fatalf("GH_CONFIG_DIR: %v", got)
	}
}

func TestDiscoverEnvTokens(t *testing.T) {
	home := t.TempDir()
	creds, err := New(nil).Discover(envOf(home, map[string]string{"GH_TOKEN": canary}))
	if err != nil || len(creds) != 1 {
		t.Fatalf("%v %v", creds, err)
	}
	c := creds[0]
	if c.ID != "github.com" || c.Kind != "env-token" || c.Source != "env" || !reflect.DeepEqual(c.EnvVars, []string{"GH_TOKEN"}) {
		t.Errorf("%+v", c)
	}
	if strings.Contains(fmt.Sprintf("%+v", creds), canary) {
		t.Error("token value stored")
	}

	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GH_ENTERPRISE_TOKEN": canary, "GH_HOST": "ghe.example.com"}))
	if len(creds) != 1 || creds[0].ID != "ghe.example.com" || creds[0].Kind != "env-token" ||
		!reflect.DeepEqual(creds[0].EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) {
		t.Errorf("enterprise: %+v", creds)
	}

	writeHosts(t, filepath.Join(home, ".config"), basicHosts)
	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GH_TOKEN": canary}))
	if got := ids(creds); !reflect.DeepEqual(got, []string{"ghe.example.com", "github.com"}) {
		t.Fatalf("merge ids: %v", got)
	}
	for _, c := range creds {
		if c.ID == "github.com" && !reflect.DeepEqual(c.EnvVars, []string{"GH_TOKEN"}) {
			t.Errorf("merged env vars: %+v", c)
		}
	}
}

func TestDiscoverEmptyAndUnreadable(t *testing.T) {
	for name, setup := range map[string]func(home string){
		"no dir": func(string) {},
		"empty":  func(h string) { writeHosts(t, filepath.Join(h, ".config"), "") },
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			setup(home)
			creds, err := New(nil).Discover(envOf(home, nil))
			if err != nil || len(creds) != 0 {
				t.Fatalf("creds=%v err=%v", creds, err)
			}
		})
	}
	for name, tc := range map[string]struct {
		setup func(home string)
		note  string
	}{
		"directory": {func(h string) { _ = os.MkdirAll(filepath.Join(h, ".config", "gh", "hosts.yml"), 0o700) }, "could not read hosts file"},
		"garbage":   {func(h string) { writeHosts(t, filepath.Join(h, ".config"), "\x00\x01: [}{\n\t- :") }, "could not parse hosts file"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			tc.setup(home)
			s := New(nil)
			creds, err := s.Discover(envOf(home, nil))
			if err != nil || len(creds) != 1 {
				t.Fatalf("creds=%v err=%v", creds, err)
			}
			c := creds[0]
			if c.ID != "unreadable" || c.Kind != "unknown" || c.Source != "file" || len(c.Files) != 1 || !reflect.DeepEqual(c.Notes, []string{tc.note}) {
				t.Errorf("%+v", c)
			}
			_, err = s.Resolve(context.Background(), c)
			var skip *scan.SkipError
			if !errors.As(err, &skip) {
				t.Errorf("resolve: %v", err)
			}
		})
	}
}

func TestDiscoverEnterpriseEnvTokens(t *testing.T) {
	home := t.TempDir()
	vars := map[string]string{"GH_ENTERPRISE_TOKEN": canary}
	// A: host in hosts.yml, no GH_HOST
	writeHosts(t, filepath.Join(home, ".config"), "ghe.example.com:\n  user: bob\nacme.ghe.com:\n  user: c\ngithub.com:\n  user: a\n")
	creds, _ := New(nil).Discover(envOf(home, vars))
	for _, c := range creds {
		want := map[string][]string{"ghe.example.com": {"GH_ENTERPRISE_TOKEN"}}[c.ID]
		if !reflect.DeepEqual(c.EnvVars, want) {
			t.Errorf("A %s: %v", c.ID, c.EnvVars)
		}
	}
	// *.ghe.com takes GH_TOKEN
	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GITHUB_TOKEN": canary}))
	for _, c := range creds {
		want := map[string][]string{"github.com": {"GITHUB_TOKEN"}, "acme.ghe.com": {"GITHUB_TOKEN"}}[c.ID]
		if !reflect.DeepEqual(c.EnvVars, want) {
			t.Errorf("ghe.com %s: %v", c.ID, c.EnvVars)
		}
	}
	// B: no host anywhere
	home = t.TempDir()
	s := New(nil)
	creds, _ = s.Discover(envOf(home, vars))
	if len(creds) != 1 {
		t.Fatalf("B: %+v", creds)
	}
	c := creds[0]
	if c.ID != "enterprise" || c.Kind != "env-token" || c.Source != "env" || !reflect.DeepEqual(c.EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) ||
		!reflect.DeepEqual(c.Notes, []string{"host unknown"}) || strings.Contains(fmt.Sprintf("%+v", c), canary) {
		t.Errorf("B: %+v", c)
	}
	var skip *scan.SkipError
	if _, err := s.Resolve(context.Background(), c); !errors.As(err, &skip) {
		t.Errorf("B resolve: %v", err)
	}
	// a real host literally named "enterprise" keeps its name, is resolved, and no placeholder appears
	home = t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), "enterprise:\n  user: x\n")
	f := &fakeRunner{out: []byte("HTTP/2.0 200 OK\n\r\n{\"login\":\"x\"}")}
	s = New(f)
	creds, _ = s.Discover(envOf(home, vars))
	if len(creds) != 1 || creds[0].Kind != "file-host" || !reflect.DeepEqual(creds[0].EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) {
		t.Fatalf("named enterprise: %+v", creds)
	}
	if _, err := s.Resolve(context.Background(), creds[0]); err != nil || f.name != "gh" {
		t.Errorf("named enterprise resolve: %v", err)
	}
}

func TestDiscoverYAMLErrorsNeverEchoContent(t *testing.T) {
	for _, body := range []string{"github.com: " + canary + "\n", "github.com:\n  user: [" + canary + "]\n"} {
		home := t.TempDir()
		writeHosts(t, filepath.Join(home, ".config"), body)
		creds, err := New(nil).Discover(envOf(home, nil))
		out := fmt.Sprintf("%+v %v", creds, err)
		if strings.Contains(out, canary) {
			t.Errorf("canary leaked: %s", out)
		}
		if err != nil || len(creds) != 1 || creds[0].ID != "unreadable" || !reflect.DeepEqual(creds[0].Notes, []string{"could not parse hosts file"}) {
			t.Errorf("creds: %+v err %v", creds, err)
		}
	}
}

func TestHostEntryHasNoTokenField(t *testing.T) {
	typ := reflect.TypeOf(hostEntry{})
	if typ.NumField() != 1 || typ.Field(0).Name != "User" {
		t.Fatalf("hostEntry fields: %v", typ)
	}
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(strings.ToLower(typ.Field(i).Name), "token") {
			t.Errorf("token field %s", typ.Field(i).Name)
		}
	}
}

func TestParseAPIResponse(t *testing.T) {
	body := "\r\n{\"login\":\"alice\"}"
	tests := []struct {
		name, raw string
		login     string
		scopes    []string
		readable  bool
		wantErr   bool
	}{
		{"scopes", "HTTP/2.0 200 OK\nX-Oauth-Scopes: repo, workflow, admin:org\r\nServer: x\r\n" + body, "alice", []string{"repo", "workflow", "admin:org"}, true, false},
		{"empty header", "HTTP/2.0 200 OK\nX-Oauth-Scopes: \r\n" + body, "alice", []string{}, true, false},
		{"absent", "HTTP/2.0 200 OK\nServer: x\r\n" + body, "alice", nil, false, false},
		{"lower case", "HTTP/1.1 200 OK\nx-oauth-scopes: repo\r\n" + body, "alice", []string{"repo"}, true, false},
		{"not json", "HTTP/2.0 200 OK\nX-Oauth-Scopes: repo\r\n\r\n<html>" + canary, "", nil, false, true},
		{"scopes only header", "HTTP/2.0 200 OK\nX-Oauth-Scopes: repo\r\n" + body, "alice", []string{"repo"}, true, false},
		{"no headers", "HTTP/2.0 200 OK\n" + body, "alice", nil, false, false},
		{"no blank line", "HTTP/2.0 200 OK", "", nil, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			login, scopes, readable, err := ParseAPIResponse([]byte(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Errorf("error echoes body: %v", err)
			}
			if login != tc.login || readable != tc.readable || !reflect.DeepEqual(scopes, tc.scopes) {
				t.Errorf("got %q %#v %v", login, scopes, readable)
			}
		})
	}
}

type fakeRunner struct {
	name string
	args []string
	env  []string
	out  []byte
	err  error
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, env []string) ([]byte, error) {
	f.name, f.args, f.env = name, args, env
	return f.out, f.err
}

func TestResolveRunsExactlyOneReadOnlyCommand(t *testing.T) {
	f := &fakeRunner{out: []byte("HTTP/2.0 200 OK\nX-Oauth-Scopes: repo\r\n\r\n{\"login\":\"bob\"}")}
	r, err := New(f).Resolve(context.Background(), model.Credential{Tool: "gh", ID: "ghe.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if f.name != "gh" || !reflect.DeepEqual(f.args, []string{"api", "-i", "--hostname", "ghe.example.com", "user"}) {
		t.Errorf("command: %s %v", f.name, f.args)
	}
	for _, want := range []string{"GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1"} {
		found := false
		for _, e := range f.env {
			found = found || e == want
		}
		if !found {
			t.Errorf("env lacks %s: %v", want, f.env)
		}
	}
	if r.Identity != "bob" || !r.ScopesReadable || !reflect.DeepEqual(r.Scopes, []string{"repo"}) {
		t.Errorf("%+v", r)
	}
}

func TestResolveDegrades(t *testing.T) {
	c := model.Credential{Tool: "gh", ID: "github.com"}
	_, err := New(&fakeRunner{err: fmt.Errorf("run: %w", exec.ErrNotFound)}).Resolve(context.Background(), c)
	var skip *scan.SkipError
	if !errors.As(err, &skip) || skip.Reason != "gh not installed" {
		t.Errorf("not found: %v", err)
	}
	_, err = New(&fakeRunner{out: []byte(canary), err: errors.New("exit status 1")}).Resolve(context.Background(), c)
	if err == nil || errors.As(err, &skip) || strings.Contains(err.Error(), canary) {
		t.Errorf("non-zero exit: %v", err)
	}
}
