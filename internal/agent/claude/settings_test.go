package claude

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/model"
)

// perms builds a settings.json body with the given permissions object.
func perms(allow, ask, deny []string, mode string) string {
	q := func(l []string) string {
		s := make([]string, len(l))
		for i, r := range l {
			s[i] = fmt.Sprintf("%q", r)
		}
		return "[" + strings.Join(s, ",") + "]"
	}
	m := ""
	if mode != "" {
		m = fmt.Sprintf(`,"defaultMode":%q`, mode)
	}
	return fmt.Sprintf(`{"permissions":{"allow":%s,"ask":%s,"deny":%s%s}}`, q(allow), q(ask), q(deny), m)
}

func put(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMergesSources(t *testing.T) {
	cfg, proj, mdir := t.TempDir(), t.TempDir(), t.TempDir()
	u := put(t, filepath.Join(cfg, "settings.json"), `{"env":{"X":"CANARY-SECRET-DO-NOT-PRINT"},"hooks":{"a":"CANARY-SECRET-DO-NOT-PRINT"},"permissions":{"allow":["Bash(aws:*)"],"deny":["Bash(gh:*)"]}}`)
	p := put(t, filepath.Join(proj, ".claude", "settings.json"), perms(nil, []string{"Bash(zz:*)"}, []string{"Bash(zz:*)"}, "plan"))
	l := put(t, filepath.Join(proj, ".claude", "settings.local.json"), perms([]string{"Bash(x:*)"}, nil, nil, ""))
	m := put(t, filepath.Join(mdir, "managed-settings.json"), perms(nil, nil, []string{"Read(~/.aws/**)"}, ""))
	d2 := put(t, filepath.Join(mdir, "managed-settings.d", "20-b.json"), perms(nil, []string{"Bash(b:*)"}, nil, ""))
	d1 := put(t, filepath.Join(mdir, "managed-settings.d", "10-a.json"), perms(nil, []string{"Bash(a:*)"}, nil, ""))
	put(t, filepath.Join(mdir, "managed-settings.d", "skip.txt"), `not json`)
	put(t, filepath.Join(mdir, "managed-settings.d", ".hidden.json"), perms(nil, nil, []string{"Bash"}, "dontAsk"))

	s := Load(cfg, proj, []string{m})
	if !reflect.DeepEqual(s.Allow, []string{"Bash(aws:*)", "Bash(x:*)"}) {
		t.Errorf("Allow = %v", s.Allow)
	}
	if !reflect.DeepEqual(s.Deny, []string{"Bash(gh:*)", "Read(~/.aws/**)"}) {
		t.Errorf("Deny = %v", s.Deny)
	}
	if !reflect.DeepEqual(s.Ask, []string{"Bash(a:*)", "Bash(b:*)"}) {
		t.Errorf("Ask = %v", s.Ask)
	}
	if want := []string{u, p, l, m, d1, d2}; !reflect.DeepEqual(s.Sources, want) {
		t.Errorf("Sources = %v, want %v", s.Sources, want)
	}
	if want := []string{p + ": deny, ask and defaultMode settings apply to this project only and are not counted"}; !reflect.DeepEqual(s.Notes, want) {
		t.Errorf("Notes = %v, want %v", s.Notes, want)
	}
	if s.DefaultMode != "" {
		t.Errorf("project defaultMode leaked: %q", s.DefaultMode)
	}
	if strings.Contains(fmt.Sprintf("%+v", s), "CANARY") {
		t.Error("canary leaked into Settings")
	}
}

func TestLoadTolerantOfBadFiles(t *testing.T) {
	cfg, proj := t.TempDir(), t.TempDir()
	put(t, filepath.Join(proj, ".claude", "settings.json"), "")                              // empty: no note
	bad := put(t, filepath.Join(proj, ".claude", "settings.local.json"), `{"x": CANARY-BAD`) // invalid JSON
	wrong := put(t, filepath.Join(cfg, "settings.json"), `{"permissions":{"allow":"Bash"}}`)
	dir := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := Load(cfg, proj, []string{dir, filepath.Join(t.TempDir(), "missing.json")})
	if len(s.Notes) != 3 {
		t.Fatalf("Notes = %v", s.Notes)
	}
	for i, p := range []string{wrong, bad, dir} {
		if !strings.Contains(s.Notes[i], p) {
			t.Errorf("Notes[%d] = %q, want path %q", i, s.Notes[i], p)
		}
	}
	if strings.Contains(strings.Join(s.Notes, "\n"), "CANARY") || len(s.Allow) != 0 || len(s.Sources) != 0 {
		t.Errorf("bad files leaked or counted: %+v", s)
	}
}

func TestLoadDefaultModePrecedenceAndHonouring(t *testing.T) {
	load := func(user, proj, local, managed string) Settings {
		cfg, pd, md := t.TempDir(), t.TempDir(), t.TempDir()
		for path, mode := range map[string]string{
			filepath.Join(cfg, "settings.json"):                 user,
			filepath.Join(pd, ".claude", "settings.json"):       proj,
			filepath.Join(pd, ".claude", "settings.local.json"): local,
			filepath.Join(md, "managed-settings.json"):          managed,
		} {
			if mode != "" {
				put(t, path, perms(nil, nil, nil, mode))
			}
		}
		return Load(cfg, pd, []string{filepath.Join(md, "managed-settings.json")})
	}
	if s := load("plan", "", "", "dontAsk"); s.DefaultMode != "dontAsk" {
		t.Errorf("managed should win: %q", s.DefaultMode)
	}
	if s := load("manual", "", "", ""); s.DefaultMode != "default" {
		t.Errorf("manual should read as default: %q", s.DefaultMode)
	}
	if s := load("bypassPermissions", "", "", ""); s.DefaultMode != "bypassPermissions" || len(s.Notes) != 0 {
		t.Errorf("user bypass honoured: %+v", s)
	}
	if s := load("", "", "", "auto"); s.DefaultMode != "auto" {
		t.Errorf("managed auto honoured: %q", s.DefaultMode)
	}
	// a project or project-local mode, of any value, never counts: it applies to one project only
	for _, mode := range []string{"bypassPermissions", "auto", "plan", "dontAsk"} {
		s := load("bypassPermissions", mode, "", "")
		if s.DefaultMode != "bypassPermissions" || len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "settings.json") || !strings.Contains(s.Notes[0], "apply to this project only") {
			t.Errorf("project %s must not count: %+v", mode, s)
		}
		s = load("", "", mode, "")
		if s.DefaultMode != "" || len(s.Notes) != 1 || !strings.Contains(s.Notes[0], "settings.local.json") {
			t.Errorf("local %s must not count: %+v", mode, s)
		}
	}
}

func TestLoadProjectOnlyWidens(t *testing.T) {
	cfg, proj := t.TempDir(), t.TempDir()
	put(t, filepath.Join(cfg, "settings.json"), perms([]string{"Bash(aws:*)"}, nil, nil, "bypassPermissions"))
	p := put(t, filepath.Join(proj, ".claude", "settings.json"), perms(nil, nil, []string{"Bash(aws:*)", "Read(~/.aws/**)"}, "plan"))
	s := Load(cfg, proj, nil)
	if a, blocked := s.Classify(awsCred("/h/.aws/credentials"), "/h"); a != model.AccessAllowed || blocked {
		t.Errorf("user allow + project deny: got (%s, %v)", a, blocked)
	}
	if !s.UnrestrictedShell() {
		t.Error("user bypass + project plan must stay unrestricted")
	}
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], p) || len(s.Sources) != 2 {
		t.Errorf("notes/sources: %+v", s)
	}
	// no user rule + project allow => allowed
	put(t, filepath.Join(proj, ".claude", "settings.local.json"), perms([]string{"Bash(aws:*)"}, nil, nil, ""))
	if a, _ := Load(t.TempDir(), proj, nil).Classify(awsCred(), "/h"); a != model.AccessAllowed {
		t.Errorf("project allow: got %s", a)
	}
}

func TestManagedPaths(t *testing.T) {
	if got := ManagedPaths("darwin"); !reflect.DeepEqual(got, []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}) {
		t.Errorf("darwin = %v", got)
	}
	if got := ManagedPaths("linux"); !reflect.DeepEqual(got, []string{"/etc/claude-code/managed-settings.json"}) {
		t.Errorf("linux = %v", got)
	}
	if got := ManagedPaths("test"); len(got) != 0 {
		t.Errorf("other = %v", got)
	}
}

func awsCred(files ...string) model.Credential {
	return model.Credential{Tool: "aws", ID: "default", Files: files}
}

func TestClassifyTool(t *testing.T) {
	A, K, D := model.AccessAllowed, model.AccessAsks, model.AccessDenied
	cases := []struct {
		name             string
		allow, ask, deny []string
		mode             string
		want             model.AgentAccess
	}{
		{"no rules", nil, nil, nil, "", K},
		{"colon star", []string{"Bash(aws:*)"}, nil, nil, "", A},
		{"space star", []string{"Bash(aws *)"}, nil, nil, "", A},
		{"exact aws only", []string{"Bash(aws)"}, nil, nil, "", K},
		{"no-space star", []string{"Bash(aws*)"}, nil, nil, "", A},
		{"no-space star deny", []string{"Bash"}, nil, []string{"Bash(aws*)"}, "", D},
		{"no-space star other tool", []string{"Bash(awscli*)"}, nil, nil, "", K},
		{"bare Bash", []string{"Bash"}, nil, nil, "", A},
		{"Bash star", []string{"Bash(*)"}, nil, nil, "", A},
		{"partial", []string{"Bash(aws s3 ls:*)"}, nil, nil, "", K},
		{"other tool prefix", []string{"Bash(awscli:*)"}, nil, nil, "", K},
		{"non-bash tool", []string{"Read(aws:*)"}, nil, nil, "", K},
		{"ask beats allow", []string{"Bash(aws:*)"}, []string{"Bash(aws:*)"}, nil, "", K},
		{"deny beats allow", []string{"Bash"}, nil, []string{"Bash(aws:*)"}, "", D},
		{"deny Bash", nil, nil, []string{"Bash"}, "", D},
		{"exact deny does not deny", nil, nil, []string{"Bash(aws)"}, "", K},
		{"exact deny plus prefix allow", []string{"Bash(aws:*)"}, nil, []string{"Bash(aws)"}, "", A},
		{"bypass", nil, nil, nil, "bypassPermissions", A},
		{"bypass denied", nil, nil, []string{"Bash(aws:*)"}, "bypassPermissions", D},
		{"bypass ask", nil, []string{"Bash(aws:*)"}, nil, "bypassPermissions", K},
		{"auto", nil, nil, nil, "auto", A},
		{"auto denied", nil, nil, []string{"Bash"}, "auto", D},
		{"acceptEdits", nil, nil, nil, "acceptEdits", K},
		{"plan", nil, nil, nil, "plan", K},
		{"dontAsk no rule", nil, nil, nil, "dontAsk", D},
		{"dontAsk allow", []string{"Bash(aws:*)"}, nil, nil, "dontAsk", A},
		{"dontAsk ask match", []string{"Bash(aws:*)"}, []string{"Bash(aws:*)"}, nil, "dontAsk", D},
	}
	for _, c := range cases {
		s := Settings{Allow: c.allow, Ask: c.ask, Deny: c.deny, DefaultMode: c.mode}
		if got, _ := s.Classify(awsCred(), "/h"); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	// placeholder credential IDs classify like any other credential of the tool
	s := Settings{Allow: []string{"Bash(aws:*)"}}
	for _, id := range []string{"unreadable", "enterprise", "environment", "chain"} {
		if got, _ := s.Classify(model.Credential{Tool: "aws", ID: id}, "/h"); got != model.AccessAllowed {
			t.Errorf("id %s: got %s", id, got)
		}
	}
}

func TestClassifyCredentialFileDeny(t *testing.T) {
	cred := awsCred("/h/.aws/credentials")
	allow := []string{"Bash(aws:*)"}
	cases := []struct {
		name        string
		allow, deny []string
		cred        model.Credential
		access      model.AgentAccess
		blocked     bool
	}{
		{"dir glob", nil, []string{"Read(~/.aws/**)"}, cred, model.AccessAsks, true},
		{"dir glob with allow", allow, []string{"Read(~/.aws/**)"}, cred, model.AccessAllowed, true},
		{"single star", nil, []string{"Read(~/.aws/*)"}, cred, model.AccessAsks, true},
		{"double-slash absolute", nil, []string{"Read(//h/.aws/credentials)"}, cred, model.AccessAsks, true},
		{"single-slash is not absolute", nil, []string{"Read(/h/.aws/credentials)"}, cred, model.AccessAsks, false},
		{"other file", nil, []string{"Read(~/.aws/config)"}, cred, model.AccessAsks, false},
		{"other dir", nil, []string{"Read(~/.ssh/**)"}, cred, model.AccessAsks, false},
		{"prefix is not a dir", nil, []string{"Read(~/.aw/**)"}, cred, model.AccessAsks, false},
		{"Edit rule ignored", nil, []string{"Edit(~/.aws/**)"}, cred, model.AccessAsks, false},
		{"both denied", nil, []string{"Read(~/.aws/**)", "Bash(aws:*)"}, cred, model.AccessDenied, true},
		{"env credential", nil, []string{"Read(~/.aws/**)"}, awsCred(), model.AccessAsks, false},
	}
	for _, c := range cases {
		s := Settings{Allow: c.allow, Deny: c.deny}
		if a, b := s.Classify(c.cred, "/h"); a != c.access || b != c.blocked {
			t.Errorf("%s: got (%s, %v), want (%s, %v)", c.name, a, b, c.access, c.blocked)
		}
	}
}

func TestUnrestrictedShell(t *testing.T) {
	cases := []struct {
		name string
		s    Settings
		want bool
	}{
		{"allow Bash", Settings{Allow: []string{"Bash"}}, true},
		{"allow Bash(*)", Settings{Allow: []string{"Bash(*)"}}, true},
		{"bypass", Settings{DefaultMode: "bypassPermissions"}, true},
		{"auto", Settings{DefaultMode: "auto"}, true},
		{"deny beats allow", Settings{Allow: []string{"Bash"}, Deny: []string{"Bash"}}, false},
		{"deny beats bypass", Settings{DefaultMode: "bypassPermissions", Deny: []string{"Bash(*)"}}, false},
		{"deny beats auto", Settings{DefaultMode: "auto", Deny: []string{"Bash"}}, false},
		{"narrow allow", Settings{Allow: []string{"Bash(aws:*)"}}, false},
		{"narrow deny keeps bypass", Settings{DefaultMode: "bypassPermissions", Deny: []string{"Bash(aws:*)"}}, true},
		{"default", Settings{}, false},
		{"dontAsk", Settings{DefaultMode: "dontAsk"}, false},
	}
	for _, c := range cases {
		if got := c.s.UnrestrictedShell(); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLoadKeysAreCaseSensitive(t *testing.T) {
	cfg := t.TempDir()
	put(t, filepath.Join(cfg, "settings.json"), `{"PERMISSIONS":{"deny":["Bash"]}}`)
	if s := Load(cfg, t.TempDir(), nil); len(s.Deny) != 0 {
		t.Errorf("PERMISSIONS counted: %v", s.Deny)
	}
	put(t, filepath.Join(cfg, "settings.json"), `{"permissions":{"Deny":["Bash"],"ALLOW":["Bash"],"DefaultMode":"bypassPermissions"}}`)
	if s := Load(cfg, t.TempDir(), nil); len(s.Deny)+len(s.Allow) != 0 || s.DefaultMode != "" {
		t.Errorf("mixed-case keys counted: %+v", s)
	}
	put(t, filepath.Join(cfg, "settings.json"), `{"permissions":{"deny":["Bash"]}}`)
	if s := Load(cfg, t.TempDir(), nil); len(s.Deny) != 1 {
		t.Errorf("exact keys lost: %+v", s)
	}
}

func TestLoadUnknownDefaultModeKeepsCurrentMode(t *testing.T) {
	cfg, md := t.TempDir(), t.TempDir()
	put(t, filepath.Join(cfg, "settings.json"), perms(nil, nil, nil, "dontAsk"))
	m := put(t, filepath.Join(md, "managed-settings.json"), perms(nil, nil, nil, "bogusMode"))
	s := Load(cfg, t.TempDir(), []string{m})
	if s.DefaultMode != "dontAsk" {
		t.Errorf("mode = %q, want dontAsk", s.DefaultMode)
	}
	if len(s.Notes) != 1 || !strings.Contains(s.Notes[0], m) || !strings.Contains(s.Notes[0], "defaultMode") || strings.Contains(s.Notes[0], "bogusMode") {
		t.Errorf("notes = %v", s.Notes)
	}
}

func TestClassifyMCP(t *testing.T) {
	mcp := model.Credential{Tool: "mcp", ID: "filesystem"}
	cases := []struct {
		name string
		s    Settings
		c    model.Credential
		want model.AgentAccess
	}{
		{"deny server", Settings{Deny: []string{"mcp__filesystem"}}, mcp, model.AccessDenied},
		{"deny server wildcard", Settings{Deny: []string{"mcp__filesystem__*"}}, mcp, model.AccessDenied},
		{"deny one tool", Settings{Deny: []string{"mcp__filesystem__read"}}, mcp, model.AccessAsks},
		{"deny other server", Settings{Deny: []string{"mcp__other"}}, mcp, model.AccessAsks},
		{"prefix trap", Settings{Deny: []string{"mcp__filesystem2"}}, mcp, model.AccessAsks},
		{"bash rule", Settings{Deny: []string{"Bash(mcp:*)"}}, mcp, model.AccessAsks},
		{"allow", Settings{Allow: []string{"mcp__filesystem"}}, mcp, model.AccessAllowed},
		{"ask", Settings{Ask: []string{"mcp__filesystem"}}, mcp, model.AccessAsks},
		{"dontAsk", Settings{DefaultMode: "dontAsk"}, mcp, model.AccessDenied},
		{"mcp rule on aws", Settings{Deny: []string{"mcp__filesystem"}}, model.Credential{Tool: "aws"}, model.AccessAsks},
		{"double underscore id, one-tool rule", Settings{Deny: []string{"mcp__a__b"}}, model.Credential{Tool: "mcp", ID: "a__b"}, model.AccessAsks},
		{"double underscore id, server rule", Settings{Deny: []string{"mcp__a"}}, model.Credential{Tool: "mcp", ID: "a__b"}, model.AccessDenied},
		{"trailing underscore id, seen rule", Settings{Deny: []string{"mcp__caf"}}, model.Credential{Tool: "mcp", ID: "caf_"}, model.AccessDenied},
		{"trailing underscore id, own rule", Settings{Deny: []string{"mcp__caf_"}}, model.Credential{Tool: "mcp", ID: "caf_"}, model.AccessAsks},
		{"leading underscores id", Settings{Deny: []string{"mcp____x"}}, model.Credential{Tool: "mcp", ID: "__x"}, model.AccessAsks},
	}
	for _, tc := range cases {
		if got, _ := tc.s.Classify(tc.c, "/h"); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
