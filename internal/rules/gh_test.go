package rules

import (
	"strings"
	"testing"

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
