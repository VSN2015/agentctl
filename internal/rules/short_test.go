package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

func TestFindingUsedAndIssue(t *testing.T) {
	allowed := func(c model.Credential) model.Credential {
		c.Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
		return c
	}
	fake := allowed(cred(model.AccessAllowed, false))
	unread := usage.Usage{HistoryStart: hist(45).HistoryStart, Unread: 1}
	unattr := &fakeRule{}
	cases := []struct {
		name        string
		f           model.Finding
		used, issue string
	}{
		{"unused", run(fake, agentIn(hist(45)), &fakeRule{}), "0", "unused"},
		{"rare", run(fake, agentIn(fakeUsage(45, 2)), &fakeRule{}), "2", "rarely used"},
		{"used", run(fake, agentIn(fakeUsage(45, 5)), &fakeRule{}), "5", ""},
		{"unknown", run(fake, agentIn(fakeUsage(10, 2)), &fakeRule{}), "2?", ""},
		{"unread", run(fake, agentIn(unread), unattr), "0?", ""},
		{"risks then usage", run(fake, agentIn(hist(45)), &fakeRule{risks: []Risk{
			{Rule: "x", Severity: model.SevHigh, Short: "bad"}, {Severity: model.SevOK, Short: "not checked"}}}), "0", "bad, not checked, unused"},
		{"file blocked", run(cred(model.AccessAllowed, true), agentIn(fakeUsage(45, 5)), &fakeRule{}), "5", "file blocked, tool allowed"},
		{"denied", run(cred(model.AccessDenied, true), agentIn(hist(45)), &fakeRule{}), "", ""},
	}
	for _, c := range cases {
		if c.f.Used != c.used || c.f.Issue != c.issue {
			t.Errorf("%s: used %q issue %q, want %q %q", c.name, c.f.Used, c.f.Issue, c.used, c.issue)
		}
	}
	// calls the rule cannot tie to this credential
	f := run(fake, agentIn(fakeUsage(45, 1)), &unattributable{})
	if f.Used != "?" {
		t.Errorf("unattributable used = %q", f.Used)
	}
}

type unattributable struct{ fakeRule }

func (*unattributable) Attribute(_ model.Credential, c []usage.Call, _ Context) ([]usage.Call, int) {
	return nil, len(c)
}

func TestShortLabelsOfToolRules(t *testing.T) {
	r := AWSRule{}
	admin := r.Risks(awsCred("p", &model.Resolution{AdminChecked: true, Admin: true}), model.AgentState{}, AgentUse{}, Context{})
	unchecked := r.Risks(awsCred("p", &model.Resolution{}), model.AgentState{}, AgentUse{}, Context{})
	c := awsCred("p", nil)
	c.LongLived = true
	long := r.Risks(c, model.AgentState{}, AgentUse{}, Context{})
	if admin[0].Short != "admin" || unchecked[0].Short != "admin not checked" || long[0].Short != "long-lived key" {
		t.Errorf("aws: %q %q %q", admin[0].Short, unchecked[0].Short, long[0].Short)
	}
	g := GHRule{}
	gc := ghCred("github.com", &model.Resolution{ScopesReadable: false})
	if got := g.Risks(gc, model.AgentState{}, AgentUse{Calls: calls(1, "gh", "pr", "")}, Context{}); got[0].Short != "scopes not checked" {
		t.Errorf("gh unreadable: %+v", got)
	}
	gc = ghCred("github.com", &model.Resolution{ScopesReadable: true, Scopes: []string{"repo", "gist"}})
	if got := g.Risks(gc, model.AgentState{}, AgentUse{Calls: calls(1, "gh", "pr", ""), Count: 1}, Context{}); len(got) != 1 || got[0].Short != "extra scopes" {
		t.Errorf("gh unused scopes: %+v", got)
	}
	if got := g.Risks(gc, model.AgentState{}, AgentUse{Calls: calls(1, "gh", "api", ""), Count: 1}, Context{}); got[0].Short != "scopes not checked" {
		t.Errorf("gh unattributable: %+v", got)
	}
}

func TestShellFindingShortFields(t *testing.T) {
	f := shellFinding("claude-code")
	if f.Access != model.AccessAllowed || f.Issue != "unrestricted" || f.Used != "" {
		t.Errorf("%+v", f)
	}
}

func TestShortTexts(t *testing.T) {
	if got := ShortWindow(30 * 24 * time.Hour); got != "30d" {
		t.Error(got)
	}
	if got := ShortWindow(12 * time.Hour); got != "12h" {
		t.Error(got)
	}
	rev := AWSRule{}.Revoke(awsCred("p", nil), Context{Window: window})
	if rev != "revoke key AKIA****WXYZ: no use in the last 30 days per AWS (aws iam update-access-key --status Inactive)" {
		t.Error(rev)
	}
	c := awsCred("p", &model.Resolution{AdminChecked: true, Admin: true})
	if a := (AWSRule{}).Risks(c, model.AgentState{}, AgentUse{}, Context{})[0].Advice[0]; a != "give the agent a least-privilege profile, or block it from AWS" {
		t.Error(a)
	}
	c.LongLived = true
	if a := (AWSRule{}).Risks(c, model.AgentState{}, AgentUse{}, Context{})[1].Advice[0]; !strings.HasPrefix(a, "replace the long-lived key with short-lived credentials (aws sso login") {
		t.Error(a)
	}
}
