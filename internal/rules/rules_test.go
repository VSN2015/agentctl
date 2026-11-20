package rules

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
	"github.com/VSN2015/agentctl/internal/usage/shellparse"
)

var now = time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

const window = 30 * 24 * time.Hour

func hist(days int) usage.Usage {
	return usage.Usage{HistoryStart: now.Add(-time.Duration(days) * 24 * time.Hour)}
}

func calls(n int, tool, sub, target string) []usage.Call {
	var out []usage.Call
	for i := 0; i < n; i++ {
		out = append(out, usage.Call{At: now.Add(-time.Duration(i+1) * time.Hour), Invocation: shellparse.Invocation{Tool: tool, Sub: sub, Target: target}})
	}
	return out
}

// devHistory builds shell history in a temp home; lines are zsh entries.
func devHistory(t *testing.T, lines ...string) devuse.History {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".zsh_history"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return devuse.Read(home, func(string) string { return "" })
}

func zshAt(t time.Time, cmd string) string {
	return ": " + strconv.FormatInt(t.Unix(), 10) + ":0;" + cmd
}

// fakeRule returns scripted results.
type fakeRule struct {
	risks      []Risk
	dev        DevUse
	revoke     string
	risksCalls int
}

func (f *fakeRule) Tool() string { return "fake" }
func (f *fakeRule) Attribute(_ model.Credential, c []usage.Call, _ Context) ([]usage.Call, int) {
	return c, 0
}
func (f *fakeRule) Risks(model.Credential, model.AgentState, AgentUse, Context) []Risk {
	f.risksCalls++
	return f.risks
}
func (f *fakeRule) DeveloperUse(model.Credential, AgentUse, Context) DevUse { return f.dev }
func (f *fakeRule) Revoke(model.Credential, Context) string                 { return f.revoke }

func cred(access model.AgentAccess, blocked bool) model.Credential {
	return model.Credential{Tool: "fake", ID: "c1", Access: []model.AgentState{{Agent: "claude-code", Access: access, FileBlocked: blocked}}}
}

func agentIn(u usage.Usage) AgentInput {
	return AgentInput{Name: "claude-code", Usage: u, BlockAdvice: func(tool string) string { return "block " + tool }}
}

func run(c model.Credential, a AgentInput, r ToolRule) model.Finding {
	fs := Evaluate(Input{Creds: []model.Credential{c}, Agents: []AgentInput{a}, Now: now, Window: window}, []ToolRule{r})
	return fs[0]
}

func has(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func fakeUsage(days, n int) usage.Usage {
	u := hist(days)
	u.Shell = calls(n, "fake", "", "")
	return u
}

func TestAgentUseStates(t *testing.T) {
	cases := []struct {
		name  string
		u     usage.Usage
		n, un int
		want  UseState
		days  int
	}{
		{"unused", hist(45), 0, 0, UseUnused, 45},
		{"rare", hist(45), 2, 0, UseRare, 45},
		{"used", hist(45), 3, 0, UseUsed, 45},
		{"short zero", hist(10), 0, 0, UseUnknown, 10},
		{"short two", hist(10), 2, 0, UseUnknown, 10},
		{"no history", usage.Usage{}, 0, 0, UseUnknown, 0},
		{"unattributable", hist(45), 0, 4, UseUnattributable, 45},
		{"unread unused", usage.Usage{HistoryStart: hist(45).HistoryStart, Unread: 1}, 0, 0, UseUnknown, 45},
		{"unread rare", usage.Usage{HistoryStart: hist(45).HistoryStart, Unread: 1}, 2, 0, UseUnknown, 45},
		{"unread but used", usage.Usage{HistoryStart: hist(45).HistoryStart, Unread: 1}, 3, 0, UseUsed, 45},
	}
	for _, c := range cases {
		got := agentUse(c.u, calls(c.n, "fake", "", ""), c.un, window, now)
		if got.State != c.want || got.HistoryDays != c.days || got.Count != c.n {
			t.Errorf("%s: got %+v want state %v days %d", c.name, got, c.want, c.days)
		}
	}
}

func TestEngineDeniedIsOKAndSkipsRisks(t *testing.T) {
	r := &fakeRule{risks: []Risk{{Rule: "x", Severity: model.SevHigh, Headline: "h"}}}
	f := run(cred(model.AccessDenied, false), agentIn(fakeUsage(45, 0)), r)
	if f.Severity != model.SevOK || r.risksCalls != 0 || !strings.Contains(f.Headline, "denied by agent settings") {
		t.Fatalf("%+v calls %d", f, r.risksCalls)
	}
	r2 := &fakeRule{}
	if f := run(cred(model.AccessDenied, true), agentIn(fakeUsage(45, 0)), r2); f.Severity != model.SevOK || r2.risksCalls != 0 {
		t.Fatalf("file blocked + denied: %+v", f)
	}
}

func TestEngineFileBlockedStillRisky(t *testing.T) {
	r := &fakeRule{risks: []Risk{{Rule: "x", Severity: model.SevHigh, Headline: "h"}}}
	f := run(cred(model.AccessAllowed, true), agentIn(fakeUsage(45, 5)), r)
	if f.Severity != model.SevHigh || !has(f.Details, "credential file blocked, tool still allowed") {
		t.Fatalf("%+v", f)
	}
}

func TestEngineAsksFirstShownNotDowngraded(t *testing.T) {
	r := &fakeRule{risks: []Risk{{Rule: "x", Severity: model.SevHigh, Headline: "h"}}}
	f := run(cred(model.AccessAsks, false), agentIn(fakeUsage(45, 5)), r)
	if f.Severity != model.SevHigh || !has(f.Details, "asks first") {
		t.Fatalf("%+v", f)
	}
	// absent state is treated as asks
	c := cred(model.AccessAllowed, false)
	c.Access = nil
	if f := run(c, agentIn(fakeUsage(45, 5)), r); !has(f.Details, "asks first") || f.Access != model.AccessAsks {
		t.Fatalf("absent: %+v", f)
	}
}

func TestEngineAdviceBranches(t *testing.T) {
	const reminder = "If you do not use it either, revoke the credential."
	cases := []struct {
		name   string
		r      *fakeRule
		n      int
		want   []string
		absent []string
	}{
		{"known recent", &fakeRule{dev: DevUse{State: DevKnownRecent}, revoke: "REV"}, 0, []string{"block fake", "advisory"}, []string{"REV", reminder}},
		{"nobody", &fakeRule{dev: DevUse{State: DevNobody}, revoke: "REV"}, 0, []string{"REV"}, []string{"block fake", "advisory"}},
		{"nobody rare", &fakeRule{dev: DevUse{State: DevNobody}, revoke: "REV"}, 2, []string{"block fake", reminder, "advisory"}, []string{"REV"}},
		{"nobody no revoke", &fakeRule{dev: DevUse{State: DevNobody}}, 0, []string{"block fake", reminder, "advisory"}, nil},
		{"unknown", &fakeRule{dev: DevUse{State: DevUnknown}, revoke: "REV"}, 0, []string{"block fake", reminder, "advisory"}, []string{"REV"}},
	}
	for _, c := range cases {
		f := run(cred(model.AccessAllowed, false), agentIn(fakeUsage(45, c.n)), c.r)
		for _, w := range c.want {
			if !has(f.Advice, w) {
				t.Errorf("%s: missing %q in %v", c.name, w, f.Advice)
			}
		}
		for _, w := range c.absent {
			if has(f.Advice, w) {
				t.Errorf("%s: unexpected %q in %v", c.name, w, f.Advice)
			}
		}
		n := 0
		for _, a := range f.Advice {
			if strings.Contains(a, "advisory") {
				n++
			}
		}
		if n > 1 {
			t.Errorf("%s: advisory %d times", c.name, n)
		}
	}
}

func TestEngineUsageSeverity(t *testing.T) {
	r := &fakeRule{dev: DevUse{State: DevUnknown}}
	a := cred(model.AccessAllowed, false)
	if f := run(a, agentIn(fakeUsage(45, 0)), r); f.Severity != model.SevMed {
		t.Errorf("unused: %+v", f)
	}
	if f := run(a, agentIn(fakeUsage(45, 2)), r); f.Severity != model.SevLow {
		t.Errorf("rare: %+v", f)
	}
	if f := run(a, agentIn(fakeUsage(45, 3)), r); f.Severity != model.SevOK || !strings.Contains(f.Headline, "used 3 times") {
		t.Errorf("used: %+v", f)
	}
	f := run(a, agentIn(fakeUsage(10, 2)), r)
	if f.Severity != model.SevOK || !has(f.Details, "10 days of history available") || len(f.Advice) != 0 ||
		f.Headline != "2 calls by claude-code in 10 days of history" || !has(f.Details, "Agent use: 2 calls in 10 days of history") ||
		has(f.Details, "last 30 days") || strings.Contains(f.Headline, "used 0") {
		t.Errorf("short: %+v", f)
	}
}

func TestEngineNoRuleForTool(t *testing.T) {
	c := model.Credential{Tool: "zzz", ID: "a"}
	f := Evaluate(Input{Creds: []model.Credential{c}, Agents: []AgentInput{agentIn(usage.Usage{})}, Now: now, Window: window}, nil)
	if len(f) != 1 || f[0].Severity != model.SevOK || !strings.Contains(f[0].Headline, "no rules") {
		t.Fatalf("%+v", f)
	}
}

func TestEngineOneFindingPerAgentAndCredential(t *testing.T) {
	cs := []model.Credential{{Tool: "fake", ID: "a"}, {Tool: "fake", ID: "b"}}
	fs := Evaluate(Input{Creds: cs, Agents: []AgentInput{{Name: "a1"}, {Name: "a2"}}, Now: now, Window: window}, []ToolRule{&fakeRule{}})
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	if len(fs) != 4 || !has(ids, "a1:fake:a") || !has(ids, "a2:fake:b") {
		t.Fatalf("%v", ids)
	}
}

func TestUnrestrictedShellFinding(t *testing.T) {
	in := Input{Agents: []AgentInput{{Name: "claude-code", UnrestrictedShell: true}}, Now: now, Window: window}
	fs := Evaluate(in, nil)
	if len(fs) != 1 || fs[0].ID != "claude-code:shell" || fs[0].Severity != model.SevMed || fs[0].Rules[0] != "agent.unrestricted-shell" {
		t.Fatalf("%+v", fs)
	}
	in.Agents[0].UnrestrictedShell = false
	if fs := Evaluate(in, nil); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestEvaluateOrderingAndEmpty(t *testing.T) {
	if fs := Evaluate(Input{Now: now, Window: window}, nil); fs == nil || len(fs) != 0 {
		t.Fatalf("%#v", fs)
	}
	r := &fakeRule{}
	cs := []model.Credential{{Tool: "fake", ID: "b"}, {Tool: "fake", ID: "a"}, {Tool: "fake", ID: "z", Access: []model.AgentState{{Agent: "x", Access: model.AccessDenied}}}}
	fs := Evaluate(Input{Creds: cs, Agents: []AgentInput{{Name: "x", Usage: fakeUsage(45, 0)}}, Now: now, Window: window}, []ToolRule{r})
	if fs[0].ID != "x:fake:a" || fs[1].ID != "x:fake:b" || fs[2].ID != "x:fake:z" {
		t.Fatalf("%v %v %v", fs[0].ID, fs[1].ID, fs[2].ID)
	}
}

func TestEngineUnknownKindIsUnattributable(t *testing.T) {
	r := &fakeRule{dev: DevUse{State: DevNobody}, revoke: "REV"}
	c := cred(model.AccessAllowed, false)
	c.Kind, c.ID = "unknown", "unreadable"
	f := run(c, agentIn(fakeUsage(45, 0)), r)
	if f.Severity != model.SevOK || len(f.Advice) != 0 || !has(f.Details, "cannot be attributed") || has(f.Details, "unused") ||
		f.Headline != "use by claude-code cannot be attributed" || !has(f.Details, "Agent use, last 30 days: cannot be attributed") {
		t.Fatalf("%+v", f)
	}
}

func TestEngineUnreadHistoryNeverUnused(t *testing.T) {
	u := fakeUsage(45, 0)
	u.Unread = 2
	f := run(cred(model.AccessAllowed, false), agentIn(u), &fakeRule{})
	if f.Severity != model.SevOK || len(f.Advice) != 0 || !has(f.Details, "history could not be read") ||
		f.Headline != "0 calls by claude-code in the history that could be read" || !has(f.Details, "Agent use: 0 calls in the history that could be read") ||
		has(f.Details, "last 30 days") {
		t.Fatalf("%+v", f)
	}
}

func devuse0Unread() devuse.History {
	// a directory where the history file should be makes it unreadable
	home, _ := os.MkdirTemp("", "h")
	_ = os.Mkdir(filepath.Join(home, ".zsh_history"), 0o700)
	defer os.RemoveAll(home)
	return devuse.Read(home, func(string) string { return "" })
}

func TestEngineUnknownKindRealCredentialIsNormal(t *testing.T) {
	c := model.Credential{Tool: "aws", ID: "chain", Kind: "unknown", Source: "chain",
		Access: []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}}
	f := run(c, agentIn(hist(45)), AWSRule{})
	if f.Severity != model.SevMed || !has(f.Rules, "usage.unused") {
		t.Fatalf("%+v", f)
	}
}
