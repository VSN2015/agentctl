package run

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/agent"
	"github.com/VSN2015/agentctl/internal/confirm"
	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/rules"
	"github.com/VSN2015/agentctl/internal/scan"
	"github.com/VSN2015/agentctl/internal/usage"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type fakeScanner struct {
	name, provider string
	creds          []model.Credential
	discoverErr    error
	resolve        func(context.Context, model.Credential) (*model.Resolution, error)
	resolved       int
	log            *[]string
}

func (f *fakeScanner) Name() string     { return f.name }
func (f *fakeScanner) Provider() string { return f.provider }
func (f *fakeScanner) Discover(scan.Env) ([]model.Credential, error) {
	return append([]model.Credential(nil), f.creds...), f.discoverErr
}
func (f *fakeScanner) Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error) {
	f.resolved++
	if f.log != nil {
		*f.log = append(*f.log, "resolve")
	}
	if f.resolve != nil {
		return f.resolve(ctx, c)
	}
	return &model.Resolution{Identity: "id-" + c.ID, AdminChecked: true, Admin: true}, nil
}

type fakeRule struct {
	tool string
	sev  model.Severity
}

func (r fakeRule) Tool() string { return r.tool }
func (fakeRule) Attribute(_ model.Credential, calls []usage.Call, _ rules.Context) ([]usage.Call, int) {
	return calls, 0
}
func (r fakeRule) Risks(model.Credential, model.AgentState, rules.AgentUse, rules.Context) []rules.Risk {
	return []rules.Risk{{Rule: "fake.risk", Severity: r.sev, Headline: "fake risk headline", Details: []string{"fake detail"}}}
}
func (fakeRule) DeveloperUse(model.Credential, rules.AgentUse, rules.Context) rules.DevUse {
	return rules.DevUse{State: rules.DevUnknown}
}
func (fakeRule) Revoke(model.Credential, rules.Context) string { return "" }

type fakeAgent struct {
	name        string
	state       model.AgentState
	usageErr    error
	forbidUsage *testing.T
	since       *time.Time
	unread      int
	posture     agent.Posture
}

func (a *fakeAgent) Name() string { return a.name }
func (a *fakeAgent) ReadUsage(_ context.Context, since, _ time.Time) (usage.Usage, error) {
	if a.forbidUsage != nil {
		a.forbidUsage.Fatal("ReadUsage called")
	}
	if a.since != nil {
		*a.since = since
	}
	return usage.Usage{Agent: a.name, Since: since, HistoryStart: now.Add(-45 * 24 * time.Hour), Unread: a.unread}, a.usageErr
}
func (a *fakeAgent) Classify(model.Credential) model.AgentState {
	s := a.state
	s.Agent = a.name
	if s.Access == "" {
		s.Access = model.AccessAllowed
	}
	return s
}
func (a *fakeAgent) BlockAdvice(string) string { return "block it" }
func (a *fakeAgent) Posture() agent.Posture    { return a.posture }

func cred(tool, id string) model.Credential {
	return model.Credential{Tool: tool, ID: id, Label: "label " + id, Kind: "key", Source: "file"}
}

type rig struct {
	sc      *fakeScanner
	ag      *fakeAgent
	rule    fakeRule
	confirm func([]string) (bool, error)
	out     *bytes.Buffer
	errb    *bytes.Buffer
	log     []string
	dev     func() devuse.History
}

func newRig() *rig {
	r := &rig{ag: &fakeAgent{name: "fake-agent"}, rule: fakeRule{"fake", model.SevMed}, out: &bytes.Buffer{}, errb: &bytes.Buffer{}}
	r.sc = &fakeScanner{name: "fake", provider: "Fakery", creds: []model.Credential{cred("fake", "c1")}, log: &r.log}
	r.confirm = func(p []string) (bool, error) { r.log = append(r.log, "confirm"); return true, nil }
	return r
}

func (r *rig) deps() Deps {
	return Deps{
		Scanners: []scan.Scanner{r.sc}, Agents: []agent.Agent{r.ag}, Rules: []rules.ToolRule{r.rule},
		Dev: r.dev, Env: scan.Env{Getenv: func(string) string { return "" }}, Now: func() time.Time { return now },
		Confirm: func(p []string) (bool, error) { return r.confirm(p) }, Out: r.out, Err: r.errb,
	}
}

func doctor(extra ...func(*Options)) Options {
	o := Options{Command: "doctor", Since: 30 * 24 * time.Hour}
	for _, f := range extra {
		f(&o)
	}
	return o
}

func inventory() Options { return Options{Command: "inventory", Since: 30 * 24 * time.Hour} }

func TestExecuteOfflineNeverResolves(t *testing.T) {
	r := newRig()
	r.sc.resolve = func(context.Context, model.Credential) (*model.Resolution, error) {
		t.Fatal("Resolve called offline")
		return nil, nil
	}
	r.confirm = func([]string) (bool, error) { t.Fatal("Confirm called offline"); return false, nil }
	if got := Execute(context.Background(), doctor(func(o *Options) { o.Offline = true }), r.deps()); got != 0 {
		t.Fatalf("exit %d, err %q", got, r.errb)
	}
}

func TestCollectReturnsReportAsData(t *testing.T) {
	r := newRig()
	rep, err := Collect(context.Background(), doctor(), r.deps())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Command != "doctor" || rep.Offline || rep.SchemaVersion != 1 || len(rep.Credentials) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	c := rep.Credentials[0]
	if c.Resolved == nil || c.Provider != "Fakery" || len(c.Access) != 1 || c.Access[0].Agent != "fake-agent" {
		t.Errorf("credential = %+v", c)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].ID != "fake-agent:fake:c1" || rep.Findings[0].Severity != model.SevMed {
		t.Errorf("findings = %+v", rep.Findings)
	}
	if len(rep.Agents) != 1 || rep.Agents[0] != "fake-agent" || rep.WindowDays != 30 || rep.HistoryDays != 45 {
		t.Errorf("agents/window = %v %d %d", rep.Agents, rep.WindowDays, rep.HistoryDays)
	}
	if strings.Join(r.log, ",") != "confirm,resolve" {
		t.Errorf("order = %v", r.log)
	}

	r = newRig()
	r.confirm = func(p []string) (bool, error) { return false, nil }
	r.sc.resolve = func(context.Context, model.Credential) (*model.Resolution, error) {
		t.Fatal("Resolve after decline")
		return nil, nil
	}
	rep, err = Collect(context.Background(), doctor(), r.deps())
	if err != nil || !rep.Offline || !strings.Contains(strings.Join(rep.Notes, "\n"), "declined") {
		t.Errorf("decline: err %v offline %v notes %v", err, rep.Offline, rep.Notes)
	}

	r = newRig()
	r.confirm = func(p []string) (bool, error) { return false, confirm.ErrNoTerminal }
	rep, err = Collect(context.Background(), doctor(), r.deps())
	if !errors.Is(err, confirm.ErrNoTerminal) || rep.Command != "" || rep.Credentials != nil {
		t.Errorf("no terminal: err %v report %+v", err, rep)
	}
}

func TestCollectConfirmSeesProvidersBeforeResolve(t *testing.T) {
	r := newRig()
	r.sc.provider = "AWS"
	other := &fakeScanner{name: "other", provider: "GitHub", creds: []model.Credential{cred("other", "o1")}, log: &r.log}
	r.rule = fakeRule{"fake", model.SevMed}
	d := r.deps()
	d.Scanners = append(d.Scanners, other)
	d.Rules = append(d.Rules, fakeRule{"other", model.SevMed})
	var got []string
	r.confirm = func(p []string) (bool, error) {
		got = p
		r.log = append(r.log, "confirm")
		return true, nil
	}
	if code := Execute(context.Background(), inventory(), d); code != 0 {
		t.Fatalf("exit %d %q", code, r.errb)
	}
	if strings.Join(got, ",") != "AWS,GitHub" || strings.Join(r.log, ",") != "confirm,resolve,resolve" {
		t.Errorf("providers %v log %v", got, r.log)
	}
}

func TestExecuteDeclineContinuesOffline(t *testing.T) {
	r := newRig()
	r.confirm = func([]string) (bool, error) { return false, nil }
	if code := Execute(context.Background(), inventory(), r.deps()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r.sc.resolved != 0 || !strings.Contains(r.out.String(), "declined") {
		t.Errorf("resolved %d out %q", r.sc.resolved, r.out)
	}
}

func TestExecuteNoTerminalExit2(t *testing.T) {
	r := newRig()
	r.confirm = func([]string) (bool, error) { return false, confirm.ErrNoTerminal }
	if code := Execute(context.Background(), doctor(), r.deps()); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if e := r.errb.String(); !strings.Contains(e, "--yes") || !strings.Contains(e, "--offline") || r.out.Len() != 0 || r.sc.resolved != 0 {
		t.Errorf("err %q out %q resolved %d", e, r.out, r.sc.resolved)
	}
}

func TestExecuteOtherConfirmErrorIsGeneric(t *testing.T) {
	r := newRig()
	r.confirm = func([]string) (bool, error) { return false, errors.New("write failed") }
	if code := Execute(context.Background(), doctor(), r.deps()); code != 2 {
		t.Fatalf("exit %d", code)
	}
	e := r.errb.String()
	if strings.Contains(e, "--yes") || strings.Count(e, "\n") != 1 || r.out.Len() != 0 {
		t.Errorf("err %q out %q", e, r.out)
	}
}

func TestExecuteNoCredentialsSkipsPrompt(t *testing.T) {
	r := newRig()
	r.sc.creds = nil
	r.confirm = func([]string) (bool, error) { t.Fatal("Confirm called"); return false, nil }
	if code := Execute(context.Background(), doctor(), r.deps()); code != 0 || !strings.Contains(r.out.String(), "No credentials found.") {
		t.Errorf("exit %d out %q", code, r.out)
	}
}

func TestExecuteProviderFailureDegrades(t *testing.T) {
	r := newRig()
	r.sc.creds = []model.Credential{cred("fake", "a"), cred("fake", "b"), cred("fake", "c")}
	r.sc.resolve = func(_ context.Context, c model.Credential) (*model.Resolution, error) {
		switch c.ID {
		case "a":
			return nil, errors.New("boom")
		case "b":
			return nil, &scan.SkipError{Reason: "needs login"}
		}
		return &model.Resolution{Identity: "ok"}, nil
	}
	rep, err := Collect(context.Background(), inventory(), r.deps())
	if err != nil {
		t.Fatal(err)
	}
	cs := rep.Credentials
	if len(cs[0].Notes) != 1 || len(cs[1].Notes) != 1 || cs[0].Resolved != nil || cs[1].Resolved != nil || cs[2].Resolved == nil {
		t.Errorf("creds = %+v", cs)
	}
	all := strings.Join(rep.Notes, "\n")
	if !strings.Contains(all, "boom") || !strings.Contains(all, "needs login") {
		t.Errorf("notes = %v", rep.Notes)
	}
	if code := Execute(context.Background(), inventory(), r.deps()); code != 0 {
		t.Errorf("exit %d", code)
	}
}

func TestResolveRunsUnderTimeout(t *testing.T) {
	r := newRig()
	var dl time.Time
	var ok bool
	r.sc.resolve = func(ctx context.Context, _ model.Credential) (*model.Resolution, error) {
		dl, ok = ctx.Deadline()
		return &model.Resolution{}, nil
	}
	if _, err := Collect(context.Background(), inventory(), r.deps()); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(dl); !ok || left <= 15*time.Second || left > 20*time.Second {
		t.Errorf("deadline ok=%v left=%v", ok, left)
	}
}

func TestExecuteDoctorExitCodes(t *testing.T) {
	r := newRig()
	r.rule.sev = model.SevHigh
	if code := Execute(context.Background(), doctor(), r.deps()); code != 1 {
		t.Errorf("high: exit %d", code)
	}
	r = newRig()
	if code := Execute(context.Background(), doctor(), r.deps()); code != 0 {
		t.Errorf("med: exit %d", code)
	}
	r = newRig()
	r.ag.usageErr = errors.New("history exploded")
	if code := Execute(context.Background(), doctor(), r.deps()); code != 2 || r.out.Len() != 0 {
		t.Errorf("usage error: exit %d out %q", code, r.out)
	}
}

func TestExecuteFileBlockedStillRisky(t *testing.T) {
	r := newRig()
	r.rule.sev = model.SevHigh
	r.ag.state = model.AgentState{Access: model.AccessAllowed, FileBlocked: true}
	if code := Execute(context.Background(), doctor(), r.deps()); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(r.out.String(), "credential file blocked, tool still allowed") || !strings.Contains(r.out.String(), "HIGH") {
		t.Errorf("out %q", r.out)
	}
}

func TestExecuteInventoryDoesNotReadUsage(t *testing.T) {
	r := newRig()
	r.ag.forbidUsage = t
	r.dev = func() devuse.History { t.Fatal("Dev called"); return devuse.History{} }
	if code := Execute(context.Background(), inventory(), r.deps()); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestExecuteCancelledContextExit2(t *testing.T) {
	r := newRig()
	ctx, cancel := context.WithCancel(context.Background())
	r.confirm = func([]string) (bool, error) { cancel(); return true, nil }
	if code := Execute(ctx, doctor(), r.deps()); code != 2 || r.sc.resolved != 0 || r.out.Len() != 0 {
		t.Errorf("exit %d resolved %d out %q", code, r.sc.resolved, r.out)
	}
	r = newRig()
	r.confirm = func([]string) (bool, error) { t.Fatal("Confirm after cancel"); return true, nil }
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if code := Execute(ctx, doctor(), r.deps()); code != 2 {
		t.Errorf("pre-cancelled: exit %d", code)
	}
}

func TestExecuteSinceWindowPassed(t *testing.T) {
	r := newRig()
	var since time.Time
	r.ag.since = &since
	o := doctor(func(o *Options) { o.Since = 7 * 24 * time.Hour })
	Execute(context.Background(), o, r.deps())
	if want := now.Add(-7 * 24 * time.Hour); !since.Equal(want) {
		t.Errorf("since = %v, want %v", since, want)
	}
}

func TestExecuteMultipleAgentsAppendStates(t *testing.T) {
	r := newRig()
	d := r.deps()
	d.Agents = append(d.Agents, &fakeAgent{name: "second"})
	rep, err := Collect(context.Background(), inventory(), d)
	if err != nil {
		t.Fatal(err)
	}
	a := rep.Credentials[0].Access
	if len(a) != 2 || a[0].Agent != "fake-agent" || a[1].Agent != "second" {
		t.Errorf("access = %+v", a)
	}
}

func TestCollectNotes(t *testing.T) {
	r := newRig()
	r.ag.unread = 3
	r.ag.posture = agent.Posture{Notes: []string{"settings file x is unreadable"}}
	r.dev = func() devuse.History { return devuse.History{Unread: 2} }
	rep, err := Collect(context.Background(), doctor(), r.deps())
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rep.Notes, "\n")
	for _, want := range []string{"3 agent history", "shell history", "settings file x is unreadable"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q: %v", want, rep.Notes)
		}
	}
	if rep.HistoryUnread != 3 {
		t.Errorf("HistoryUnread = %d", rep.HistoryUnread)
	}
}

func TestCollectKeepsCallerNotesAndDiscoverError(t *testing.T) {
	r := newRig()
	r.sc.creds = nil
	r.sc.discoverErr = errors.New("scan broke")
	d := r.deps()
	d.Notes = []string{"home directory could not be determined"}
	rep, err := Collect(context.Background(), inventory(), d)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rep.Notes, "\n")
	if !strings.Contains(all, "home directory") || !strings.Contains(all, "scan broke") {
		t.Errorf("notes = %v", rep.Notes)
	}
}

func TestStyleColourOnlyOnTerminal(t *testing.T) {
	env := func(m map[string]string) scan.Env { return scan.Env{Getenv: func(k string) string { return m[k] }} }
	cases := []struct {
		tty  bool
		env  map[string]string
		want [2]bool // Color, Fancy
	}{
		{false, nil, [2]bool{false, false}},
		{true, nil, [2]bool{true, true}},
		{true, map[string]string{"NO_COLOR": "1"}, [2]bool{false, true}},
		{true, map[string]string{"TERM": "dumb"}, [2]bool{false, false}},
	}
	for i, c := range cases {
		got := style(Deps{OutIsTTY: c.tty, Env: env(c.env)})
		if got.Color != c.want[0] || got.Fancy != c.want[1] {
			t.Errorf("case %d: %+v", i, got)
		}
	}
}
