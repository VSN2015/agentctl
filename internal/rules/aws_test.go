package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

func awsCred(id string, res *model.Resolution) model.Credential {
	return model.Credential{Tool: "aws", ID: id, Source: "file", KeyID: "AKIA****WXYZ", Resolved: res}
}

func ruleNames(rs []Risk) (out []string) {
	for _, r := range rs {
		if r.Rule != "" {
			out = append(out, r.Rule)
		}
	}
	return
}

func TestAWSAdminHigh(t *testing.T) {
	r := AWSRule{}
	got := r.Risks(awsCred("prod", &model.Resolution{AdminChecked: true, Admin: true}), model.AgentState{}, AgentUse{}, Context{})
	if len(got) != 1 || got[0].Rule != "aws.admin" || got[0].Severity != model.SevHigh {
		t.Fatalf("%+v", got)
	}
	if got := r.Risks(awsCred("prod", &model.Resolution{AdminChecked: true}), model.AgentState{}, AgentUse{}, Context{}); len(got) != 0 {
		t.Fatalf("not admin: %+v", got)
	}
	if got := r.Risks(awsCred("prod", nil), model.AgentState{}, AgentUse{}, Context{}); len(got) != 0 {
		t.Fatalf("offline: %+v", got)
	}
}

func TestAWSAdminNotCheckedIsNotNotAdmin(t *testing.T) {
	c := awsCred("prod", &model.Resolution{Admin: true}) // Admin without AdminChecked is meaningless
	got := AWSRule{}.Risks(c, model.AgentState{}, AgentUse{}, Context{})
	if len(ruleNames(got)) != 0 || len(got) != 1 || !strings.Contains(got[0].Details[0], "could not be read") {
		t.Fatalf("%+v", got)
	}
	c.Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
	u := hist(45)
	u.Shell = calls(5, "aws", "", "prod")
	f := run(c, agentIn(u), AWSRule{})
	if f.Severity != model.SevOK || !has(f.Details, "could not be read") || has(f.Details, "not admin") {
		t.Fatalf("%+v", f)
	}
}

func TestAWSLongLivedKeyMed(t *testing.T) {
	c := awsCred("prod", nil)
	c.LongLived = true
	got := AWSRule{}.Risks(c, model.AgentState{}, AgentUse{}, Context{})
	if len(got) != 1 || got[0].Rule != "aws.long-lived-key" || got[0].Severity != model.SevMed {
		t.Fatalf("%+v", got)
	}
	c.LongLived = false
	if got := (AWSRule{}).Risks(c, model.AgentState{}, AgentUse{}, Context{}); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func awsAttr(c model.Credential, targets ...string) int {
	var in []usage.Call
	for _, t := range targets {
		in = append(in, calls(1, "aws", "", t)...)
	}
	own, _ := AWSRule{}.Attribute(c, in, Context{})
	return len(own)
}

func TestAWSAttribution(t *testing.T) {
	env := model.Credential{Tool: "aws", ID: "environment", Source: "env"}
	chain := model.Credential{Tool: "aws", ID: "chain", Source: "chain"}
	if awsAttr(awsCred("default", nil), "", "prod", "default") != 2 {
		t.Error("default takes \"\" and default")
	}
	if awsAttr(env, "", "prod") != 1 || awsAttr(chain, "", "prod") != 1 {
		t.Error("environment and chain take only \"\"")
	}
	if awsAttr(awsCred("prod", nil), "", "prod") != 1 {
		t.Error("prod takes only prod")
	}
	// a file profile named like a reserved word has ID profile:<name>
	if awsAttr(awsCred("profile:environment", nil), "environment", "") != 1 {
		t.Error("profile:environment takes the profile name only")
	}
}

func TestAWSDeveloperUse(t *testing.T) {
	x := func(h ...string) Context { return Context{Now: now, Window: window, Dev: devHistory(t, h...)} }
	unused := AgentUse{State: UseUnused, HistoryDays: 45}
	checked := func(last *time.Time, svc string) model.Credential {
		return awsCred("prod", &model.Resolution{KeyChecked: true, KeyLastUsed: last, KeyLastUsedService: svc})
	}
	recent := now.Add(-48 * time.Hour)
	old := now.Add(-90 * 24 * time.Hour)
	r := AWSRule{}

	if d := r.DeveloperUse(awsCred("prod", nil), unused, x(zshAt(now.Add(-time.Hour), "aws s3 ls --profile prod"))); d.State != DevKnownRecent {
		t.Errorf("dated history: %+v", d)
	}
	if d := r.DeveloperUse(awsCred("prod", nil), unused, x("aws s3 ls --profile prod")); d.State != DevUnknown {
		t.Errorf("undated history: %+v", d)
	}
	if d := r.DeveloperUse(checked(nil, ""), unused, x()); d.State != DevNobody {
		t.Errorf("never used: %+v", d)
	}
	if d := r.DeveloperUse(checked(&old, "s3"), unused, x()); d.State != DevNobody {
		t.Errorf("last use before window: %+v", d)
	}
	if d := r.DeveloperUse(checked(&recent, "s3"), unused, x()); d.State != DevKnownRecent {
		t.Errorf("provider recent: %+v", d)
	}
	for _, svc := range []string{"sts", "iam"} {
		d := r.DeveloperUse(checked(&recent, svc), unused, x())
		if d.State != DevUnknown || !strings.Contains(d.Why, "identity or permission check") {
			t.Errorf("%s last use: %+v", svc, d)
		}
	}
	if d := r.DeveloperUse(awsCred("prod", &model.Resolution{}), unused, x()); d.State != DevUnknown {
		t.Errorf("not checked is not nobody: %+v", d)
	}
	if d := r.DeveloperUse(checked(nil, ""), AgentUse{Count: 5, State: UseUsed}, x()); d.State == DevNobody {
		t.Errorf("agent used: %+v", d)
	}
	// unreadable developer history never pushes toward nobody
	h := x()
	h.Dev = devuse0Unread()
	if d := r.DeveloperUse(awsCred("prod", nil), unused, h); d.State != DevUnknown {
		t.Errorf("unread: %+v", d)
	}
}

func TestAWSRevokeMasksKey(t *testing.T) {
	c := awsCred("prod", nil)
	c.KeyID = "AKIAABCDEFGHIJKLWXYZ"
	s := AWSRule{}.Revoke(c, Context{Window: window})
	if !strings.Contains(s, "AKIA****WXYZ") || !strings.Contains(s, "update-access-key --status Inactive") ||
		!strings.Contains(s, "30 days") || strings.Contains(s, "ABCDEFGHIJKL") || strings.Contains(s, "agentctl fix") {
		t.Fatal(s)
	}
}

// End to end: a never-used key and an unused agent gives revoke-only advice.
func TestAWSEngineRevokeOnly(t *testing.T) {
	c := awsCred("prod", &model.Resolution{AdminChecked: true, KeyChecked: true})
	c.Access = []model.AgentState{{Agent: "claude-code", Access: model.AccessAllowed}}
	f := run(c, agentIn(hist(45)), AWSRule{})
	if len(f.Advice) != 1 || !strings.Contains(f.Advice[0], "Revoke it at AWS") {
		t.Fatalf("%+v", f)
	}
}

func TestAWSEmptyTargetCountsForEnvSelectedProfile(t *testing.T) {
	attr := func(vars map[string]string, id string) int {
		own, _ := AWSRule{}.Attribute(awsCred(id, nil), calls(10, "aws", "", ""),
			Context{Getenv: func(k string) string { return vars[k] }})
		return len(own)
	}
	for _, v := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE"} {
		vars := map[string]string{v: "work"}
		if attr(vars, "work") != 10 || attr(vars, "default") != 10 || attr(vars, "prod") != 0 {
			t.Errorf("%s=work: work=%d default=%d prod=%d", v, attr(vars, "work"), attr(vars, "default"), attr(vars, "prod"))
		}
	}
	if vars := map[string]string{"AWS_PROFILE": "a", "AWS_DEFAULT_PROFILE": "b"}; attr(vars, "a") != 10 || attr(vars, "b") != 0 {
		t.Error("AWS_PROFILE wins over AWS_DEFAULT_PROFILE")
	}
	if attr(nil, "default") != 10 || attr(nil, "work") != 0 || attr(nil, "prod") != 0 {
		t.Error("unset: default only")
	}
}
