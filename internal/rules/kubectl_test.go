package rules

import (
	"strconv"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

func kubeCred(id, kind string) model.Credential {
	c := cred(model.AccessAllowed, false)
	c.Tool, c.ID, c.Kind = "kubectl", id, kind
	return c
}

func kubeUsage(days int, cs ...[]usage.Call) usage.Usage {
	u := hist(days)
	for _, c := range cs {
		u.Shell = append(u.Shell, c...)
	}
	return u
}

func TestKubectlAttribute(t *testing.T) {
	cs := append(append(calls(2, "kubectl", "", "prod"), calls(1, "kubectl", "", "dev")...), calls(3, "kubectl", "", "")...)
	for _, c := range []struct {
		id, kind  string
		own, unat int
	}{{"prod", "context", 2, 3}, {"dev", "context", 1, 3}, {"serviceaccount:in-cluster", "serviceaccount", 3, 0}} {
		own, un := KubectlRule{}.Attribute(kubeCred(c.id, c.kind), cs, Context{})
		if len(own) != c.own || un != c.unat {
			t.Errorf("%s: own %d un %d", c.id, len(own), un)
		}
	}
}

func TestKubectlSpecCases(t *testing.T) {
	r := KubectlRule{}
	dev, prod := kubeCred("dev", "context"), kubeCred("production", "production-context")

	f := run(dev, agentIn(hist(45)), r)
	if len(f.Rules) != 1 || f.Rules[0] != "usage.unused" || f.Severity != model.SevMed {
		t.Errorf("a dev: %+v", f)
	}
	f = run(prod, agentIn(hist(45)), r)
	if !has(f.Rules, "kubectl.production-context") || !has(f.Rules, "usage.unused") {
		t.Errorf("a prod: %+v", f)
	}

	u := kubeUsage(45, calls(4, "kubectl", "", ""))
	const d4 = "Agent ran kubectl 4 times without naming a context"
	f = run(dev, agentIn(u), r)
	if f.Used != "?" || has(f.Rules, "usage.unused") || !has(f.Details, d4) {
		t.Errorf("b dev: %+v", f)
	}
	f = run(prod, agentIn(u), r)
	if !has(f.Rules, "kubectl.production-context") || !has(f.Details, d4) {
		t.Errorf("b prod: %+v", f)
	}

	u = kubeUsage(45, calls(3, "kubectl", "", "dev"))
	f = run(dev, agentIn(u), r)
	if f.Severity != model.SevOK || f.Used != "3" {
		t.Errorf("c dev: %+v", f)
	}
	if f = run(prod, agentIn(u), r); f.Severity != model.SevMed {
		t.Errorf("c prod: %+v", f)
	}

	d := kubeCred("production", "production-context")
	d.Access[0].Access = model.AccessDenied
	if f = run(d, agentIn(hist(45)), r); f.Severity != model.SevOK || len(f.Rules) != 0 {
		t.Errorf("d: %+v", f)
	}

	f = run(dev, agentIn(kubeUsage(45, calls(1, "kubectl", "", ""))), r)
	if !has(f.Details, "Agent ran kubectl 1 time without naming a context") {
		t.Errorf("e: %+v", f)
	}
}

func TestKubectlDeveloperUse(t *testing.T) {
	x := Context{Now: now, Window: window}
	recent := zshAt(now.Add(-time.Hour), "kubectl --context prod get pods")
	x.Dev = devHistory(t, recent)
	if u := (KubectlRule{}).DeveloperUse(kubeCred("prod", "context"), AgentUse{}, x); u.State != DevKnownRecent {
		t.Errorf("prod: %+v", u)
	}
	if u := (KubectlRule{}).DeveloperUse(kubeCred("dev", "context"), AgentUse{}, x); u.State != DevUnknown {
		t.Errorf("dev: %+v", u)
	}
	x.Dev = devHistory(t, "kubectl --context prod get pods", zshAt(now.Add(-time.Hour), "kubectl get pods"))
	for _, id := range []string{"prod", "dev"} {
		if u := (KubectlRule{}).DeveloperUse(kubeCred(id, "context"), AgentUse{}, x); u.State != DevUnknown {
			t.Errorf("%s undated/unnamed: %+v", id, u)
		}
	}
	_ = strconv.Itoa
}
