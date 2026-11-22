package rules

import (
	"strconv"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
)

func dockerCred(kind string) model.Credential {
	c := cred(model.AccessAllowed, false)
	c.Tool, c.Kind = "docker", kind
	return c
}

func TestDockerRisks(t *testing.T) {
	rs := DockerRule{}.Risks(dockerCred("socket"), model.AgentState{}, AgentUse{}, Context{})
	if len(rs) != 1 || rs[0].Rule != "docker.socket" || rs[0].Severity != model.SevHigh || !rs[0].Block ||
		rs[0].Short != "socket reachable" {
		t.Fatalf("%+v", rs)
	}
	if rs := (DockerRule{}).Risks(dockerCred("socket-unreachable"), model.AgentState{}, AgentUse{}, Context{}); len(rs) != 0 {
		t.Fatalf("unreachable: %+v", rs)
	}
}

func TestDockerAttributeAll(t *testing.T) {
	own, un := DockerRule{}.Attribute(dockerCred("socket"), calls(3, "docker", "", ""), Context{})
	if len(own) != 3 || un != 0 {
		t.Fatalf("own %d un %d", len(own), un)
	}
}

func TestDockerDeveloperUse(t *testing.T) {
	x := Context{Now: now, Window: window}
	x.Dev = devHistory(t, ": "+strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)+":0;docker ps")
	if u := (DockerRule{}).DeveloperUse(dockerCred("socket"), AgentUse{}, x); u.State != DevKnownRecent {
		t.Errorf("recent: %+v", u)
	}
	x.Dev = devHistory(t, "")
	if u := (DockerRule{}).DeveloperUse(dockerCred("socket"), AgentUse{}, x); u.State != DevUnknown {
		t.Errorf("empty: %+v", u)
	}
}

func TestDockerEvaluate(t *testing.T) {
	f := run(dockerCred("socket"), agentIn(hist(45)), DockerRule{})
	if f.Severity != model.SevHigh || !has(f.Rules, "docker.socket") || !has(f.Rules, "usage.unused") || !has(f.Advice, "block docker") {
		t.Fatalf("%+v", f)
	}
	c := dockerCred("socket")
	c.Access[0].Access = model.AccessDenied
	f = run(c, agentIn(hist(45)), DockerRule{})
	if f.Severity != model.SevOK || f.Headline != "denied by agent settings" {
		t.Fatalf("denied: %+v", f)
	}
}
