package rules

import (
	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type DockerRule struct{}

func (DockerRule) Tool() string { return "docker" }

// Attribute: every docker call goes through the one daemon socket the user can reach.
func (DockerRule) Attribute(_ model.Credential, calls []usage.Call, _ Context) ([]usage.Call, int) {
	return calls, 0
}

func (DockerRule) Risks(c model.Credential, _ model.AgentState, _ AgentUse, _ Context) []Risk {
	if c.Kind != "socket" {
		return nil
	}
	return []Risk{{Rule: "docker.socket", Severity: model.SevHigh,
		Headline: "Docker socket is reachable by the agent (equivalent to root on this machine)",
		Short:    "socket reachable", Block: true}}
}

func (DockerRule) DeveloperUse(_ model.Credential, _ AgentUse, x Context) DevUse {
	if u, ok := x.Dev.Lookup("docker", ""); ok && u.Dated && x.Now.Sub(u.Last) <= x.Window {
		return DevUse{DevKnownRecent, "found in dated shell history within the window"}
	}
	return DevUse{DevUnknown, "shell history cannot prove nobody uses it"}
}

func (DockerRule) Revoke(model.Credential, Context) string { return "" }
