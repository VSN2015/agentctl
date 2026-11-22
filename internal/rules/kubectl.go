package rules

import (
	"fmt"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type KubectlRule struct{}

func (KubectlRule) Tool() string { return "kubectl" }

// Attribute: a call belongs to the context it names; a call naming none might use any context.
// The in-cluster service account is what an unnamed call uses inside a pod.
func (KubectlRule) Attribute(c model.Credential, calls []usage.Call, _ Context) ([]usage.Call, int) {
	var own []usage.Call
	unnamed := 0
	for _, call := range calls {
		switch {
		case call.Target == "":
			unnamed++
			if c.Kind == "serviceaccount" {
				own = append(own, call)
			}
		case call.Target == c.ID:
			own = append(own, call)
		}
	}
	if c.Kind == "serviceaccount" {
		return own, 0
	}
	return own, unnamed
}

func (KubectlRule) Risks(c model.Credential, _ model.AgentState, use AgentUse, _ Context) []Risk {
	var out []Risk
	if c.Kind == "production-context" {
		out = append(out, Risk{Rule: "kubectl.production-context", Severity: model.SevMed,
			Headline: "Production Kubernetes context is reachable by the agent", Short: "production", Block: true})
	}
	if c.Kind != "serviceaccount" && use.Unattributed > 0 {
		out = append(out, Risk{Severity: model.SevOK,
			Details: []string{fmt.Sprintf("Agent ran kubectl %s without naming a context", plural(use.Unattributed, "time"))}})
	}
	return out
}

func (KubectlRule) DeveloperUse(c model.Credential, _ AgentUse, x Context) DevUse {
	if u, ok := x.Dev.Lookup("kubectl", c.ID); ok && u.Dated && x.Now.Sub(u.Last) <= x.Window {
		return DevUse{DevKnownRecent, "found in dated shell history within the window"}
	}
	return DevUse{DevUnknown, "shell history cannot prove nobody uses it"}
}

func (KubectlRule) Revoke(model.Credential, Context) string { return "" }
