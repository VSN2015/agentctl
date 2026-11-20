package rules

import (
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type GHRule struct{}

func (GHRule) Tool() string { return "gh" }

// gh sub-command to the scope it needs.
var ghScope = map[string]string{"run": "workflow", "issue": "repo", "repo": "repo", "release": "repo", "pr": "repo", "gist": "gist", "org": "read:org"}

// implies lists what holding a scope also grants.
var implies = map[string][]string{"admin:org": {"read:org", "write:org"}, "repo": {"repo:status"}}

func (GHRule) targets(c model.Credential, x Context) []string {
	if c.Kind == "unknown" || c.ID == "enterprise" {
		return nil
	}
	def := "github.com"
	if x.Getenv != nil && x.Getenv("GH_HOST") != "" {
		def = x.Getenv("GH_HOST")
	}
	if c.ID == def {
		return []string{c.ID, ""}
	}
	return []string{c.ID}
}

func (r GHRule) Attribute(c model.Credential, calls []usage.Call, x Context) ([]usage.Call, int) {
	var own []usage.Call
	t := r.targets(c, x)
	for _, call := range calls {
		if contains(t, call.Target) {
			own = append(own, call)
		}
	}
	return own, 0
}

func (GHRule) Risks(c model.Credential, _ model.AgentState, use AgentUse, _ Context) []Risk {
	k := c.Resolved
	if k == nil || c.Kind == "unknown" {
		return nil
	}
	if !k.ScopesReadable {
		return []Risk{{Severity: model.SevOK, Details: []string{"Token permissions cannot be read (fine-grained token), so unused scopes were not checked"}}}
	}
	if len(use.Calls) == 0 {
		return nil
	}
	var needs []string
	for _, call := range use.Calls {
		s, ok := ghScope[call.Sub]
		if !ok {
			return []Risk{{Severity: model.SevOK, Details: []string{"Scope need cannot be attributed: the agent ran gh commands (such as gh api) that can use any scope, so unused scopes were not checked"}}}
		}
		if !contains(needs, s) {
			needs = append(needs, s)
		}
	}
	var unused []string
	for _, s := range k.Scopes {
		used := false
		for _, n := range needs {
			used = used || s == n || contains(implies[s], n) || contains(implies[n], s)
		}
		if !used {
			unused = append(unused, s)
		}
	}
	if len(unused) == 0 {
		return nil
	}
	return []Risk{{
		Rule: "gh.unused-scopes", Severity: model.SevMed, Headline: "Token has scopes the agent's commands did not need",
		Details: []string{"Scopes: " + strings.Join(k.Scopes, ", "), "Agent's commands needed: " + strings.Join(needs, ", "), "Unused scopes: " + strings.Join(unused, ", ")},
		Advice:  []string{"Replace the token with one limited to the scopes you use at https://" + c.ID + "/settings/tokens"},
	}}
}

func (r GHRule) DeveloperUse(c model.Credential, _ AgentUse, x Context) DevUse {
	dated := false
	for _, t := range r.targets(c, x) {
		if u, ok := x.Dev.Lookup("gh", t); ok {
			if u.Dated && x.Now.Sub(u.Last) <= x.Window {
				return DevUse{DevKnownRecent, "found in dated shell history within the window"}
			}
			dated = dated || !u.Dated
		}
	}
	if dated {
		return DevUse{DevUnknown, "found in shell history, no dates"}
	}
	return DevUse{DevUnknown, "shell history cannot prove nobody uses it"}
}

// Revoke is empty: GitHub exposes no read-only way to tell whether anyone else uses a token.
func (GHRule) Revoke(model.Credential, Context) string { return "" }
