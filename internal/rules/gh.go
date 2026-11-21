package rules

import (
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type GHRule struct{}

func (GHRule) Tool() string { return "gh" }

// gh sub-command to the scope it needs.
// gh run needs repo as well: reading Actions runs of a private repository needs it.
var ghScope = map[string][]string{"run": {"repo", "workflow"}, "issue": {"repo"}, "repo": {"repo"}, "release": {"repo"}, "pr": {"repo"}, "gist": {"gist"}, "org": {"read:org"}}

// implies lists what holding a scope also grants.
var implies = map[string][]string{"admin:org": {"read:org", "write:org"}, "repo": {"repo:status", "public_repo", "repo_deployment", "repo:invite", "security_events"}}

func isPlaceholder(c model.Credential) bool {
	return c.ID == "enterprise" && c.Kind == "env-token" && c.Source == "env"
}

func defaultHost(x Context) string {
	if x.Getenv != nil && x.Getenv("GH_HOST") != "" {
		return x.Getenv("GH_HOST")
	}
	return "github.com"
}

func (GHRule) targets(c model.Credential, x Context) []string {
	if c.Kind == "unknown" || c.ID == "enterprise" {
		return nil
	}
	if c.ID == defaultHost(x) {
		return []string{c.ID, ""}
	}
	return []string{c.ID}
}

// Attribute: gh picks the host of repo commands from the git remote, so a call that
// names no host can belong to any host but the default one; for those it is unattributable.
// The enterprise placeholder's host is unknown, so every call may be its own.
func (r GHRule) Attribute(c model.Credential, calls []usage.Call, x Context) ([]usage.Call, int) {
	if isPlaceholder(c) {
		return nil, len(calls)
	}
	var own []usage.Call
	un := 0
	t := r.targets(c, x)
	for _, call := range calls {
		switch {
		case contains(t, call.Target):
			own = append(own, call)
		case call.Target == "" && len(t) > 0:
			un++
		}
	}
	return own, un
}

const scopeUnattributable = "Scope need cannot be attributed: the agent ran gh commands (such as gh api) that can use any scope, so unused scopes were not checked"

func (GHRule) Risks(c model.Credential, _ model.AgentState, use AgentUse, _ Context) []Risk {
	k := c.Resolved
	if k == nil || c.Kind == "unknown" || c.ID == "enterprise" {
		return nil
	}
	if !k.ScopesReadable {
		return []Risk{{Severity: model.SevOK, Short: "scopes not checked", Details: []string{"Token permissions cannot be read (fine-grained token), so unused scopes were not checked"}}}
	}
	if len(use.Calls) == 0 {
		return nil
	}
	if use.Unattributed > 0 {
		return []Risk{{Severity: model.SevOK, Short: "scopes not checked", Details: []string{scopeUnattributable}}}
	}
	var needs []string
	for _, call := range use.Calls {
		ss, ok := ghScope[call.Sub]
		if !ok {
			return []Risk{{Severity: model.SevOK, Short: "scopes not checked", Details: []string{scopeUnattributable}}}
		}
		for _, s := range ss {
			if !contains(needs, s) {
				needs = append(needs, s)
			}
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
		Rule: "gh.unused-scopes", Severity: model.SevMed, Headline: "Token has scopes the agent's commands did not need", Short: "extra scopes",
		Details: []string{"Scopes: " + strings.Join(k.Scopes, ", "), "Agent's commands needed: " + strings.Join(needs, ", "), "Unused scopes: " + strings.Join(unused, ", ")},
		Advice:  []string{"replace the token with fewer scopes: https://" + c.ID + "/settings/tokens"},
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
