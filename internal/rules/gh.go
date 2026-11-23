package rules

import (
	"cmp"
	"regexp"
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

// safeAccount repeats scan/gh's validAccount (the length limit is checked at the use) (duplicated, not exported): the advice line is pasted into a shell.
var safeAccount = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$`)

// tokenShaped repeats scan/gh's tokenShaped (duplicated: no shared package): a token pasted into a name must never be printed.
var tokenShaped = regexp.MustCompile(`(?i)^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)`)

func isPlaceholder(c model.Credential) bool {
	return c.ID == "enterprise" && c.Kind == "env-token" && c.Source == "env"
}

func defaultHost(x Context) string {
	if x.Getenv != nil && x.Getenv("GH_HOST") != "" {
		return strings.ToLower(x.Getenv("GH_HOST")) // scan/gh lower-cases hosts, as gh does
	}
	return "github.com"
}

// hostOf is the host a credential belongs to; credentials without Host (placeholders, old data) use their ID.
func hostOf(c model.Credential) string { return cmp.Or(c.Host, c.ID) }

// inEffect reports whether gh uses this credential: the environment token if there is one for the host,
// otherwise the active stored account. Inactive accounts and tokens shadowed by the environment are not in effect.
// shortcut: history cannot tell which account was active at the time of a past call (gh auth switch, inline GH_TOKEN=...), so every call is counted for the account in effect now; revisit only if gh usage logs ever name the account.
func inEffect(c model.Credential, x Context) bool {
	switch c.Kind {
	case "env-token":
		return true
	case "file-host":
		for _, o := range x.Creds {
			if o.Tool == "gh" && o.Kind == "env-token" && hostOf(o) == hostOf(c) {
				return false
			}
		}
		return true
	}
	return false
}

// ghNotInEffect describes a stored gh account that gh does not use. Used stays empty: its usage is not applicable.
func ghNotInEffect(c model.Credential, x Context) (details, advice []string, ok bool) {
	if c.Tool != "gh" || c.Kind != "file-host-inactive" && c.Kind != "file-host" || inEffect(c, x) {
		return nil, nil, false
	}
	host := model.Sanitize(hostOf(c))
	for _, o := range x.Creds {
		if o.Tool == "gh" && hostOf(o) == hostOf(c) && inEffect(o, x) {
			if o.Kind == "file-host" && o.Identity == "" { // host-only: one of the listed accounts may be the login gh uses
				return []string{"hosts.yml names no active account for " + host + "; gh uses the token stored for the host, which may belong to this account"},
					[]string{"check which GitHub account gh uses: gh auth status --hostname " + host}, true
			}
			details = append(details, "gh uses "+cmp.Or(o.Label, o.ID)+" for "+host)
			break
		}
	}
	if c.Identity == "" { // no account name: logout without --user is ambiguous on a host with several accounts
		return details, []string{"check which GitHub account gh uses: gh auth status --hostname " + host}, true
	}
	if len(c.Identity) > 39 || !safeAccount.MatchString(c.Identity) || tokenShaped.MatchString(c.Identity) { // never print an unsafe name (39 is GitHub's login limit, scan/gh's maxAccount), and never a logout without --user
		return details, []string{"check which GitHub account gh uses: gh auth status --hostname " + host}, true
	}
	cmd := "gh auth logout --hostname " + host + " --user " + c.Identity
	advice = []string{"log out of a GitHub account you do not use: " + cmd}
	return details, advice, true
}

func (GHRule) targets(c model.Credential, x Context) []string {
	if c.Kind == "unknown" || isPlaceholder(c) || !inEffect(c, x) {
		return nil
	}
	if h := hostOf(c); h == defaultHost(x) {
		return []string{h, ""}
	} else {
		return []string{h}
	}
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
		case contains(t, strings.ToLower(call.Target)): // hosts in credentials are lower-cased
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
	if k == nil || c.Kind == "unknown" || isPlaceholder(c) {
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
		Advice:  []string{"replace the token with fewer scopes: https://" + hostOf(c) + "/settings/tokens"},
	}}
}

func (r GHRule) DeveloperUse(c model.Credential, _ AgentUse, x Context) DevUse {
	dated := false
	for _, t := range r.targets(c, x) {
		if u, ok := x.Dev.LookupFold("gh", t); ok {
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
