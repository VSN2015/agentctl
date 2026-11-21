package rules

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type AWSRule struct{}

func (AWSRule) Tool() string { return "aws" }

// targets are the shell-invocation targets that belong to c: its profile name, plus
// "" for the default profile, the profile the environment selects, the environment and the chain.
// A call with no profile may be the agent's own AWS_PROFILE or the default; both lean toward "used".
func (AWSRule) targets(c model.Credential, x Context) []string {
	if c.Source != "file" {
		return []string{""}
	}
	p := strings.TrimPrefix(c.ID, "profile:") // reserved words are stored as profile:<name>
	if p == "default" || (x.Getenv != nil && p == cmp.Or(x.Getenv("AWS_PROFILE"), x.Getenv("AWS_DEFAULT_PROFILE"))) {
		return []string{p, ""}
	}
	return []string{p}
}

func (r AWSRule) Attribute(c model.Credential, calls []usage.Call, x Context) ([]usage.Call, int) {
	var own []usage.Call
	for _, call := range calls {
		if contains(r.targets(c, x), call.Target) {
			own = append(own, call)
		}
	}
	return own, 0
}

func contains(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

func (AWSRule) Risks(c model.Credential, _ model.AgentState, _ AgentUse, _ Context) []Risk {
	var out []Risk
	if r := c.Resolved; r != nil {
		switch {
		case r.AdminChecked && r.Admin:
			d := []string{}
			if r.AdminWhy != "" {
				d = append(d, r.AdminWhy)
			}
			out = append(out, Risk{Rule: "aws.admin", Severity: model.SevHigh, Headline: "Credential has administrator access", Short: "admin", Details: d,
				Advice: []string{"give the agent a least-privilege profile, or block it from AWS"},
				Block:  true})
		case !r.AdminChecked:
			out = append(out, Risk{Severity: model.SevOK, Short: "admin not checked", Details: []string{"Permissions could not be read, so administrator access was not checked"}})
		}
	}
	if c.LongLived {
		out = append(out, Risk{Rule: "aws.long-lived-key", Severity: model.SevMed, Headline: "Long-lived access key that does not expire", Short: "long-lived key",
			Advice: []string{"replace the long-lived key with short-lived credentials (aws sso login, or an assumed role)"}})
	}
	return out
}

func (r AWSRule) DeveloperUse(c model.Credential, use AgentUse, x Context) DevUse {
	dated := false
	for _, t := range r.targets(c, x) {
		if u, ok := x.Dev.Lookup("aws", t); ok {
			if u.Dated && x.Now.Sub(u.Last) <= x.Window {
				return DevUse{DevKnownRecent, "found in dated shell history within the window"}
			}
			dated = dated || !u.Dated
		}
	}
	if k := c.Resolved; k != nil && k.KeyChecked {
		switch {
		case k.KeyLastUsed != nil && x.Now.Sub(*k.KeyLastUsed) <= x.Window:
			if k.KeyLastUsedService == "sts" || k.KeyLastUsedService == "iam" {
				return DevUse{DevUnknown, "the key's last use was an identity or permission check, possibly this tool"}
			}
			return DevUse{DevKnownRecent, "AWS reports the key was used within the window"}
		case use.Count == 0:
			return DevUse{DevNobody, "AWS reports no use of the key within the window"}
		}
	}
	if dated {
		return DevUse{DevUnknown, "found in shell history, no dates"}
	}
	return DevUse{DevUnknown, "shell history cannot prove nobody uses it"}
}

func (AWSRule) Revoke(c model.Credential, x Context) string {
	if c.KeyID == "" {
		return ""
	}
	return fmt.Sprintf(`revoke key %s: no use in the last %s per AWS (aws iam update-access-key --status Inactive)`,
		model.MaskKeyID(c.KeyID), WindowText(x.Window))
}
