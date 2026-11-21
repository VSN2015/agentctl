// Package rules turns credentials, agent access, agent usage and developer use
// into findings. The engine knows no tool names; each tool is one ToolRule.
package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type Context struct {
	Agent       string
	Now         time.Time
	Window      time.Duration
	Offline     bool
	Dev         devuse.History
	Getenv      func(string) string
	HistoryDays int
}

type AgentInput struct {
	Name              string
	Usage             usage.Usage
	UnrestrictedShell bool
	BlockAdvice       func(tool string) string
}

// Risk is one thing a tool rule found. A Risk with Severity SevOK only adds its Details.
type Risk struct {
	Rule     string
	Severity model.Severity
	Headline string
	Details  []string
	Advice   []string
	Block    bool // the agent should be kept away from this credential: the engine adds its block advice
}

type DevState int

const (
	DevKnownRecent DevState = iota
	DevNobody
	DevUnknown
)

type DevUse struct {
	State DevState
	Why   string
}

type ToolRule interface {
	Tool() string
	Attribute(c model.Credential, calls []usage.Call, x Context) (own []usage.Call, unattributed int)
	Risks(c model.Credential, st model.AgentState, use AgentUse, x Context) []Risk // not called when st.Access == "denied"
	DeveloperUse(c model.Credential, use AgentUse, x Context) DevUse
	Revoke(c model.Credential, x Context) string // "" when the tool has none
}

type Input struct {
	Creds   []model.Credential
	Agents  []AgentInput
	Dev     devuse.History
	Getenv  func(string) string
	Now     time.Time
	Window  time.Duration
	Offline bool
}

const (
	advisory     = "Agent deny rules are advisory unless the agent runs in a sandbox."
	revokeIfNone = "If you do not use it either, revoke the credential."
)

// Evaluate returns one finding per (agent, credential), plus one per agent with an unrestricted shell.
func Evaluate(in Input, tools []ToolRule) []model.Finding {
	byTool := map[string]ToolRule{}
	for _, t := range tools {
		byTool[t.Tool()] = t
	}
	out := []model.Finding{}
	for _, a := range in.Agents {
		x := Context{Agent: a.Name, Now: in.Now, Window: in.Window, Offline: in.Offline, Dev: in.Dev,
			Getenv: in.Getenv, HistoryDays: a.Usage.HistoryDays(in.Now)}
		for _, c := range in.Creds {
			out = append(out, evalOne(c, a, byTool[c.Tool], x))
		}
		if a.UnrestrictedShell {
			out = append(out, shellFinding(a.Name))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func evalOne(c model.Credential, a AgentInput, rule ToolRule, x Context) model.Finding {
	st := model.AgentState{Agent: a.Name, Access: model.AccessAsks}
	for _, s := range c.Access {
		if s.Agent == a.Name {
			st = s
		}
	}
	f := model.Finding{ID: a.Name + ":" + c.Tool + ":" + c.ID, Severity: model.SevOK, Agent: a.Name,
		Tool: c.Tool, Subject: c.ID, Access: st.Access, FileBlocked: st.FileBlocked}
	switch {
	case rule == nil:
		f.Headline = "no rules exist for the tool " + c.Tool
		return f
	case st.Access == model.AccessDenied:
		f.Headline = "denied by agent settings"
		return f
	}
	span := windowText(x.Window)
	unreadable := c.ID == "unreadable" && c.Kind == "unknown"

	var use AgentUse
	if unreadable { // placeholder for a store that could not be read: no host or profile to match calls against
		use = AgentUse{State: UseUnattributable, HistoryDays: x.HistoryDays}
	} else {
		own, un := rule.Attribute(c, a.Usage.Calls(c.Tool), x)
		use = agentUse(a.Usage, own, un, x.Window, x.Now)
	}
	risks := rule.Risks(c, st, use, x)
	sort.SliceStable(risks, func(i, j int) bool { return risks[i].Severity > risks[j].Severity })

	needBlock := false
	for _, r := range risks {
		needBlock = needBlock || r.Block
		f.Details = append(f.Details, r.Details...)
		f.Advice = append(f.Advice, r.Advice...)
		if r.Severity == model.SevOK {
			continue
		}
		f.Rules = append(f.Rules, r.Rule)
		if r.Severity > f.Severity {
			f.Severity, f.Headline = r.Severity, r.Headline
		} else if r.Headline != "" {
			f.Details = append(f.Details, r.Headline)
		}
	}

	line := fmt.Sprintf("Agent use, last %s: %s", span, plural(use.Count, "call"))
	headline := ""
	switch {
	case use.State == UseUnattributable:
		line = fmt.Sprintf("Agent use, last %s: cannot be attributed", span)
		headline = fmt.Sprintf("use by %s cannot be attributed", a.Name)
	case use.State == UseUnknown && a.Usage.Unread > 0:
		line = fmt.Sprintf("Agent use: %s in the history that could be read", plural(use.Count, "call"))
		headline = fmt.Sprintf("%s by %s in the history that could be read", plural(use.Count, "call"), a.Name)
	case use.State == UseUnknown:
		line = fmt.Sprintf("Agent use: %s in %s of history", plural(use.Count, "call"), plural(use.HistoryDays, "day"))
		headline = fmt.Sprintf("%s by %s in %s of history", plural(use.Count, "call"), a.Name, plural(use.HistoryDays, "day"))
	}
	if !use.Last.IsZero() && use.State != UseUnattributable {
		line += ", last " + use.Last.Format("2006-01-02")
	}
	f.Details = append(f.Details, line)
	if st.Access == model.AccessAsks {
		f.Details = append(f.Details, "Agent asks first before running it")
	}
	if st.FileBlocked {
		f.Details = append(f.Details, "credential file blocked, tool still allowed")
	}

	usageRule, usageSev := "", model.SevOK
	switch use.State {
	case UseUnused:
		usageRule, usageSev = "usage.unused", model.SevMed
	case UseRare:
		usageRule, usageSev = "usage.rare", model.SevLow
	case UseUnknown:
		f.Details = append(f.Details, plural(use.HistoryDays, "day")+" of history available")
		if a.Usage.Unread > 0 {
			f.Details = append(f.Details, "Some agent history could not be read, so absence of use is not certain")
		}
	case UseUnattributable:
		if unreadable {
			f.Details = append(f.Details, "The credential could not be read, so its use cannot be attributed")
		} else {
			f.Details = append(f.Details, "Some agent calls could not be attributed to this credential")
		}
	}
	if usageSev > model.SevOK {
		f.Rules = append(f.Rules, usageRule)
	}
	if usageSev > f.Severity {
		f.Severity = usageSev
		if usageSev == model.SevMed {
			f.Headline = fmt.Sprintf("not used by %s in the last %s", a.Name, span)
		} else {
			f.Headline = fmt.Sprintf("rarely used by %s (%s in the last %s)", a.Name, plural(use.Count, "call"), span)
		}
	}
	if f.Headline == "" && headline != "" {
		f.Headline = headline
	}
	if f.Headline == "" {
		f.Headline = fmt.Sprintf("used %d times by %s in the last %s", use.Count, a.Name, span)
	}

	if usageSev > model.SevOK {
		adv, revokeOnly := usageAdvice(c, a, rule, use, x)
		if revokeOnly { // nobody uses the key: narrowing or replacing it is moot
			f.Advice = nil
		}
		f.Advice = append(f.Advice, adv...)
	} else if needBlock && a.BlockAdvice != nil { // usageAdvice already carries block advice when it ran
		if block := a.BlockAdvice(c.Tool); block != "" {
			f.Advice = append(f.Advice, block, advisory)
		}
	}
	return f
}

func usageAdvice(c model.Credential, a AgentInput, rule ToolRule, use AgentUse, x Context) (advice []string, revokeOnly bool) {
	dev := rule.DeveloperUse(c, use, x)
	if revoke := rule.Revoke(c, x); dev.State == DevNobody && use.State == UseUnused && revoke != "" {
		return []string{revoke}, true
	}
	var block string
	if a.BlockAdvice != nil {
		block = a.BlockAdvice(c.Tool)
	}
	var out []string
	if block != "" {
		out = append(out, block)
	}
	if dev.State != DevKnownRecent {
		out = append(out, revokeIfNone)
	}
	if block != "" {
		out = append(out, advisory)
	}
	return out, false
}
