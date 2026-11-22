package rules

import (
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

func mcpCalls(n int, server, tool string) []usage.MCPCall {
	var out []usage.MCPCall
	for i := 0; i < n; i++ {
		out = append(out, usage.MCPCall{At: now.Add(-time.Duration(i+1) * time.Hour), Server: server, Tool: tool})
	}
	return out
}

func mcpCred(id string) model.Credential { return model.Credential{Tool: "mcp", ID: id} }

func TestMCPAttribute(t *testing.T) {
	x := Context{MCP: append(mcpCalls(3, "filesystem", "read"), mcpCalls(1, "other", "read")...)}
	own, un := MCPRule{}.Attribute(mcpCred("filesystem"), nil, x)
	if len(own) != 3 || un != 0 {
		t.Fatalf("own=%d un=%d", len(own), un)
	}
	if i := own[0].Invocation; i.Tool != "mcp" || i.Sub != "read" || i.Target != "filesystem" {
		t.Fatalf("invocation %+v", i)
	}
}

func TestMCPEvaluate(t *testing.T) {
	with := func(days int, m []usage.MCPCall) AgentInput {
		u := hist(days)
		u.MCP = m
		return agentIn(u)
	}
	c := mcpCred("filesystem")
	f := run(c, with(45, nil), MCPRule{})
	if f.Severity != model.SevMed || len(f.Rules) != 1 || f.Rules[0] != "usage.unused" {
		t.Fatalf("unused: %v %v", f.Severity, f.Rules)
	}
	if f := run(c, with(45, mcpCalls(1, "filesystem", "read")), MCPRule{}); f.Severity != model.SevLow {
		t.Fatalf("one call: %v", f.Severity)
	}
	f = run(c, with(45, mcpCalls(212, "filesystem", "read")), MCPRule{})
	if f.Severity != model.SevOK || f.Used != "212" || f.Headline != "used 212 times by claude-code in the last 30 days" {
		t.Fatalf("used: %v %q %q", f.Severity, f.Used, f.Headline)
	}
	f = run(c, with(10, nil), MCPRule{})
	if f.Used != "0?" || has(f.Rules, "usage.unused") {
		t.Fatalf("short history: %q %v", f.Used, f.Rules)
	}
	f = run(c, with(45, mcpCalls(5, "other", "read")), MCPRule{})
	if f.Used != "0" {
		t.Fatalf("other server: %q", f.Used)
	}
}
