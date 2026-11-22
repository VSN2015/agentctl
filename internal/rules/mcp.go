package rules

import (
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
	"github.com/VSN2015/agentctl/internal/usage/shellparse"
)

type MCPRule struct{}

func (MCPRule) Tool() string { return "mcp" }

// Attribute ignores the shell calls: MCP use arrives in x.MCP, matched to the server by name.
func (MCPRule) Attribute(c model.Credential, _ []usage.Call, x Context) ([]usage.Call, int) {
	// seen is what the reader records as Server for a call to this server (text before the first "__").
	// shortcut: the reader cannot tell my__server or caf_ calls from calls to a server named my or caf, and never sees an ID starting with __ (empty server is dropped); upgrade when the reader keeps the full tool name.
	if seen, _, _ := strings.Cut(c.ID+"__", "__"); seen != c.ID {
		un := 0
		for _, m := range x.MCP {
			if seen != "" && m.Server == seen {
				un++
			}
		}
		return nil, un
	}
	var own []usage.Call
	for _, m := range x.MCP {
		if m.Server == c.ID {
			own = append(own, usage.Call{At: m.At, Invocation: shellparse.Invocation{Tool: "mcp", Sub: m.Tool, Target: m.Server}})
		}
	}
	return own, 0
}

func (MCPRule) Risks(model.Credential, model.AgentState, AgentUse, Context) []Risk { return nil }

func (MCPRule) DeveloperUse(model.Credential, AgentUse, Context) DevUse {
	return DevUse{DevUnknown, "there is no shell history for MCP servers"}
}

func (MCPRule) Revoke(model.Credential, Context) string { return "" }
