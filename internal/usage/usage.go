// Package usage holds what an agent's session history says it actually called.
package usage

import (
	"time"

	"github.com/VSN2015/agentctl/internal/usage/shellparse"
)

// Call is one shell tool use at a point in time.
type Call struct {
	At time.Time
	shellparse.Invocation
}

// MCPCall is one MCP tool use.
type MCPCall struct {
	At           time.Time
	Server, Tool string
}

// Usage is the tool use found in an agent's history within [Since, now].
type Usage struct {
	Agent        string
	Since        time.Time
	HistoryStart time.Time // zero when there is no history
	Shell        []Call
	MCP          []MCPCall
}

// HistoryDays is the whole days from HistoryStart to now; 0 if there is no history.
func (u Usage) HistoryDays(now time.Time) int {
	if u.HistoryStart.IsZero() {
		return 0
	}
	return int(now.Sub(u.HistoryStart) / (24 * time.Hour))
}

// Calls returns the shell calls of one tool.
func (u Usage) Calls(tool string) []Call {
	var out []Call
	for _, c := range u.Shell {
		if c.Tool == tool {
			out = append(out, c)
		}
	}
	return out
}
