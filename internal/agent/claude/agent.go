package claude

import (
	"context"
	"time"

	"github.com/VSN2015/agentctl/internal/agent"
	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

const name = "claude-code"

type claudeAgent struct {
	configDir, home string
	settings        Settings
}

var _ agent.Agent = (*claudeAgent)(nil)

// New loads settings once; goos selects the managed settings paths.
func New(configDir, projectDir, home, goos string) agent.Agent {
	return &claudeAgent{configDir, home, Load(configDir, projectDir, ManagedPaths(goos))}
}

func (a *claudeAgent) Name() string { return name }

func (a *claudeAgent) ReadUsage(ctx context.Context, since, now time.Time) (usage.Usage, error) {
	u, err := readUsage(ctx, a.configDir, since, now)
	u.Agent = name
	return u, err
}

func (a *claudeAgent) Classify(c model.Credential) model.AgentState {
	access, blocked := a.settings.Classify(c, a.home)
	return model.AgentState{Agent: name, Access: access, FileBlocked: blocked}
}

func (a *claudeAgent) BlockAdvice(c model.Credential) string {
	if c.Tool == mcpTool {
		switch seen := mcpSeen(c.ID); {
		case seen == "":
			return ""
		case seen == c.ID:
			return `deny "mcp__` + c.ID + `" in ~/.claude/settings.json`
		default:
			return `deny "mcp__` + seen + `" in ~/.claude/settings.json (this also covers every server Claude Code calls "` + seen + `")`
		}
	}
	return `deny "Bash(` + c.Tool + `:*)" in ~/.claude/settings.json`
}

func (a *claudeAgent) Posture() agent.Posture {
	return agent.Posture{UnrestrictedShell: a.settings.UnrestrictedShell(), Notes: a.settings.Notes}
}
