// Package agent defines the single extension point for coding agents; a new agent is one package implementing Agent.
package agent

import (
	"context"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/usage"
)

type Agent interface {
	Name() string                                                             // "claude-code"
	ReadUsage(ctx context.Context, since, now time.Time) (usage.Usage, error) // every project on the machine; Usage.Agent == Name()
	Classify(c model.Credential) model.AgentState                             // Agent == Name(); Access is about the tool only; FileBlocked is separate
	BlockAdvice(tool string) string                                           // agent-specific text for blocking a tool; excludes the advisory sentence (the rules engine adds it)
	Posture() Posture
}

// Posture is the agent's overall permission stance. Notes name unreadable or invalid settings files (path only, never contents).
type Posture struct {
	UnrestrictedShell bool
	Notes             []string
}
