// Package registry is the only place that lists scanners, tool rules and agents.
// Adding a tool or an agent is a new package plus one line here.
package registry

import (
	"path/filepath"

	"github.com/VSN2015/agentctl/internal/agent"
	"github.com/VSN2015/agentctl/internal/agent/claude"
	"github.com/VSN2015/agentctl/internal/rules"
	"github.com/VSN2015/agentctl/internal/scan"
	"github.com/VSN2015/agentctl/internal/scan/aws"
	"github.com/VSN2015/agentctl/internal/scan/docker"
	"github.com/VSN2015/agentctl/internal/scan/gh"
	"github.com/VSN2015/agentctl/internal/scan/kubectl"
)

// Scanners builds the scanners; it makes no network call and reads no credential.
func Scanners(r scan.Runner) []scan.Scanner {
	return []scan.Scanner{aws.New(aws.NewSDK()), gh.New(r), docker.New(), kubectl.New()}
}

func ToolRules() []rules.ToolRule {
	return []rules.ToolRule{rules.AWSRule{}, rules.GHRule{}, rules.DockerRule{}, rules.KubectlRule{}}
}

type AgentParams struct {
	Getenv          func(string) string
	Home, Cwd, GOOS string
}

// Agents builds the agents. An agent whose config directory cannot be
// determined (no override and no home) is left out rather than guessed.
func Agents(p AgentParams) []agent.Agent {
	dir := p.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		if p.Home == "" {
			return nil
		}
		dir = filepath.Join(p.Home, ".claude")
	}
	return []agent.Agent{claude.New(dir, p.Cwd, p.Home, p.GOOS)}
}
