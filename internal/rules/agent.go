package rules

import "github.com/VSN2015/agentctl/internal/model"

func shellFinding(agent string) model.Finding {
	return model.Finding{
		ID: agent + ":shell", Rules: []string{"agent.unrestricted-shell"}, Severity: model.SevMed,
		Agent: agent, Tool: "shell", Subject: "shell", Access: model.AccessAllowed, Issue: "unrestricted",
		Headline: "Agent can run any shell command without a restriction",
		Details:  []string{"Any credential on this machine is reachable through the shell, whatever the per-tool rules say"},
		Advice:   []string{"restrict the agent's shell, or use a sandbox"},
	}
}
