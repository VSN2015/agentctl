package cli

import "github.com/spf13/cobra"

func newInventoryCmd(io IO, exec Exec) *cobra.Command {
	return newPipelineCmd(io, exec, "inventory", "List what the agent can reach on this machine")
}
