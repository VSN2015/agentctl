package cli

import "github.com/spf13/cobra"

func newDoctorCmd(io IO, exec Exec) *cobra.Command {
	return newPipelineCmd(io, exec, "doctor", "Check this machine for risky agent access")
}
