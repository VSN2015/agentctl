package cli

import (
	"github.com/OWNER/agentctl/internal/run"
	"github.com/spf13/cobra"
)

type commonFlags struct {
	offline, yes, json bool
	since              string
}

// register defines the shared flags; every subcommand that needs them calls it.
func (f *commonFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.offline, "offline", false, "do not make any network requests")
	fl.StringVar(&f.since, "since", "30d", "look-back window, e.g. 30d, 12h, 1d12h")
	fl.BoolVar(&f.json, "json", false, "write the report as JSON")
	fl.BoolVar(&f.yes, "yes", false, "assume yes for prompts")
}

func (f *commonFlags) options(command string) (run.Options, error) {
	since, err := ParseSince(f.since)
	if err != nil {
		return run.Options{}, err
	}
	return run.Options{Command: command, Offline: f.offline, Yes: f.yes, JSON: f.json, Since: since}, nil
}
