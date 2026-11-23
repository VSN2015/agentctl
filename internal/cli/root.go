// Package cli is the cobra command line; it parses arguments and hands run.Options to an Exec.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// Version is set by -ldflags at release time.
var Version = "dev"

type IO struct {
	In                io.Reader
	Out, Err          io.Writer
	InIsTTY, OutIsTTY bool
	ErrIsTTY          bool
	Getenv            func(string) string
	Home, Cwd         string
	SysRoot           string // "" means /sys; tests point it at a fixture so the host is never consulted
}

// ExitError carries an exit status out of RunE; Msg, if non-empty, is printed to Err.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// Run executes the command line and returns the process exit status.
func Run(args []string, io IO) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return execute(ctx, newRoot(io, defaultExec), args, io)
}

func execute(ctx context.Context, root *cobra.Command, args []string, io IO) int {
	root.SetArgs(args)
	cmd, err := root.ExecuteContextC(ctx)
	var ee *ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		if ee.Msg != "" {
			fmt.Fprintln(io.Err, ee.Msg)
		}
		return ee.Code
	default:
		fmt.Fprintf(io.Err, "agentctl: %v\n%s", err, cmd.UsageString())
		return 2
	}
}

func quiet(cmd *cobra.Command, io IO) {
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(io.Out)
	cmd.SetErr(io.Err)
	cmd.Args = cobra.NoArgs
}

func newPipelineCmd(io IO, exec Exec, name, short string) *cobra.Command {
	var f commonFlags
	cmd := &cobra.Command{
		Use:   name,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := f.options(name)
			if err != nil {
				return err
			}
			if code := exec(cmd.Context(), o, io); code != 0 {
				return &ExitError{Code: code}
			}
			return nil
		},
	}
	quiet(cmd, io)
	f.register(cmd)
	if name == "doctor" {
		cmd.Flags().BoolVar(&f.inventory, "inventory", false, "also list every credential found")
	}
	return cmd
}

func newRoot(io IO, exec Exec) *cobra.Command {
	root := &cobra.Command{
		Use:     "agentctl",
		Short:   "Show what an AI coding agent can reach on this machine",
		Version: Version,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("a subcommand is required")
		},
	}
	quiet(root, io)
	root.CompletionOptions = cobra.CompletionOptions{DisableDefaultCmd: true}
	root.SetVersionTemplate("agentctl {{.Version}}\n")
	root.AddCommand(newInventoryCmd(io, exec), newDoctorCmd(io, exec))
	return root
}
