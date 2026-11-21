package cli

import (
	"context"
	"runtime"
	"time"

	"github.com/VSN2015/agentctl/internal/confirm"
	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/registry"
	"github.com/VSN2015/agentctl/internal/run"
	"github.com/VSN2015/agentctl/internal/scan"
)

// Exec is the pipeline seam; it returns the exit status 0, 1 or 2.
type Exec func(ctx context.Context, o run.Options, io IO) int

var defaultExec Exec = func(ctx context.Context, o run.Options, io IO) int {
	return run.Execute(ctx, o, buildDeps(ctx, o, io))
}

// buildDeps wires the registry, the real clock and the prompt into run.Deps. It makes no network call.
func buildDeps(ctx context.Context, o run.Options, io IO) run.Deps {
	d := run.Deps{
		Scanners: registry.Scanners(scan.ExecRunner{}),
		Rules:    registry.ToolRules(),
		Agents:   registry.Agents(registry.AgentParams{Getenv: io.Getenv, Home: io.Home, Cwd: io.Cwd, GOOS: runtime.GOOS}),
		Env:      scan.Env{Home: io.Home, Getenv: io.Getenv},
		Now:      time.Now,
		Confirm: func(p []string) (bool, error) {
			return cancellable(ctx, func() (bool, error) {
				return confirm.Online(io.In, io.Err, io.InIsTTY, o.Offline, o.Yes, p)
			})
		},
		Out: io.Out, Err: io.Err, OutIsTTY: io.OutIsTTY,
	}
	if io.ErrIsTTY && io.Getenv("TERM") != "dumb" {
		d.Progress = run.NewProgress(io.Err)
	}
	if io.Home == "" {
		// An empty home would make devuse read history files from the current directory.
		d.Notes = []string{"the home directory could not be determined, so shell history and agent settings under it were not read"}
		d.Dev = func() devuse.History { return devuse.History{} }
	} else {
		d.Dev = func() devuse.History { return devuse.Read(io.Home, io.Getenv) }
	}
	return d
}

// cancellable returns ctx.Err() as soon as ctx is done, even while f is blocked reading the
// terminal. The blocked read is left behind; the process is about to exit, so that is acceptable.
func cancellable(ctx context.Context, f func() (bool, error)) (bool, error) {
	type result struct {
		ok  bool
		err error
	}
	ch := make(chan result, 1)
	go func() { ok, err := f(); ch <- result{ok, err} }()
	select {
	case r := <-ch:
		return r.ok, r.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
