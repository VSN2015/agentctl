// Package run is the pipeline: Collect gathers everything as data, Execute renders it.
// It iterates scanners, agents and rules; it never branches on a tool or agent name.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"github.com/VSN2015/agentctl/internal/agent"
	"github.com/VSN2015/agentctl/internal/confirm"
	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/render"
	"github.com/VSN2015/agentctl/internal/rules"
	"github.com/VSN2015/agentctl/internal/scan"
	"github.com/VSN2015/agentctl/internal/usage"
)

const resolveTimeout = 20 * time.Second

type Deps struct {
	Scanners []scan.Scanner
	Agents   []agent.Agent
	Rules    []rules.ToolRule
	Dev      func() devuse.History // lazily read, doctor only
	Env      scan.Env
	Now      func() time.Time
	Notes    []string                               // notes the caller already knows, added first to the report
	Confirm  func(providers []string) (bool, error) // may return confirm.ErrNoTerminal
	Out, Err io.Writer                              // used by Execute only; Collect never touches them
	OutIsTTY bool
	Progress func(msg string) // nil means none; "" clears the line. Execute and Collect only call it
}

// NewProgress writes progress to w, one rewritten line with no newline; "" clears the line.
func NewProgress(w io.Writer) func(string) {
	return func(msg string) {
		if msg == "" {
			fmt.Fprint(w, "\r\x1b[2K")
			return
		}
		fmt.Fprint(w, "\r\x1b[2Kagentctl: "+model.Sanitize(msg)+"…") // labels come from files
	}
}

func (d Deps) progress(msg string) {
	if d.Progress != nil {
		d.Progress(msg)
	}
}

// Collect gathers everything and returns it as data: no printing, no exit status.
func Collect(ctx context.Context, o Options, d Deps) (render.Report, error) {
	now := d.Now()
	rep := render.Report{SchemaVersion: 1, GeneratedAt: now, Command: o.Command, Offline: o.Offline,
		WindowDays: int(o.Since / (24 * time.Hour)), WindowHours: rules.WindowHours(o.Since), Agents: []string{}, Notes: append([]string{}, d.Notes...)}

	d.progress("finding credentials")
	creds, owners, providers := discover(d, &rep)
	if !o.Offline && len(providers) > 0 {
		if err := ctx.Err(); err != nil {
			return render.Report{}, err
		}
		d.progress("") // the prompt must not share a line with progress
		ok, err := d.Confirm(providers)
		if cerr := ctx.Err(); cerr != nil { // Ctrl-C at the prompt must not read as "no"
			return render.Report{}, cerr
		}
		if err != nil {
			if errors.Is(err, confirm.ErrNoTerminal) {
				return render.Report{}, err
			}
			return render.Report{}, fmt.Errorf("online confirmation failed: %w", err)
		}
		if !ok {
			rep.Offline = true
			rep.Notes = append(rep.Notes, "online checks were declined; showing only what the files show")
		}
	}
	if !rep.Offline && len(creds) > 0 {
		if err := resolveAll(ctx, d, creds, owners, &rep); err != nil {
			return render.Report{}, err
		}
	}
	for _, a := range d.Agents {
		rep.Agents = append(rep.Agents, a.Name())
		for i := range creds {
			creds[i].Access = append(creds[i].Access, a.Classify(creds[i]))
		}
		rep.Notes = append(rep.Notes, a.Posture().Notes...)
	}
	rep.Credentials = creds
	if o.Command == "doctor" {
		if err := evaluate(ctx, o, d, now, &rep); err != nil {
			return render.Report{}, err
		}
	}
	return rep, nil
}

// discover runs Discover on every scanner; owners[i] is the scanner that found creds[i].
func discover(d Deps, rep *render.Report) (creds []model.Credential, owners []scan.Scanner, providers []string) {
	creds = []model.Credential{}
	seen := map[string]bool{}
	for _, sc := range d.Scanners {
		found, err := sc.Discover(d.Env)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("%s scan failed: %v", sc.Provider(), err))
		}
		for _, c := range found {
			c.Provider = sc.Provider()
			for _, n := range c.Notes {
				addNote(rep, c.Label+": "+n)
			}
			creds, owners = append(creds, c), append(owners, sc)
			if !seen[c.Provider] {
				seen[c.Provider] = true
				providers = append(providers, c.Provider)
			}
		}
	}
	return creds, owners, providers
}

// addNote adds a line to the report once; scanners may share one note across credentials.
func addNote(rep *render.Report, line string) {
	if !slices.Contains(rep.Notes, line) {
		rep.Notes = append(rep.Notes, line)
	}
}

func resolveAll(ctx context.Context, d Deps, creds []model.Credential, owners []scan.Scanner, rep *render.Report) error {
	for i := range creds {
		if err := ctx.Err(); err != nil {
			return err
		}
		c := &creds[i]
		d.progress(fmt.Sprintf("checking %s %s (%d/%d)", c.Provider, c.Label, i+1, len(creds)))
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		res, err := owners[i].Resolve(rctx, *c)
		cancel()
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err != nil:
			note := "online check failed: " + err.Error()
			var skip *scan.SkipError
			if errors.As(err, &skip) {
				note = "online check skipped: " + err.Error()
			}
			c.Notes = append(slices.Clip(c.Notes), note)
			addNote(rep, c.Label+": "+note)
		default:
			c.Resolved = res
		}
		if res != nil { // a failed Resolve may still return notes (such as where the call went)
			for _, n := range res.Notes {
				c.Notes = append(slices.Clip(c.Notes), n)
				addNote(rep, c.Label+": "+n)
			}
		}
	}
	return nil
}

func evaluate(ctx context.Context, o Options, d Deps, now time.Time, rep *render.Report) error {
	since := now.Add(-o.Since)
	in := rules.Input{Creds: rep.Credentials, Getenv: d.Env.Getenv, Now: now, Window: o.Since, Offline: rep.Offline}
	d.progress("reading agent history")
	unread := 0
	noHistory, shortDays := false, math.MaxInt
	for _, a := range d.Agents {
		u, err := a.ReadUsage(ctx, since, now)
		if err != nil {
			return fmt.Errorf("reading %s history: %w", a.Name(), err)
		}
		unread += u.Unread
		rep.HistoryDays = max(rep.HistoryDays, u.HistoryDays(now))
		in.Agents = append(in.Agents, agentInput(a, u))
		switch {
		case u.HistoryStart.IsZero():
			noHistory = true
		case now.Sub(u.HistoryStart) < o.Since:
			shortDays = min(shortDays, u.HistoryDays(now))
		}
	}
	if d.Dev != nil {
		d.progress("reading shell history")
		in.Dev = d.Dev()
	}
	if noHistory {
		rep.Notes = append(rep.Notes, `no agent history was found, so "?" marks counts that could not be confirmed`)
	} else if shortDays != math.MaxInt {
		unit := "days"
		if shortDays == 1 {
			unit = "day"
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf(`agent history covers %d %s, less than the window, so "?" marks counts that may be incomplete`, shortDays, unit))
	}
	if unread > 0 {
		rep.HistoryUnread = unread
		noun := "files"
		if unread == 1 {
			noun = "file"
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d agent history %s could not be read, so absence of use is not certain", unread, noun))
	}
	if in.Dev.Unread > 0 {
		rep.Notes = append(rep.Notes, "some shell history could not be read, so your own use may be undercounted")
	}
	rep.Findings = rules.Evaluate(in, d.Rules)
	return nil
}

func agentInput(a agent.Agent, u usage.Usage) rules.AgentInput {
	return rules.AgentInput{Name: a.Name(), Usage: u, UnrestrictedShell: a.Posture().UnrestrictedShell, BlockAdvice: a.BlockAdvice}
}

// Execute is Collect, then render, then an exit status: 0, 1 (doctor found a HIGH finding) or 2.
func Execute(ctx context.Context, o Options, d Deps) int {
	rep, err := Collect(ctx, o, d)
	d.progress("") // nothing may stay on screen or precede an error line
	if err != nil {
		switch {
		case errors.Is(err, confirm.ErrNoTerminal):
			fmt.Fprintln(d.Err, "agentctl: no terminal to ask on; pass --yes to allow the online checks or --offline to stay local")
		case ctx.Err() != nil:
			fmt.Fprintln(d.Err, "agentctl: cancelled")
		default:
			fmt.Fprintf(d.Err, "agentctl: %v\n", err)
		}
		return 2
	}
	if o.JSON {
		err = render.JSON(d.Out, rep)
	} else {
		err = render.Text(d.Out, rep, style(d))
	}
	if err != nil {
		fmt.Fprintf(d.Err, "agentctl: writing the report failed: %v\n", err)
		return 2
	}
	if o.Command == "doctor" {
		for _, f := range rep.Findings {
			if f.Severity == model.SevHigh {
				return 1
			}
		}
	}
	return 0
}

// style is fancy on a terminal that is not dumb, and coloured unless NO_COLOR is set.
func style(d Deps) render.Style {
	fancy := d.OutIsTTY && d.Env.Getenv("TERM") != "dumb"
	return render.Style{Fancy: fancy, Color: fancy && d.Env.Getenv("NO_COLOR") == ""}
}
