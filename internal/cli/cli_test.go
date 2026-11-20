package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/run"
	"github.com/spf13/cobra"
)

type fake struct {
	calls  []run.Options
	status int
}

func (f *fake) exec(_ context.Context, o run.Options, _ IO) int {
	f.calls = append(f.calls, o)
	return f.status
}

func newIO() (IO, *bytes.Buffer, *bytes.Buffer) {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	return IO{In: strings.NewReader(""), Out: out, Err: errb, Getenv: func(string) string { return "" }}, out, errb
}

func drive(f *fake, args ...string) (int, *bytes.Buffer, *bytes.Buffer) {
	io, out, errb := newIO()
	return execute(context.Background(), newRoot(io, f.exec), args, io), out, errb
}

func TestOptionsMapping(t *testing.T) {
	f := &fake{}
	drive(f, "doctor")
	drive(f, "inventory", "--offline", "--json", "--yes", "--since", "7d")
	if len(f.calls) != 2 {
		t.Fatalf("calls = %d", len(f.calls))
	}
	if want := (run.Options{Command: "doctor", Since: 720 * time.Hour}); f.calls[0] != want {
		t.Errorf("doctor = %+v, want %+v", f.calls[0], want)
	}
	want := run.Options{Command: "inventory", Offline: true, Yes: true, JSON: true, Since: 168 * time.Hour}
	if f.calls[1] != want {
		t.Errorf("inventory = %+v, want %+v", f.calls[1], want)
	}
}

func TestExecStatusPassesThroughUntouched(t *testing.T) {
	for _, s := range []int{0, 1, 2} {
		f := &fake{status: s}
		got, out, errb := drive(f, "doctor", "--json")
		if got != s || out.Len() != 0 || errb.Len() != 0 {
			t.Errorf("status %d: got %d out=%q err=%q", s, got, out, errb)
		}
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"doctor", "--nope"}, {"doctor", "extra"},
		{"inventory", "--since", "abc"}, {"doctor", "--since", "0"}, {"completion"}} {
		f := &fake{}
		got, _, errb := drive(f, args...)
		e := errb.String()
		if got != 2 || !strings.Contains(e, "agentctl:") || !strings.Contains(e, "Usage:") || len(f.calls) != 0 {
			t.Errorf("%v: status %d calls %d err %q", args, got, len(f.calls), e)
		}
		if len(args) == 0 || args[0] == "bogus" {
			if !strings.Contains(e, "inventory") || !strings.Contains(e, "doctor") {
				t.Errorf("%v: usage lacks subcommands: %q", args, e)
			}
		}
	}
}

func TestJSONModeUsageErrorsLeaveStdoutEmpty(t *testing.T) {
	for _, args := range [][]string{{"doctor", "--json", "--nope"}, {"inventory", "--json", "--since", "x"}, {"doctor", "--json", "extra"}} {
		got, out, errb := drive(&fake{}, args...)
		if got != 2 || out.Len() != 0 || errb.Len() == 0 {
			t.Errorf("%v: status %d out=%q err=%q", args, got, out, errb)
		}
	}
}

func TestHelpAndVersionGoToStdoutAndExit0(t *testing.T) {
	got, out, errb := drive(&fake{}, "--help")
	if got != 0 || !strings.Contains(out.String(), "inventory") || !strings.Contains(out.String(), "doctor") || errb.Len() != 0 {
		t.Errorf("--help: %d out=%q err=%q", got, out, errb)
	}
	got, out, _ = drive(&fake{}, "doctor", "--help")
	for _, w := range []string{"--offline", "--since", "--json", "--yes"} {
		if got != 0 || !strings.Contains(out.String(), w) {
			t.Errorf("doctor --help missing %s (status %d)", w, got)
		}
	}
	got, out, _ = drive(&fake{}, "--version")
	if got != 0 || out.String() != "agentctl dev\n" {
		t.Errorf("--version: %d %q", got, out)
	}
}

func TestSharedFlagsDefinedOnce(t *testing.T) {
	io, _, _ := newIO()
	root := newRoot(io, (&fake{}).exec)
	throwaway := &cobra.Command{Use: "fix"}
	(&commonFlags{}).register(throwaway)
	for _, name := range []string{"offline", "since", "json", "yes"} {
		ref := throwaway.Flags().Lookup(name)
		if ref == nil {
			t.Fatalf("throwaway lacks %s", name)
		}
		for _, sub := range []string{"inventory", "doctor"} {
			c, _, _ := root.Find([]string{sub})
			fl := c.Flags().Lookup(name)
			if fl == nil || fl.DefValue != ref.DefValue || fl.Usage != ref.Usage {
				t.Errorf("%s --%s differs: %+v vs %+v", sub, name, fl, ref)
			}
		}
	}
}

func TestExitErrorMessagePrinted(t *testing.T) {
	io, out, errb := newIO()
	root := newRoot(io, (&fake{}).exec)
	root.AddCommand(&cobra.Command{Use: "boom", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error { return &ExitError{Code: 2, Msg: "boom"} }})
	got := execute(context.Background(), root, []string{"boom"}, io)
	if got != 2 || !strings.Contains(errb.String(), "boom") || out.Len() != 0 {
		t.Errorf("got %d err=%q out=%q", got, errb, out)
	}
}
