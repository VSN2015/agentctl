package run

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/confirm"
	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/model"
)

const clearSeq = "\r\x1b[2K"

// twoCreds is a rig with two credentials; record collects the non-empty progress messages.
func twoCreds() (*rig, Deps, *[]string) {
	r := newRig()
	r.sc.creds = []model.Credential{cred("fake", "c1"), cred("fake", "c2")}
	r.dev = func() devuse.History { return devuse.History{} }
	var got []string
	d := r.deps()
	d.Progress = func(m string) {
		if m != "" {
			got = append(got, m)
		}
	}
	return r, d, &got
}

func TestCollectProgressMessages(t *testing.T) {
	_, d, got := twoCreds()
	if _, err := Collect(context.Background(), doctor(), d); err != nil {
		t.Fatal(err)
	}
	want := "finding credentials|checking Fakery label c1 (1/2)|checking Fakery label c2 (2/2)|reading agent history|reading shell history"
	if g := strings.Join(*got, "|"); g != want {
		t.Errorf("doctor online: %q", g)
	}
	_, d, got = twoCreds()
	if _, err := Collect(context.Background(), inventory(), d); err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(*got, "|"); g != "finding credentials|checking Fakery label c1 (1/2)|checking Fakery label c2 (2/2)" {
		t.Errorf("inventory online: %q", g)
	}
	_, d, got = twoCreds()
	if _, err := Collect(context.Background(), doctor(func(o *Options) { o.Offline = true }), d); err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(*got, "|"); g != "finding credentials|reading agent history|reading shell history" {
		t.Errorf("doctor offline: %q", g)
	}
}

func TestProgressClearedBeforeConfirm(t *testing.T) {
	r, d, _ := twoCreds()
	var errAtConfirm string
	r.confirm = func([]string) (bool, error) { errAtConfirm = r.errb.String(); return true, nil }
	d.Progress = NewProgress(r.errb)
	if code := Execute(context.Background(), inventory(), d); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasSuffix(errAtConfirm, clearSeq) || !strings.Contains(errAtConfirm, "finding credentials") {
		t.Errorf("stderr at Confirm %q", errAtConfirm)
	}
}

func TestExecuteProgressEnabledKeepsStdoutAndEndsCleared(t *testing.T) {
	r, d, _ := twoCreds()
	d.Progress = NewProgress(r.errb)
	if code := Execute(context.Background(), doctor(), d); code != 0 {
		t.Fatalf("exit %d", code)
	}
	e := r.errb.String()
	if !strings.HasSuffix(e, clearSeq) || strings.Contains(e, "\n") {
		t.Errorf("stderr %q", e)
	}
	if !strings.Contains(e, "\r\x1b[2Kagentctl: checking Fakery label c1 (1/2)…") {
		t.Errorf("stderr %q", e)
	}
	r2, d2, _ := twoCreds()
	d2.Progress = nil
	Execute(context.Background(), doctor(), d2)
	if r.out.String() != r2.out.String() || r2.errb.Len() != 0 {
		t.Errorf("stdout differs or stderr not empty: %q", r2.errb)
	}
}

func TestProgressSanitisesHostileText(t *testing.T) {
	var b bytes.Buffer
	NewProgress(&b)("checking x\x1b[31m\nevil")
	if got := b.String(); got != "\r\x1b[2Kagentctl: checking x?[31m?evil…" {
		t.Errorf("%q", got)
	}
}

func TestProgressClearedBeforeErrorLine(t *testing.T) {
	r, d, _ := twoCreds()
	r.confirm = func([]string) (bool, error) { return false, confirm.ErrNoTerminal }
	d.Progress = NewProgress(r.errb)
	if code := Execute(context.Background(), doctor(), d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if e := r.errb.String(); !strings.Contains(e, clearSeq+"agentctl: no terminal") {
		t.Errorf("stderr %q", e)
	}
	r, d, _ = twoCreds()
	ctx, cancel := context.WithCancel(context.Background())
	r.confirm = func([]string) (bool, error) { cancel(); return true, nil }
	d.Progress = NewProgress(r.errb)
	if code := Execute(ctx, doctor(), d); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if e := r.errb.String(); !strings.Contains(e, clearSeq+"agentctl: cancelled") {
		t.Errorf("stderr %q", e)
	}
}

func TestProgressCapsLongMessages(t *testing.T) {
	var b bytes.Buffer
	p := NewProgress(&b)
	p("checking " + strings.Repeat("é", 200))
	want := clearSeq + "agentctl: checking " + strings.Repeat("é", 51) + "…"
	if b.String() != want {
		t.Errorf("long: %q", b.String())
	}
	b.Reset()
	p("checking Fakery label c1 (1/2)")
	if b.String() != clearSeq+"agentctl: checking Fakery label c1 (1/2)…" {
		t.Errorf("short: %q", b.String())
	}
}
