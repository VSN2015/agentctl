package run

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

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
	if !strings.Contains(e, "\r\x1b[2K⠋ checking Fakery label c1 (1/2)") {
		t.Errorf("stderr %q", e)
	}
	r2, d2, _ := twoCreds()
	d2.Progress = nil
	Execute(context.Background(), doctor(), d2)
	if r.out.String() != r2.out.String() || r2.errb.Len() != 0 {
		t.Errorf("stdout differs or stderr not empty: %q", r2.errb)
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

func TestSpinnerFramesAndReplace(t *testing.T) {
	var b bytes.Buffer
	tick := make(chan time.Time)
	p := newProgress(&b, tick)
	p("one")
	for i := 0; i < 10; i++ {
		tick <- time.Time{}
	}
	p("")
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	want := clearSeq + "⠋ one"
	for i := 1; i <= 10; i++ {
		want += clearSeq + frames[i%10] + " one"
	}
	want += clearSeq
	if b.String() != want {
		t.Errorf("got %q\nwant %q", b.String(), want)
	}
	b.Reset() // a new message redraws at once with the new text, same frame
	p = newProgress(&b, tick)
	p("one")
	p("two")
	p("")
	if want := clearSeq + "⠋ one" + clearSeq + "⠋ two" + clearSeq; b.String() != want {
		t.Errorf("replace: %q", b.String())
	}
}

func TestSpinnerSilentAfterClear(t *testing.T) {
	var b bytes.Buffer
	tick := make(chan time.Time, 5)
	p := newProgress(&b, tick)
	p("x")
	p("")
	n := b.Len()
	for i := 0; i < 5; i++ {
		tick <- time.Time{}
	}
	close(tick)
	time.Sleep(20 * time.Millisecond)
	if b.Len() != n || !strings.HasSuffix(b.String(), clearSeq) {
		t.Errorf("wrote after clear: %q", b.String())
	}
}

func TestSpinnerSanitisesAndCaps(t *testing.T) {
	var b bytes.Buffer
	p := newProgress(&b, make(chan time.Time))
	p("checking x\x1b[31m\nevil")
	p("")
	if got := b.String(); got != clearSeq+"⠋ checking x?[31m?evil"+clearSeq {
		t.Errorf("hostile: %q", got)
	}
	b.Reset()
	p("checking " + strings.Repeat("é", 200))
	p("")
	if want := clearSeq + "⠋ checking " + strings.Repeat("é", 51) + "…" + clearSeq; b.String() != want {
		t.Errorf("long: %q", b.String())
	}
}
