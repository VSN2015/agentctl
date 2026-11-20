package confirm

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const line1 = "About to ask AWS and GitHub what your credentials can do.\n"
const line2 = "Read-only, but the requests appear in their audit logs.\n"
const ask = "Continue? [y/N] (--yes to skip this question, --offline to stay local) "

var both = []string{"AWS", "GitHub"}

// panicReader fails the test if it is ever read.
type panicReader struct{ t *testing.T }

func (p panicReader) Read([]byte) (int, error) { p.t.Fatal("reader touched"); return 0, nil }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestPromptText(t *testing.T) {
	var out bytes.Buffer
	got, err := Online(strings.NewReader("y\n"), &out, true, false, false, both)
	if !got || err != nil || out.String() != line1+line2+ask {
		t.Errorf("got %v %v %q", got, err, out.String())
	}
	for providers, want := range map[string]string{
		"AWS":            "About to ask AWS what your credentials can do.",
		"AWS,GitHub,Foo": "About to ask AWS, GitHub and Foo what your credentials can do.",
	} {
		out.Reset()
		Online(strings.NewReader("n\n"), &out, true, false, false, strings.Split(providers, ","))
		if !strings.HasPrefix(out.String(), want+"\n") {
			t.Errorf("%s: %q", providers, out.String())
		}
	}
}

func TestAnswers(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "Y\n": true, "yes\n": true, "YES\n": true, "yes\r\n": true,
		"\n": false, "n\n": false, "no\n": false, "maybe\n": false, "": false, "y": false} {
		got, err := Online(strings.NewReader(in), &bytes.Buffer{}, true, false, false, both)
		if got != want || err != nil {
			t.Errorf("%q: got %v %v", in, got, err)
		}
	}
	if got, err := Online(errReader{}, &bytes.Buffer{}, true, false, false, both); got || err == nil {
		t.Errorf("read error: %v %v", got, err)
	}
}

func TestNoTerminalWithoutFlags(t *testing.T) {
	var out bytes.Buffer
	got, err := Online(panicReader{t}, &out, false, false, false, both)
	if got || !errors.Is(err, ErrNoTerminal) || out.Len() != 0 {
		t.Errorf("got %v %v %q", got, err, out.String())
	}
}

func TestYesPrintsNoticeAndSkipsQuestion(t *testing.T) {
	var out bytes.Buffer
	got, err := Online(panicReader{t}, &out, false, false, true, both)
	if !got || err != nil || out.String() != line1+line2 {
		t.Errorf("got %v %v %q", got, err, out.String())
	}
}

func TestOfflineBeatsYes(t *testing.T) {
	var out bytes.Buffer
	got, err := Online(panicReader{t}, &out, true, true, true, both)
	if got || err != nil || out.Len() != 0 {
		t.Errorf("got %v %v %q", got, err, out.String())
	}
}

func TestNoProvidersNeverPrompts(t *testing.T) {
	for _, yes := range []bool{false, true} {
		var out bytes.Buffer
		got, err := Online(panicReader{t}, &out, true, false, yes, nil)
		if got || err != nil || out.Len() != 0 {
			t.Errorf("yes=%v: %v %v %q", yes, got, err, out.String())
		}
	}
}

func TestProviderNameIsNotAFormat(t *testing.T) {
	var out bytes.Buffer
	Online(strings.NewReader("n\n"), &out, true, false, false, []string{"%s%d"})
	if !strings.HasPrefix(out.String(), "About to ask %s%d what") {
		t.Errorf("%q", out.String())
	}
}
