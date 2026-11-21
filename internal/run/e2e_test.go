package run_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/agent"
	"github.com/VSN2015/agentctl/internal/agent/claude"
	"github.com/VSN2015/agentctl/internal/canaryhome"
	"github.com/VSN2015/agentctl/internal/confirm"
	"github.com/VSN2015/agentctl/internal/devuse"
	"github.com/VSN2015/agentctl/internal/registry"
	"github.com/VSN2015/agentctl/internal/run"
	"github.com/VSN2015/agentctl/internal/scan"
	"github.com/VSN2015/agentctl/internal/scan/aws"
	"github.com/VSN2015/agentctl/internal/scan/gh"
)

type fakeAWS struct{ calls int }

func (f *fakeAWS) CallerIdentity(context.Context) (aws.Identity, error) {
	f.calls++
	return aws.Identity{ARN: "arn:aws:iam::123456789012:user/dev", Account: "123456789012", Kind: "user", Name: "dev"}, nil
}
func (f *fakeAWS) Policies(context.Context, aws.Identity) ([]aws.Policy, error) {
	f.calls++
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	return []aws.Policy{{Name: "everything", ARN: "arn:aws:iam::123456789012:policy/everything", Document: []byte(doc)}}, nil
}
func (f *fakeAWS) AccessKeyLastUsed(context.Context, string) (*aws.KeyUse, error) {
	f.calls++
	return &aws.KeyUse{At: time.Now().Add(-time.Hour), Service: "s3"}, nil
}

type fakeGH struct{ calls int }

func (f *fakeGH) Run(context.Context, string, []string, []string) ([]byte, error) {
	f.calls++
	return []byte("HTTP/2.0 200 OK\nX-Oauth-Scopes: repo, read:org\r\n\r\n{\"login\":\"octocat\"}"), nil
}

// runOnce runs the pipeline over home with fakes only; the real home and network are never touched.
func runOnce(t *testing.T, h canaryhome.Home, o run.Options, tty bool) (code int, out, errb string, calls int) {
	t.Helper()
	api, runner := &fakeAWS{}, &fakeGH{}
	var ob, eb bytes.Buffer
	d := run.Deps{
		Scanners: []scan.Scanner{aws.New(func(context.Context, string) (aws.API, error) { return api, nil }), gh.New(runner)},
		Rules:    registry.ToolRules(),
		Agents:   []agent.Agent{claude.New(h.Env["CLAUDE_CONFIG_DIR"], h.Dir, h.Dir, "")},
		Dev:      func() devuse.History { return devuse.Read(h.Dir, h.Getenv) },
		Env:      scan.Env{Home: h.Dir, Getenv: h.Getenv},
		Now:      time.Now,
		Confirm: func(p []string) (bool, error) {
			return confirm.Online(strings.NewReader(""), &eb, false, o.Offline, o.Yes, p)
		},
		Out: &ob, Err: &eb, OutIsTTY: tty,
	}
	code = run.Execute(context.Background(), o, d)
	return code, ob.String(), eb.String(), api.calls + runner.calls
}

func noSecrets(t *testing.T, label string, outputs ...string) {
	t.Helper()
	for _, s := range canaryhome.Secrets {
		for _, o := range outputs {
			if strings.Contains(o, s) {
				t.Errorf("%s: output contains canary %q:\n%s", label, s, o)
			}
		}
	}
}

func TestE2ENoSecretReachesOutput(t *testing.T) {
	h := canaryhome.New(t, false)
	for _, cmd := range []string{"doctor", "inventory"} {
		for _, offline := range []bool{true, false} {
			for _, mode := range []string{"text", "tty", "json"} {
				o := run.Options{Command: cmd, Offline: offline, Yes: !offline, JSON: mode == "json", Since: 720 * time.Hour}
				code, out, errb, calls := runOnce(t, h, o, mode == "tty")
				label := cmd + "/" + mode + map[bool]string{true: "/offline", false: "/yes"}[offline]
				noSecrets(t, label, out, errb)
				if out == "" || (code != 0 && code != 1) {
					t.Errorf("%s: exit %d out %q err %q", label, code, out, errb)
				}
				if mode != "json" {
					tty := mode == "tty"
					fancy := strings.Contains(out, "·") && (cmd == "inventory" || strings.Contains(out, "\x1b["))
					if fancy != tty || (!tty && (strings.Contains(out, "\x1b[") || strings.Contains(out, "·"))) {
						t.Errorf("%s: terminal rendering present = %v, want %v", label, fancy, tty)
					}
				}
				if offline && calls != 0 {
					t.Errorf("%s: %d provider calls offline", label, calls)
				}
				if !offline && calls == 0 {
					t.Errorf("%s: --yes made no (fake) provider calls", label)
				}
				if mode == "json" {
					var doc struct {
						SchemaVersion int `json:"schema_version"`
					}
					dec := json.NewDecoder(strings.NewReader(out))
					if err := dec.Decode(&doc); err != nil || doc.SchemaVersion != 1 || dec.More() {
						t.Errorf("%s: not one JSON document with schema_version 1: %v", label, err)
					}
				}
			}
		}
	}
}

func TestE2EDoctorExitStatusHighOnlineOnly(t *testing.T) {
	h := canaryhome.New(t, false)
	if code, out, errb, _ := runOnce(t, h, run.Options{Command: "doctor", Yes: true, Since: 720 * time.Hour}, false); code != 1 {
		t.Errorf("online with an admin credential: exit %d, want 1\nout %s\nerr %s", code, out, errb)
	}
	if code, out, errb, _ := runOnce(t, h, run.Options{Command: "doctor", Offline: true, Since: 720 * time.Hour}, false); code != 0 {
		t.Errorf("offline: exit %d, want 0\nout %s\nerr %s", code, out, errb)
	}
}

func TestE2EUnreadableAWSFileIsNotedNotLeaked(t *testing.T) {
	h := canaryhome.New(t, true)
	code, out, errb, _ := runOnce(t, h, run.Options{Command: "inventory", Offline: true, Since: 720 * time.Hour}, false)
	if code != 0 || !strings.Contains(out, "could not read") {
		t.Errorf("exit %d, want 0 with a could-not-read note\nout %s\nerr %s", code, out, errb)
	}
	noSecrets(t, "unreadable", out, errb)
}

func TestE2ENoTerminalWithoutFlagsExit2(t *testing.T) {
	h := canaryhome.New(t, false)
	code, out, errb, calls := runOnce(t, h, run.Options{Command: "doctor", Since: 720 * time.Hour}, false)
	if code != 2 || out != "" || calls != 0 || !strings.Contains(errb, "--yes") || !strings.Contains(errb, "--offline") {
		t.Errorf("exit %d calls %d out %q err %q", code, calls, out, errb)
	}
	noSecrets(t, "no terminal", out, errb)
}

func TestE2EEmptyHome(t *testing.T) {
	h := canaryhome.Home{Dir: t.TempDir()}
	h.Env = map[string]string{"HOME": h.Dir}
	code, out, errb, _ := runOnce(t, h, run.Options{Command: "doctor", Offline: true, Since: 720 * time.Hour}, false)
	if code != 0 || out == "" || errb != "" {
		t.Errorf("exit %d out %q err %q", code, out, errb)
	}
}

// The canary assertions above pass on empty output; these prove the scan actually found things.
func TestE2EOfflineReportShowsWhatWasFound(t *testing.T) {
	h := canaryhome.New(t, false)
	_, inv, _, _ := runOnce(t, h, run.Options{Command: "inventory", Offline: true, Since: 720 * time.Hour}, false)
	for _, want := range []string{canaryhome.MaskedID, "github.com - file-host", "Identity: octocat"} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventory lacks %q:\n%s", want, inv)
		}
	}
	_, doc, _, _ := runOnce(t, h, run.Options{Command: "doctor", Offline: true, Since: 720 * time.Hour}, false)
	if !strings.Contains(doc, "AWS     default") || !strings.Contains(doc, "long-lived key") || !strings.Contains(doc, "  1?  ") {
		t.Errorf("doctor did not count the Claude Bash use of aws:\n%s", doc)
	}
}
