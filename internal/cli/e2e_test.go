package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/canaryhome"
	"github.com/VSN2015/agentctl/internal/registry"
	"github.com/VSN2015/agentctl/internal/run"
)

// e2eRun drives the full cobra path over a canary home. The Exec seam builds the real deps but
// leaves out the machine's managed-settings path (empty GOOS), so nothing outside the temp home is read.
func e2eRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	h := canaryhome.New(t, false)
	var out, errb bytes.Buffer
	io := IO{In: strings.NewReader(""), Out: &out, Err: &errb, Getenv: h.Getenv, Home: h.Dir, Cwd: h.Dir}
	exec := func(ctx context.Context, o run.Options, io IO) int {
		d := buildDeps(o, io)
		d.Agents = registry.Agents(registry.AgentParams{Getenv: io.Getenv, Home: io.Home, Cwd: io.Cwd, GOOS: ""})
		return run.Execute(ctx, o, d)
	}
	code := execute(context.Background(), newRoot(io, exec), args, io)
	return code, out.String(), errb.String()
}

func TestE2ECLIJSONStdoutIsOnlyJSON(t *testing.T) {
	code, out, errb := e2eRun(t, "doctor", "--offline", "--json")
	var doc struct {
		SchemaVersion int `json:"schema_version"`
	}
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&doc); err != nil || doc.SchemaVersion != 1 || dec.More() || !strings.HasSuffix(out, "\n") {
		t.Errorf("stdout is not exactly one JSON document: %v\n%s", err, out)
	}
	if code != 0 || strings.Contains(errb, "Usage:") {
		t.Errorf("exit %d err %q", code, errb)
	}
	for _, s := range canaryhome.Secrets {
		if strings.Contains(out, s) || strings.Contains(errb, s) {
			t.Errorf("output contains canary %q", s)
		}
	}
}

func TestE2ECLINoTerminalExit2(t *testing.T) {
	code, out, errb := e2eRun(t, "doctor")
	if code != 2 || out != "" || !strings.Contains(errb, "--yes") || !strings.Contains(errb, "--offline") {
		t.Errorf("exit %d out %q err %q", code, out, errb)
	}
	for _, s := range canaryhome.Secrets {
		if strings.Contains(errb, s) {
			t.Errorf("stderr contains canary %q", s)
		}
	}
}
