package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

const badMsg = "could not read or parse Claude Code configuration"

func envFor(home, cfg string) scan.Env {
	return scan.Env{Home: home, Getenv: func(k string) string {
		if k == "CLAUDE_CONFIG_DIR" {
			return cfg
		}
		return ""
	}}
}

// write puts content in <dir>/.claude.json.
func write(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func discover(t *testing.T, content string) ([]model.Credential, error) {
	t.Helper()
	home := t.TempDir()
	write(t, home, content)
	return New().Discover(envFor(home, ""))
}

func TestDiscoverServers(t *testing.T) {
	creds, err := discover(t, `{"mcpServers":{"filesystem":{"command":"x"},"remote":{"type":"http","url":"u"}},
	 "projects":{"/p/a":{"mcpServers":{"filesystem":{"type":"http"},"local-only":{"type":"sse"}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{"filesystem", "stdio"}, {"local-only", "sse"}, {"remote", "http"}}
	if len(creds) != 3 {
		t.Fatalf("got %+v", creds)
	}
	for i, w := range want {
		c := creds[i]
		if c.Tool != "mcp" || c.ID != w[0] || c.Kind != w[1] || c.Source != "file" || len(c.Files) != 0 {
			t.Errorf("%d: %+v want %v", i, c, w)
		}
	}
}

func TestDiscoverNames(t *testing.T) {
	creds, err := discover(t, `{"mcpServers":{"my server.v2":{},"\u001b[31mred":{},"":{},"a b":{},"a.b":{}}}`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range creds {
		got[c.ID] = c.Label
		if strings.ContainsRune(c.Label, 0x1b) {
			t.Errorf("label not sanitized: %q", c.Label)
		}
	}
	if got["my_server_v2"] != "my server.v2" {
		t.Errorf("got %v", got)
	}
	if _, ok := got[""]; ok || len(creds) != 3 { // my_server_v2, _[31mred, a_b
		t.Errorf("creds %+v", creds)
	}
}

func TestDiscoverConfigDirWins(t *testing.T) {
	home, cfg := t.TempDir(), t.TempDir()
	write(t, home, `{"mcpServers":{"fromhome":{}}}`)
	write(t, cfg, `{"mcpServers":{"fromcfg":{}}}`)
	creds, err := New().Discover(envFor(home, cfg))
	if err != nil || len(creds) != 1 || creds[0].ID != "fromcfg" {
		t.Fatalf("cfg: %+v %v", creds, err)
	}
	creds, err = New().Discover(envFor(home, ""))
	if err != nil || len(creds) != 1 || creds[0].ID != "fromhome" {
		t.Fatalf("home: %+v %v", creds, err)
	}
	creds, err = New().Discover(envFor(home, "relative/dir"))
	if creds != nil || err == nil || err.Error() != "configuration directory is not an absolute path" {
		t.Fatalf("relative: %+v %v", creds, err)
	}
}

func TestDiscoverNeverReturnsSecrets(t *testing.T) {
	creds, err := discover(t, `{"oauthAccount":{"token":"CANARY-oauth"},
	 "mcpServers":{"a":{"command":"CANARY-cmd","args":["CANARY-arg"],"env":{"K":"CANARY-env"},"url":"CANARY-url","headers":{"H":"CANARY-hdr"}}},
	 "projects":{"/p":{"mcpServers":{"b":{"type":"http","url":"CANARY-url2","headers":{"H":"CANARY-hdr2"}}}}}}`)
	if err != nil || len(creds) != 2 {
		t.Fatalf("%+v %v", creds, err)
	}
	b, _ := json.Marshal(creds)
	if strings.Contains(string(b), "CANARY") {
		t.Fatalf("secret leaked: %s", b)
	}
}

func TestDiscoverBadFiles(t *testing.T) {
	for name, content := range map[string]string{
		"invalid":  `{"CANARY-secret": `,
		"array":    `["CANARY-secret"]`,
		"toolarge": strings.Repeat(" ", model.MaxFileSize+1),
	} {
		creds, err := discover(t, content)
		if creds != nil || err == nil || err.Error() != badMsg {
			t.Errorf("%s: %+v %v", name, creds, err)
		}
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".claude.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if creds, err := New().Discover(envFor(dir, "")); creds != nil || err == nil || err.Error() != badMsg {
		t.Errorf("dir: %+v %v", creds, err)
	}
	for name, content := range map[string]string{
		"empty":      ``,
		"null":       `{"mcpServers":null}`,
		"empty-maps": `{"mcpServers":{},"projects":{"/p":{"mcpServers":null}}}`,
		"no-servers": `{}`,
		"wrong-case": `{"MCPServers":{"x":{}}}`,
	} {
		if creds, err := discover(t, content); creds != nil || err != nil {
			t.Errorf("%s: %+v %v", name, creds, err)
		}
	}
	if creds, err := New().Discover(envFor(t.TempDir(), "")); creds != nil || err != nil {
		t.Errorf("missing: %+v %v", creds, err)
	}
	if creds, err := New().Discover(envFor("", "")); creds != nil || err != nil {
		t.Errorf("no home: %+v %v", creds, err)
	}
	creds, err := discover(t, `{"mcpServers":{"n":{"type":7}}}`)
	if err != nil || len(creds) != 1 || creds[0].Kind != "unknown" {
		t.Errorf("numeric type: %+v %v", creds, err)
	}
}

func TestResolveSkips(t *testing.T) {
	_, err := New().Resolve(context.Background(), model.Credential{})
	var skip *scan.SkipError
	if !errors.As(err, &skip) {
		t.Fatalf("got %v", err)
	}
	var _ scan.LocalOnly = New()
}
