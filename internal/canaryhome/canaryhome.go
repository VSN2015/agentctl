// Package canaryhome builds a synthetic home directory for end-to-end tests. Every secret in it is
// a canary: if one reaches any output, a test fails. It is imported by tests only.
package canaryhome

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	Secret   = "CANARY-SECRET-DO-NOT-PRINT"
	KeyID    = "AKIAIOSFODNN7EXAMPLE"
	GHToken  = "ghp_CANARYTOKENDONOTPRINT0123456789"
	MaskedID = "AKIA****MPLE"

	// environment canaries: set in Home.Env, so they must never be printed either
	EnvKeyID   = "AKIAZZZZZZZZZZZZENVK"
	EnvSecret  = "CANARY-ENV-SECRET-KEY-DO-NOT-PRINT"
	EnvSession = "CANARY-ENV-SESSION-TOKEN-DO-NOT-PRINT"
	EnvGHToken = "ghp_CANARYENVTOKENDONOTPRINT0123456789"
)

// Secrets lists every value that must never appear in output.
var Secrets = []string{Secret, KeyID, GHToken, EnvKeyID, EnvSecret, EnvSession, EnvGHToken}

type Home struct {
	Dir string
	Env map[string]string // every config-dir input points into Dir
}

func (h Home) Getenv(k string) string { return h.Env[k] }

// New writes the canary home into t.TempDir(). With unreadableAWS the AWS credentials path is a
// directory, so it exists but cannot be read as a file.
func New(t testing.TB, unreadableAWS bool) Home {
	t.Helper()
	dir := t.TempDir()
	at := func(d time.Duration) int64 { return time.Now().Add(d).Unix() }
	put := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(".aws/config", "[default]\nregion = us-east-1\n")
	if unreadableAWS {
		if err := os.MkdirAll(filepath.Join(dir, ".aws", "credentials"), 0o755); err != nil {
			t.Fatal(err)
		}
	} else {
		put(".aws/credentials", fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n", KeyID, Secret))
	}
	put("gh/hosts.yml", fmt.Sprintf("github.com:\n    user: octocat\n    oauth_token: %s\n", GHToken))
	put(".zsh_history", fmt.Sprintf(": %d:0;AWS_SECRET_ACCESS_KEY=%s aws s3 ls\n", at(-2*time.Hour), Secret))
	put(".claude/settings.json", fmt.Sprintf(`{"env":{"ANTHROPIC_API_KEY":%q}}`, Secret))
	put(".claude/projects/p/s.jsonl", fmt.Sprintf(
		`{"timestamp":%q,"message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"AWS_SECRET_ACCESS_KEY=%s aws s3 ls"}}]}}`+"\n",
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), Secret))
	return Home{Dir: dir, Env: map[string]string{
		"HOME": dir, "CLAUDE_CONFIG_DIR": filepath.Join(dir, ".claude"),
		"AWS_CONFIG_FILE":             filepath.Join(dir, ".aws", "config"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, ".aws", "credentials"),
		"GH_CONFIG_DIR":               filepath.Join(dir, "gh"), "XDG_CONFIG_HOME": filepath.Join(dir, "xdg"),
		"HISTFILE": filepath.Join(dir, ".no_histfile"), "ZDOTDIR": dir,
		"AWS_ACCESS_KEY_ID": EnvKeyID, "AWS_SECRET_ACCESS_KEY": EnvSecret, "AWS_SESSION_TOKEN": EnvSession,
		"GH_TOKEN":    EnvGHToken,
		"DOCKER_HOST": "unix://" + filepath.Join(dir, "docker.sock"),
	}}
}
