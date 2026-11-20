package aws

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/OWNER/agentctl/internal/model"
	"github.com/OWNER/agentctl/internal/scan"
)

const canary = "CANARY-SECRET-DO-NOT-PRINT"

const basicConfig = `[default]
region = us-east-1

[profile prod]
role_arn = arn:aws:iam::123456789012:role/Admin
source_profile = default

[profile dev-sso]
sso_session = s
sso_account_id = 111111111111

[sso-session s]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
`

const basicKeys = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = " + canary + "\n"

const weirdConfig = "[profile my team]\nrole_arn = arn:aws:iam::1:role/a\n\n" +
	"[profile 名前]\nrole_arn = arn:aws:iam::1:role/b\n\n" +
	"[profile bad\x1b[31m]\nrole_arn = arn:aws:iam::1:role/c\n\n" +
	"[default]\nregion = x\n\n" +
	"[profile default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"

// fakeHome writes synthetic ~/.aws files (empty content = file not written) into a temp dir.
func fakeHome(t *testing.T, config, keys string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"config": config, "credentials": keys} {
		if body != "" {
			write(t, filepath.Join(home, ".aws"), name, body)
		}
	}
	return home
}

func env(home string, vars map[string]string) scan.Env {
	return scan.Env{Home: home, Getenv: func(k string) string { return vars[k] }, SysRoot: filepath.Join(home, "nosys")}
}

func discover(t *testing.T, e scan.Env) map[string]model.Credential {
	t.Helper()
	creds, err := New(nil).Discover(e)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]model.Credential{}
	for _, c := range creds {
		m[c.ID] = c
	}
	return m
}

func ids(m map[string]model.Credential) []string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseINIKeepsOnlyAllowedKeys(t *testing.T) {
	in := "# c\r\n; c\r\n\r\n[prod] # trailing\r\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\r\naws_secret_access_key = " + canary + "\r\nregion = us-east-1\r\nrole_arn = arn:x\r\n"
	got, err := parseINI(strings.NewReader(in), map[string]bool{"aws_access_key_id": true, "aws_secret_access_key": false, "role_arn": true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key": "1", "role_arn": "arn:x"}
	if !reflect.DeepEqual(got["prod"], want) {
		t.Fatalf("got %v", got)
	}
	if strings.Contains(fmt.Sprint(got), canary) {
		t.Fatal("secret retained")
	}
}

func TestDiscoverBasic(t *testing.T) {
	home := fakeHome(t, basicConfig, basicKeys)
	m := discover(t, env(home, nil))
	if got := ids(m); !reflect.DeepEqual(got, []string{"default", "dev-sso", "prod"}) {
		t.Fatalf("ids %v", got)
	}
	d := m["default"]
	if d.Kind != "access-key" || !d.LongLived || d.KeyID != "AKIA****MPLE" || d.Source != "file" || d.Tool != "aws" {
		t.Fatalf("default %+v", d)
	}
	if p := m["prod"]; p.Kind != "assume-role" || p.Identity != "arn:aws:iam::123456789012:role/Admin" {
		t.Fatalf("prod %+v", p)
	}
	if m["dev-sso"].Kind != "sso" {
		t.Fatalf("sso %+v", m["dev-sso"])
	}
	for _, f := range []string{filepath.Join(home, ".aws", "config"), filepath.Join(home, ".aws", "credentials")} {
		if !contains(d.Files, f) {
			t.Fatalf("files %v lack %s", d.Files, f)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", m), canary) {
		t.Fatal("canary leaked")
	}
}

func TestDiscoverTemporaryKeyIsNotLongLived(t *testing.T) {
	home := fakeHome(t, "", "[a]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_session_token = tok\n[b]\naws_access_key_id = ASIAIOSFODNN7EXAMPLE\n[c]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	m := discover(t, env(home, nil))
	if m["a"].LongLived || m["b"].LongLived || !m["c"].LongLived {
		t.Fatalf("a=%v b=%v c=%v", m["a"].LongLived, m["b"].LongLived, m["c"].LongLived)
	}
}

func TestDiscoverEnvironment(t *testing.T) {
	m := discover(t, env(fakeHome(t, "", ""), map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY": canary}))
	c, ok := m["environment"]
	if !ok {
		t.Fatalf("ids %v", ids(m))
	}
	if !reflect.DeepEqual(c.EnvVars, []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}) || c.KeyID != "AKIA****MPLE" || c.Source != "env" {
		t.Fatalf("%+v", c)
	}
	if strings.Contains(fmt.Sprintf("%+v", m), canary) {
		t.Fatal("canary leaked")
	}
}

func TestDiscoverChainTriggers(t *testing.T) {
	home := fakeHome(t, "", "")
	for _, v := range []string{"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"} {
		if _, ok := discover(t, env(home, map[string]string{v: "x"}))["chain"]; !ok {
			t.Fatalf("%s: no chain", v)
		}
	}
	sys := t.TempDir()
	write(t, sys, "sys_vendor", "Amazon EC2\n")
	e := env(home, nil)
	e.SysRoot = sys
	if _, ok := discover(t, e)["chain"]; !ok {
		t.Fatal("ec2 hint: no chain")
	}
	e.Home = fakeHome(t, basicConfig, basicKeys)
	if _, ok := discover(t, e)["chain"]; ok {
		t.Fatal("chain despite profile")
	}
}

func TestDiscoverEmptyHome(t *testing.T) {
	if m := discover(t, env(fakeHome(t, "", ""), nil)); len(m) != 0 {
		t.Fatalf("%v", ids(m))
	}
	// A directory in place of ~/.aws/credentials: the note rides on a credential from config.
	home := fakeHome(t, "[profile p]\nrole_arn = arn:x\n", "")
	if err := os.Mkdir(filepath.Join(home, ".aws", "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := discover(t, env(home, nil))["p"]
	if !strings.Contains(strings.Join(c.Notes, "|"), "could not read") {
		t.Fatalf("notes %v", c.Notes)
	}
}

func TestDiscoverUnreadableSourceIsNotSilent(t *testing.T) {
	check := func(t *testing.T, home string) {
		t.Helper()
		m := discover(t, env(home, nil))
		c, ok := m["unreadable"]
		path := filepath.Join(home, ".aws", "credentials")
		if !ok || len(m) != 1 || c.Kind != "unknown" || c.Source != "file" || c.KeyID != "" ||
			!reflect.DeepEqual(c.Files, []string{path}) || !reflect.DeepEqual(c.Notes, []string{"could not read " + path}) ||
			!strings.Contains(c.Label, "credentials") {
			t.Fatalf("%+v", m)
		}
	}
	t.Run("directory", func(t *testing.T) {
		home := fakeHome(t, "", "")
		if err := os.Mkdir(filepath.Join(home, ".aws", "credentials"), 0o700); err != nil {
			t.Fatal(err)
		}
		check(t, home)
	})
	t.Run("mode000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores file modes")
		}
		home := fakeHome(t, "", basicKeys)
		if err := os.Chmod(filepath.Join(home, ".aws", "credentials"), 0); err != nil {
			t.Fatal(err)
		}
		check(t, home)
	})
}

func TestDiscoverFileOverrides(t *testing.T) {
	dir := t.TempDir()
	cf := write(t, dir, "cfg", "[profile o]\nrole_arn = arn:x\n")
	kf := write(t, dir, "keys", "[k]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	m := discover(t, env(fakeHome(t, basicConfig, basicKeys), map[string]string{"AWS_CONFIG_FILE": cf, "AWS_SHARED_CREDENTIALS_FILE": kf}))
	if got := ids(m); !reflect.DeepEqual(got, []string{"k", "o"}) {
		t.Fatalf("%v", got)
	}
}

func TestDiscoverOddProfileNames(t *testing.T) {
	m := discover(t, env(fakeHome(t, weirdConfig, ""), nil))
	for _, id := range []string{"my team", "名前", "bad\x1b[31m", "default"} {
		c, ok := m[id]
		if !ok {
			t.Fatalf("missing %q in %q", id, ids(m))
		}
		if c.Label != model.Sanitize(id) {
			t.Fatalf("label %q", c.Label)
		}
	}
	if len(m) != 4 || m["default"].Kind != "access-key" {
		t.Fatalf("%q %+v", ids(m), m["default"])
	}
}

func TestDiscoverOrderIsDeterministic(t *testing.T) {
	home := fakeHome(t, "[profile zeta]\nrole_arn = a\n[profile alpha]\nrole_arn = a\n[profile mid]\nrole_arn = a\n[default]\nrole_arn = a\n",
		"[beta]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	e := env(home, map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE", "AWS_WEB_IDENTITY_TOKEN_FILE": "x"})
	want := []string{"default", "alpha", "beta", "mid", "zeta", "environment", "chain"}
	for i := 0; i < 20; i++ {
		creds, err := New(nil).Discover(e)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, c := range creds {
			got = append(got, c.ID)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestDiscoverReservedProfileName(t *testing.T) {
	home := fakeHome(t, "", "[environment]\naws_access_key_id = AKIAAAAAAAAAAAAAAAAA\n")
	s := New(nil)
	creds, err := s.Discover(env(home, map[string]string{"AWS_ACCESS_KEY_ID": "AKIABBBBBBBBBBBBBBBB"}))
	if err != nil || len(creds) != 2 {
		t.Fatalf("%v %+v", err, creds)
	}
	f, e := creds[0], creds[1]
	if f.ID != "profile:environment" || f.Label != "environment" || f.Source != "file" || f.KeyID != "AKIA****AAAA" ||
		e.ID != "environment" || e.Source != "env" || e.KeyID != "AKIA****BBBB" {
		t.Fatalf("%+v %+v", f, e)
	}
	if s.keys[f.ID] != "AKIAAAAAAAAAAAAAAAAA" || s.keys[e.ID] != "AKIABBBBBBBBBBBBBBBB" {
		t.Fatal("raw keys cross-wired")
	}
}
