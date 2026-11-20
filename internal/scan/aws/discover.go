package aws

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

// keep: true stores the value, false stores only presence ("1").
var keep = map[string]bool{
	"aws_access_key_id": true, "aws_session_token": false, "aws_secret_access_key": false,
	"role_arn": true, "source_profile": true, "credential_source": true,
	"sso_session": true, "sso_start_url": true, "web_identity_token_file": true,
	"credential_process": false, "mfa_serial": false,
}

type Scanner struct {
	api  APIFactory
	keys map[string]string // credential ID -> raw access key id; never copied into model.Credential
	skip map[string]bool   // credential IDs whose resolution could run a credential_process or prompt for MFA
}

func New(api APIFactory) *Scanner {
	return &Scanner{api: api, keys: map[string]string{}, skip: map[string]bool{}}
}

func (s *Scanner) Name() string     { return "aws" }
func (s *Scanner) Provider() string { return "AWS" }

type profile struct{ keys map[string]string }

func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	s.keys, s.skip = map[string]string{}, map[string]bool{}
	var notes, failed []string
	profiles := map[string]*profile{}
	seen := map[string][]string{} // profile name -> files with a section for it, even a region-only one
	var order []string

	load := func(path string, isConfig bool) {
		fail := func() {
			failed = append(failed, path)
			notes = append(notes, "could not read "+model.Sanitize(path))
		}
		f, err := os.Open(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				fail()
			}
			return
		}
		defer f.Close()
		secs, err := parseINI(f, keep)
		if err != nil { // a directory opens fine but fails on read
			fail()
			return
		}
		for sec, kv := range secs {
			name := sec
			if isConfig {
				switch {
				case sec == "default":
				case strings.HasPrefix(sec, "profile "):
					name = strings.TrimSpace(strings.TrimPrefix(sec, "profile "))
				default: // sso-session, services, and anything else
					continue
				}
			}
			if !contains(seen[name], path) {
				seen[name] = append(seen[name], path)
			}
			if len(kv) == 0 { // no credential-relevant key, e.g. region only
				continue
			}
			p := profiles[name]
			if p == nil {
				p = &profile{keys: map[string]string{}}
				profiles[name] = p
				order = append(order, name)
			}
			for k, v := range kv {
				p.keys[k] = v
			}
		}
	}
	fallback := getenv("AWS_PROFILE") // the profile the SDK uses when nothing else is chosen
	if fallback == "" {
		fallback = "default"
	}
	cfg, crd := getenv("AWS_CONFIG_FILE"), getenv("AWS_SHARED_CREDENTIALS_FILE")
	if cfg == "" && env.Home != "" {
		cfg = filepath.Join(env.Home, ".aws", "config")
	}
	if crd == "" && env.Home != "" {
		crd = filepath.Join(env.Home, ".aws", "credentials")
	}
	for i, p := range []string{cfg, crd} {
		if p != "" {
			load(p, i == 0)
		}
	}

	// map iteration above is random; "default" first, then by name, for stable output
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		return a != b && (a == "default" || (b != "default" && a < b))
	})
	var creds []model.Credential
	for _, name := range order {
		p := profiles[name]
		id := name
		switch name { // reserved IDs belong to the env, chain and unreadable credentials
		case "environment", "chain", "unreadable":
			id = "profile:" + name
		}
		c := model.Credential{Tool: "aws", ID: id, Label: model.Sanitize(name), Source: "file", Files: seen[name], Notes: notes}
		c.Kind = kindOf(p.keys)
		s.skip[id] = prompts(profiles, name)
		if c.Kind == "assume-role" {
			c.Identity = p.keys["role_arn"]
		}
		if key := p.keys["aws_access_key_id"]; key != "" {
			s.keys[c.ID] = key
			c.KeyID = model.MaskKeyID(key)
			c.LongLived = c.Kind == "access-key" && longLived(key, p.keys["aws_session_token"] != "")
		}
		creds = append(creds, c)
	}
	if len(creds) == 0 && len(failed) > 0 { // do not let an unreadable source vanish silently
		creds = append(creds, model.Credential{Tool: "aws", ID: "unreadable", Kind: "unknown", Source: "file",
			Label: "unreadable: " + model.Sanitize(failed[0]), Files: failed, Notes: notes})
	}

	if id := getenv("AWS_ACCESS_KEY_ID"); id != "" {
		c := model.Credential{Tool: "aws", ID: "environment", Label: "environment", Kind: "access-key", Source: "env",
			EnvVars: []string{"AWS_ACCESS_KEY_ID"}, KeyID: model.MaskKeyID(id), LongLived: longLived(id, getenv("AWS_SESSION_TOKEN") != "")}
		for _, v := range []string{"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
			if getenv(v) != "" {
				c.EnvVars = append(c.EnvVars, v)
			}
		}
		s.keys["environment"] = id
		// without a full key pair the SDK falls back to a shared-config profile
		s.skip["environment"] = getenv("AWS_SECRET_ACCESS_KEY") == "" && prompts(profiles, fallback)
		creds = append(creds, c)
	}

	s.skip["chain"] = prompts(profiles, fallback)
	chain := model.Credential{Tool: "aws", ID: "chain", Label: "default credential chain", Kind: "unknown", Source: "chain"}
	switch {
	case getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "":
		chain.Kind, chain.EnvVars = "web-identity", []string{"AWS_WEB_IDENTITY_TOKEN_FILE"}
	case getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "":
		chain.EnvVars = []string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"}
	case getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "":
		chain.EnvVars = []string{"AWS_CONTAINER_CREDENTIALS_FULL_URI"}
	case len(creds) == 0 && instanceRoleHint(env.SysRoot):
		chain.Notes = []string{"host looks like an EC2 instance; an instance role may apply"}
	default:
		return creds, nil
	}
	return append(creds, chain), nil
}

// prompts reports whether resolving the profile, or any profile reached through source_profile,
// would run a credential_process or ask for an MFA code.
func prompts(profiles map[string]*profile, name string) bool {
	for seen := map[string]bool{}; !seen[name]; {
		seen[name] = true
		p := profiles[name]
		if p == nil {
			return false
		}
		if p.keys["credential_process"] != "" || p.keys["mfa_serial"] != "" {
			return true
		}
		name = p.keys["source_profile"]
	}
	return false
}

func kindOf(k map[string]string) string {
	switch {
	case k["credential_process"] != "":
		return "credential-process"
	case k["web_identity_token_file"] != "":
		return "web-identity"
	case k["role_arn"] != "":
		return "assume-role"
	case k["sso_session"] != "" || k["sso_start_url"] != "":
		return "sso"
	case k["aws_access_key_id"] != "":
		return "access-key"
	}
	return "unknown"
}

func longLived(keyID string, hasToken bool) bool {
	return !hasToken && !strings.HasPrefix(keyID, "ASIA")
}

// instanceRoleHint: sys_vendor "Amazon EC2" is sufficient but not necessary (Xen hosts differ).
func instanceRoleHint(sysRoot string) bool {
	if sysRoot == "" {
		sysRoot = "/sys/class/dmi/id"
	}
	b, err := os.ReadFile(filepath.Join(sysRoot, "sys_vendor"))
	return err == nil && strings.Contains(string(b), "Amazon EC2")
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
