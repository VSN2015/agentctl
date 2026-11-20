// Package gh finds GitHub CLI credentials and asks GitHub who they belong to.
package gh

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
	"go.yaml.in/yaml/v3"
)

const defaultHost = "github.com"

type Scanner struct {
	run  scan.Runner
	skip map[string]bool // placeholder credential IDs that Resolve must not query
}

func New(r scan.Runner) *Scanner { return &Scanner{run: r, skip: map[string]bool{}} }

func (s *Scanner) Name() string     { return "gh" }
func (s *Scanner) Provider() string { return "GitHub" }

// hostEntry deliberately has no token field: the decoder skips oauth_token and users,
// so a token value never reaches a result.
type hostEntry struct {
	User string `yaml:"user"`
}

func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	dir := filepath.Join(env.Home, ".config", "gh")
	if v := getenv("XDG_CONFIG_HOME"); v != "" {
		dir = filepath.Join(v, "gh")
	}
	if v := getenv("GH_CONFIG_DIR"); v != "" {
		dir = v
	}
	path := filepath.Join(dir, "hosts.yml")
	s.skip = map[string]bool{}

	var notes []string
	byHost := map[string]*model.Credential{}
	var order []string
	if buf, err := os.ReadFile(path); err == nil {
		var hosts map[string]hostEntry
		if err := yaml.Unmarshal(buf, &hosts); err != nil { // never echo err: yaml quotes file content
			notes, hosts = append(notes, "could not parse hosts file"), nil // yaml may return a partial map
		}
		for h, e := range hosts {
			byHost[h] = &model.Credential{Tool: "gh", ID: h, Label: model.Sanitize(h), Kind: "file-host",
				Source: "file", Files: []string{path}, Identity: model.Sanitize(e.User)}
			order = append(order, h)
		}
	} else if !os.IsNotExist(err) {
		notes = append(notes, "could not read hosts file")
	}

	fileFailed := len(notes) > 0
	hosts := append([]string(nil), order...)
	if h := getenv("GH_HOST"); h != "" {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, defaultHost)
	setOf := func(names ...string) (set []string) {
		for _, n := range names {
			if getenv(n) != "" {
				set = append(set, n)
			}
		}
		return set
	}
	addEnv := func(host string, set []string) {
		if len(set) == 0 {
			return
		}
		c := byHost[host]
		if c == nil {
			c = &model.Credential{Tool: "gh", ID: host, Label: model.Sanitize(host), Kind: "env-token", Source: "env"}
			byHost[host] = c
			order = append(order, host)
		}
		c.EnvVars = append(c.EnvVars, set...)
	}
	enterprise := setOf("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
	seenHost, haveEnterpriseHost := map[string]bool{}, false
	for _, h := range hosts {
		if seenHost[h] {
			continue
		}
		seenHost[h] = true
		if h == defaultHost || strings.HasSuffix(h, ".ghe.com") || h == "github.localhost" {
			addEnv(h, setOf("GH_TOKEN", "GITHUB_TOKEN"))
		} else {
			haveEnterpriseHost = true
			addEnv(h, enterprise)
		}
	}
	// A real host always keeps its name: placeholders are added only when the ID is free,
	// and only placeholders added here are skipped by Resolve.
	placeholder := func(c model.Credential) {
		if byHost[c.ID] == nil {
			byHost[c.ID] = &c
			order = append(order, c.ID)
			s.skip[c.ID] = true
		}
	}
	if len(enterprise) > 0 && !haveEnterpriseHost {
		placeholder(model.Credential{Tool: "gh", ID: "enterprise", Label: "enterprise", Kind: "env-token", Source: "env",
			EnvVars: enterprise, Notes: []string{"host unknown"}})
	}
	if fileFailed && len(byHost) == 0 {
		placeholder(model.Credential{Tool: "gh", ID: "unreadable", Label: "unreadable", Kind: "unknown", Source: "file", Files: []string{path}})
	}

	sort.Strings(order)
	creds := make([]model.Credential, 0, len(order))
	for _, h := range order {
		c := *byHost[h]
		c.Notes = append(c.Notes, notes...)
		creds = append(creds, c)
	}
	return creds, nil
}
