// Package gh finds GitHub CLI credentials and asks GitHub who they belong to.
package gh

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
	"go.yaml.in/yaml/v3"
)

const defaultHost = "github.com"

type Scanner struct{ run scan.Runner }

func New(r scan.Runner) *Scanner { return &Scanner{run: r} }

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

	addEnv := func(host string, names ...string) {
		var set []string
		for _, n := range names {
			if getenv(n) != "" {
				set = append(set, n)
			}
		}
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
	addEnv(defaultHost, "GH_TOKEN", "GITHUB_TOKEN")
	if h := getenv("GH_HOST"); h != "" && h != defaultHost {
		addEnv(h, "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
	}

	sort.Strings(order)
	creds := make([]model.Credential, 0, len(order))
	for _, h := range order {
		c := *byHost[h]
		c.Notes = notes
		creds = append(creds, c)
	}
	return creds, nil
}
