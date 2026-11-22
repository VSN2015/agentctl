// Package kubectl lists the contexts in the user's kubeconfig files and reports an in-cluster
// service-account token.
//
// Covered: kubeconfig contexts (KUBECONFIG, else ~/.kube/config; a context whose name or cluster
// looks like production is marked) and the mounted in-cluster token file (only stat-ed, never read).
// Not covered: users and their credentials, exec plugins, and anything that needs a cluster call.
// Only contexts[].name and contexts[].context.cluster are decoded, so no secret is ever held.
package kubectl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

type Scanner struct {
	saToken string // tests override this
}

func New() *Scanner {
	return &Scanner{saToken: "/var/run/secrets/kubernetes.io/serviceaccount/token"}
}

func (s *Scanner) Name() string     { return "kubectl" }
func (s *Scanner) Provider() string { return "kubectl" }
func (s *Scanner) LocalOnly()       {}

func (s *Scanner) Resolve(context.Context, model.Credential) (*model.Resolution, error) {
	return nil, &scan.SkipError{Reason: "nothing to resolve online"}
}

type kubeconfig struct {
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

// isProd reports whether s has an occurrence of "prod" not directly preceded by non, non- or non_.
func isProd(s string) bool {
	s = strings.ToLower(s)
	for i := 0; ; {
		j := strings.Index(s[i:], "prod")
		if j < 0 {
			return false
		}
		j += i
		before := s[:j]
		if !strings.HasSuffix(before, "non") && !strings.HasSuffix(before, "non-") && !strings.HasSuffix(before, "non_") {
			return true
		}
		i = j + 1
	}
}

func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	var paths []string
	if k := getenv("KUBECONFIG"); k != "" {
		for _, p := range filepath.SplitList(k) {
			if p != "" {
				paths = append(paths, p)
			}
		}
	} else if env.Home != "" {
		paths = []string{filepath.Join(env.Home, ".kube", "config")}
	}

	var creds []model.Credential
	var errs []error
	seen := map[string]bool{}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			errs = append(errs, fmt.Errorf("kubeconfig path is not absolute: %s", model.Sanitize(p)))
			continue
		}
		buf, err := model.ReadRegularFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var kc kubeconfig
		if err == nil {
			err = yaml.Unmarshal(buf, &kc)
		}
		if err != nil { // never include err: yaml quotes file content
			errs = append(errs, fmt.Errorf("could not read or parse %s", model.Sanitize(p)))
			continue
		}
		for _, c := range kc.Contexts {
			if c.Name == "" || seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			kind := "context"
			if isProd(c.Name) || isProd(c.Context.Cluster) {
				kind = "production-context"
			}
			creds = append(creds, model.Credential{Tool: "kubectl", ID: c.Name, Label: model.Sanitize(c.Name), Kind: kind,
				Identity: model.Sanitize(c.Context.Cluster), Source: "file", Files: []string{p}})
		}
	}
	if getenv("KUBERNETES_SERVICE_HOST") != "" {
		if fi, err := os.Stat(s.saToken); err == nil && fi.Mode().IsRegular() {
			creds = append(creds, model.Credential{Tool: "kubectl", ID: "serviceaccount:in-cluster",
				Label: "in-cluster service account", Kind: "serviceaccount", Source: "file", Files: []string{s.saToken},
				Notes: []string{"token mounted in this pod; what it can do is not resolved"}})
		}
	}
	sort.Slice(creds, func(i, j int) bool { return creds[i].ID < creds[j].ID })
	return creds, errors.Join(errs...)
}
