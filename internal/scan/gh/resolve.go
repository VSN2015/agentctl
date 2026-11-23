package gh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

// Resolve runs one read-only `gh api user` call against the credential's host.
func (s *Scanner) Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error) {
	switch {
	case c.Host == "":
		return nil, &scan.SkipError{Reason: "no host to query"}
	case c.Kind == "env-token": // gh prefers the environment token
	case c.Kind == "file-host" && !s.envHost[c.Host]: // active stored account, nothing overrides it
	default:
		return nil, nil // gh answers for another token; leave this one unchecked, without a note
	}
	// ExecRunner inherits the parent environment (scan/runner.go:27), so a GH_TOKEN set for
	// agentctl is what gh uses here.
	out, err := s.run.Run(ctx, "gh", []string{"api", "-i", "--hostname", c.Host, "user"},
		[]string{"GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1"})
	if errors.Is(err, exec.ErrNotFound) {
		return nil, &scan.SkipError{Reason: "gh not installed"}
	}
	if err != nil { // raw output may hold response text; report only the fact
		return nil, errors.New("gh api user failed")
	}
	login, scopes, readable, err := ParseAPIResponse(out)
	if err != nil {
		return nil, err
	}
	// GitHub logins are case-insensitive.
	// shortcut: a host entry with no known user accepts any login; tighten if gh starts exposing the account name offline.
	if c.Kind == "file-host" && c.Identity != "" && !strings.EqualFold(login, c.Identity) {
		return nil, errors.New("gh answered for a different account than hosts.yml names")
	}
	return &model.Resolution{Identity: model.Sanitize(login), Scopes: scopes, ScopesReadable: readable}, nil
}

// ParseAPIResponse parses `gh api -i` output: status line, headers, blank line, JSON body.
// A missing X-Oauth-Scopes header means scopes are not readable (e.g. fine-grained tokens).
func ParseAPIResponse(raw []byte) (login string, scopes []string, scopesReadable bool, err error) {
	// gh prints the status line ending "\n", header lines ending "\r\n", then "\r\n" before the body.
	head, body, ok := bytes.Cut(raw, []byte("\n\r\n"))
	if !ok {
		return "", nil, false, errors.New("unexpected gh api output")
	}
	for _, line := range strings.Split(string(head), "\n")[1:] {
		name, val, found := strings.Cut(strings.TrimSuffix(line, "\r"), ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "x-oauth-scopes") {
			scopesReadable, scopes = true, []string{}
			for _, s := range strings.Split(val, ",") {
				if s = strings.TrimSpace(s); s != "" {
					scopes = append(scopes, s)
				}
			}
		}
	}
	var u struct {
		Login string `json:"login"`
	}
	if json.Unmarshal(body, &u) != nil || u.Login == "" {
		return "", nil, false, errors.New("gh api output has no login")
	}
	return u.Login, scopes, scopesReadable, nil
}
