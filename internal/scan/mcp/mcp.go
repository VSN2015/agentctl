// Package mcp lists the MCP servers configured in Claude Code's .claude.json.
//
// Covered: user-scope mcpServers and per-project projects.<path>.mcpServers.
// Not covered: .mcp.json project files, plugin servers, claude.ai connectors, managed MCP files and
// disabledMcpServers. Only each server's name and its "type" are decoded, so env, headers, url, args,
// command and every other key (such as oauthAccount) are never held in a returned value.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string     { return "mcp" }
func (s *Scanner) Provider() string { return "MCP" }
func (s *Scanner) LocalOnly()       {}

func (s *Scanner) Resolve(context.Context, model.Credential) (*model.Resolution, error) {
	return nil, &scan.SkipError{Reason: "nothing to resolve online"}
}

var (
	errBad   = errors.New("could not read or parse Claude Code configuration") // never wraps the decoder's error: it can quote the file
	badChars = regexp.MustCompile(`[^A-Za-z0-9_-]`)
)

func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error) {
	dir := env.Home
	if env.Getenv != nil {
		if d := env.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
			if !filepath.IsAbs(d) {
				return nil, errors.New("configuration directory is not an absolute path")
			}
			dir = d
		}
	}
	if dir == "" {
		return nil, nil
	}
	buf, err := model.ReadRegularFile(filepath.Join(dir, ".claude.json"))
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(buf)) == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, errBad
	}
	// exact key lookup: encoding/json's struct decoding would match "MCPServers" too
	var top map[string]json.RawMessage
	if json.Unmarshal(buf, &top) != nil {
		return nil, errBad
	}
	servers := []map[string]json.RawMessage{}
	add := func(raw json.RawMessage) bool {
		var m map[string]json.RawMessage
		if raw != nil && json.Unmarshal(raw, &m) != nil {
			return false
		}
		servers = append(servers, m)
		return true
	}
	if !add(top["mcpServers"]) {
		return nil, errBad
	}
	var projects map[string]json.RawMessage
	if raw, ok := top["projects"]; ok && json.Unmarshal(raw, &projects) != nil {
		return nil, errBad
	}
	paths := make([]string, 0, len(projects))
	for p := range projects {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		var proj map[string]json.RawMessage
		if json.Unmarshal(projects[p], &proj) != nil || !add(proj["mcpServers"]) {
			return nil, errBad
		}
	}

	var creds []model.Credential
	seen := map[string]bool{}
	for _, m := range servers {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			id := badChars.ReplaceAllString(name, "_")
			if name == "" || seen[id] {
				continue
			}
			seen[id] = true
			creds = append(creds, model.Credential{Tool: "mcp", ID: id, Label: model.Sanitize(name), Kind: kindOf(m[name]), Source: "file"})
		}
	}
	sort.Slice(creds, func(i, j int) bool { return creds[i].ID < creds[j].ID })
	return creds, nil
}

// kindOf decodes only the "type" key of a server object (exact match); anything unexpected is "unknown".
func kindOf(raw json.RawMessage) string {
	var o map[string]json.RawMessage
	if json.Unmarshal(raw, &o) != nil {
		return "unknown"
	}
	v, ok := o["type"]
	if !ok {
		return "stdio"
	}
	var t string
	if json.Unmarshal(v, &t) != nil {
		return "unknown"
	}
	switch t {
	case "", "stdio":
		return "stdio"
	case "http", "sse":
		return t
	}
	return "unknown"
}
