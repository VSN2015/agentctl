package claude

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
)

// Settings is the merged permission state from every readable Claude Code settings file.
type Settings struct {
	Allow, Ask, Deny []string
	DefaultMode      string   // effective mode after precedence and honouring; "" when no file sets one
	Sources          []string // files that were read and parsed
	Notes            []string // unreadable, invalid, or ignored settings; file paths only, never contents
}

// ManagedPaths returns the managed settings file for goos; drop-ins live next to it in managed-settings.d.
func ManagedPaths(goos string) []string {
	switch goos {
	case "darwin":
		return []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}
	case "linux":
		return []string{"/etc/claude-code/managed-settings.json"}
	}
	return nil
}

// Load reads user settings.json, project settings.json and settings.local.json, then the managed
// files (each followed by its managed-settings.d/*.json in name order). Later sources have higher
// precedence for defaultMode; rule lists merge. Project files only widen access (their allow rules
// count; deny, ask and defaultMode are noted and ignored). It never fails: problems become Notes.
func Load(configDir, projectDir string, managed []string) Settings {
	var s Settings
	s.read(filepath.Join(configDir, "settings.json"), false)
	s.read(filepath.Join(projectDir, ".claude", "settings.json"), true)
	s.read(filepath.Join(projectDir, ".claude", "settings.local.json"), true)
	for _, m := range managed {
		s.read(m, false)
		drops, _ := filepath.Glob(filepath.Join(filepath.Dir(m), "managed-settings.d", "*.json"))
		sort.Strings(drops)
		for _, d := range drops {
			if strings.HasPrefix(filepath.Base(d), ".") {
				continue // Claude Code ignores hidden drop-ins
			}
			s.read(d, false)
		}
	}
	return s
}

// read merges one file. A project file (project true) is the current project's only: it may widen
// access with allow rules, but its deny, ask and defaultMode would otherwise let one repo decide a
// machine-wide verdict, so they are not counted.
func (s *Settings) read(path string, project bool) {
	b, err := model.ReadRegularFile(path)
	if os.IsNotExist(err) || (err == nil && len(bytes.TrimSpace(b)) == 0) {
		return
	}
	// exact key lookup: encoding/json's struct decoding would match "Deny" or "PERMISSIONS" too
	var p permissions
	if err == nil {
		err = decodePermissions(b, &p)
	}
	if err != nil {
		s.Notes = append(s.Notes, "settings file unreadable or invalid, skipped: "+path)
		return
	}
	s.Sources = append(s.Sources, path)
	s.Allow = append(s.Allow, p.Allow...)
	if project {
		if len(p.Deny)+len(p.Ask) > 0 || p.DefaultMode != "" {
			s.Notes = append(s.Notes, path+": deny, ask and defaultMode settings apply to this project only and are not counted")
		}
		return
	}
	s.Ask, s.Deny = append(s.Ask, p.Ask...), append(s.Deny, p.Deny...)
	switch p.DefaultMode {
	case "":
	case "manual":
		s.DefaultMode = "default"
	case "default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions":
		s.DefaultMode = p.DefaultMode
	default:
		s.Notes = append(s.Notes, path+": unknown defaultMode ignored")
	}
}

type permissions struct {
	Allow, Ask, Deny []string
	DefaultMode      string
}

func decodePermissions(b []byte, p *permissions) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return err
	}
	raw, ok := top["permissions"]
	if !ok {
		return nil
	}
	var perms map[string]json.RawMessage
	if err := json.Unmarshal(raw, &perms); err != nil {
		return err
	}
	for key, dst := range map[string]any{"allow": &p.Allow, "ask": &p.Ask, "deny": &p.Deny, "defaultMode": &p.DefaultMode} {
		if v, ok := perms[key]; ok {
			if err := json.Unmarshal(v, dst); err != nil {
				return err
			}
		}
	}
	return nil
}

// bashMatches reports whether rule applies to shell tool T: Bash with an empty, "*", "T *", "T:*" or "T*"
// specifier. Bash(T) is an exact-command rule and does not match the tool.
func bashMatches(rule, tool string) bool {
	if rule == "Bash" {
		return true
	}
	spec, ok := strings.CutPrefix(rule, "Bash(")
	if !ok {
		return false
	}
	spec, ok = strings.CutSuffix(spec, ")")
	return ok && (spec == "" || spec == "*" || spec == tool+" *" || spec == tool+":*" || spec == tool+"*")
}

func anyMatch(rules []string, f func(string) bool) bool {
	for _, r := range rules {
		if f(r) {
			return true
		}
	}
	return false
}

// Classify returns the agent's access to the credential's tool (Bash rules only) and whether a
// Read deny covers any of the credential's files. Neither result affects the other.
func (s Settings) Classify(c model.Credential, home string) (model.AgentAccess, bool) {
	tool := func(r string) bool { return bashMatches(r, c.Tool) }
	mode := s.DefaultMode
	var access model.AgentAccess
	switch {
	case anyMatch(s.Deny, tool):
		access = model.AccessDenied
	case anyMatch(s.Ask, tool):
		access = model.AccessAsks
		if mode == "dontAsk" {
			access = model.AccessDenied
		}
	case anyMatch(s.Allow, tool) || mode == "bypassPermissions" || mode == "auto":
		access = model.AccessAllowed
	case mode == "dontAsk":
		access = model.AccessDenied // the agent cannot prompt, so an unlisted tool is refused
	default:
		access = model.AccessAsks
	}
	blocked := false
	for _, f := range c.Files {
		if anyMatch(s.Deny, func(r string) bool { return readCovers(r, f, home) }) {
			blocked = true
		}
	}
	return access, blocked
}

// readCovers reports whether a Read(...) rule covers file. "~/" is home and "//" is a filesystem
// root; a single leading "/" is relative to the settings source, so it is never matched.
// shortcut: only a trailing /** or /* and exact paths are understood, other globs never match; extend if real rules need them.
func readCovers(rule, file, home string) bool {
	pat, ok := strings.CutPrefix(rule, "Read(")
	if !ok {
		return false
	}
	if pat, ok = strings.CutSuffix(pat, ")"); !ok {
		return false
	}
	switch {
	case strings.HasPrefix(pat, "~/"):
		pat = filepath.Join(home, pat[2:])
	case strings.HasPrefix(pat, "//"):
		pat = pat[1:]
	default:
		return false
	}
	if dir, ok := strings.CutSuffix(pat, "/**"); ok {
		return file == dir || strings.HasPrefix(file, dir+"/")
	}
	if dir, ok := strings.CutSuffix(pat, "/*"); ok {
		return file == dir || strings.HasPrefix(file, dir+"/")
	}
	return file == pat
}

// UnrestrictedShell is true when every shell command runs without a prompt: an allow rule for all
// of Bash, or an honoured bypassPermissions or auto mode, unless all of Bash is denied.
func (s Settings) UnrestrictedShell() bool {
	all := func(r string) bool { return r == "Bash" || r == "Bash()" || r == "Bash(*)" }
	if anyMatch(s.Deny, all) {
		return false
	}
	return anyMatch(s.Allow, all) || s.DefaultMode == "bypassPermissions" || s.DefaultMode == "auto"
}
