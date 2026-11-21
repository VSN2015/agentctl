package claude

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VSN2015/agentctl/internal/usage"
	"github.com/VSN2015/agentctl/internal/usage/shellparse"
)

const (
	probeLines = 50             // lines checked for a file's first timestamp
	futureSkew = 24 * time.Hour // records further ahead of now are ignored
)

type record struct {
	Timestamp time.Time `json:"timestamp"`
	Message   struct {
		Content []struct {
			Type  string `json:"type"`
			ID    string `json:"id"`
			Name  string `json:"name"`
			Input struct {
				Command string `json:"command"`
			} `json:"input"`
		} `json:"content"`
	} `json:"message"`
}

// readUsage reads the Claude Code transcripts under configDir/projects and
// returns the tool calls made at or after since. Unreadable or malformed input
// is skipped; only a cancelled context is an error. Command text is parsed by
// shellparse and never stored.
func readUsage(ctx context.Context, configDir string, since, now time.Time) (usage.Usage, error) {
	u := usage.Usage{Agent: "claude", Since: since}
	seen := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(configDir, "projects"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				u.Unread++
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil || !readFile(path, info.ModTime().Before(since), &u, seen, since, now) {
			u.Unread++
		}
		return nil
	})
	return u, err
}

// readFile adds one transcript to u and reports whether it was read without I/O error.
// A stale file is only probed for its first timestamp.
func readFile(path string, stale bool, u *usage.Usage, seen map[string]bool, since, now time.Time) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	r := bufio.NewReader(f)
	first := false
	for n := 0; ; n++ {
		line, err := r.ReadBytes('\n') // no line-length limit
		if len(line) > 0 {
			first = handleLine(line, n < probeLines && !first, stale, u, seen, since, now) || first
		}
		if err != nil || (stale && (first || n >= probeLines)) {
			return err == nil || err == io.EOF // else read error; EOF or probe done is fine
		}
	}
}

// handleLine reports whether the line supplied the file's first timestamp.
func handleLine(line []byte, wantFirst, stale bool, u *usage.Usage, seen map[string]bool, since, now time.Time) bool {
	hasTool := !stale && bytes.Contains(line, []byte(`"tool_use"`))
	if !hasTool && !wantFirst {
		return false
	}
	var rec record
	if json.Unmarshal(line, &rec) != nil || rec.Timestamp.IsZero() || rec.Timestamp.After(now.Add(futureSkew)) {
		return false
	}
	if u.HistoryStart.IsZero() || rec.Timestamp.Before(u.HistoryStart) {
		u.HistoryStart = rec.Timestamp
	}
	if hasTool && !rec.Timestamp.Before(since) {
		for _, c := range rec.Message.Content {
			if c.Type != "tool_use" || (c.ID != "" && seen[c.ID]) {
				continue
			}
			seen[c.ID] = true
			addCall(u, rec.Timestamp, c.Name, c.Input.Command)
		}
	}
	return true
}

func addCall(u *usage.Usage, at time.Time, name, command string) {
	if name == "Bash" {
		for _, inv := range shellparse.Parse(command) {
			u.Shell = append(u.Shell, usage.Call{At: at, Invocation: inv})
		}
	} else if rest, ok := strings.CutPrefix(name, "mcp__"); ok {
		if server, tool, ok := strings.Cut(rest, "__"); ok && server != "" && tool != "" {
			u.MCP = append(u.MCP, usage.MCPCall{At: at, Server: server, Tool: tool})
		}
	}
}
