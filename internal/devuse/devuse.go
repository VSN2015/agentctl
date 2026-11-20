// Package devuse reads shell history to learn whether the developer, not the
// agent, uses a tool. History can only prove use, never absence, and it keeps no
// command text: each line goes through shellparse.Parse and is discarded.
package devuse

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/VSN2015/agentctl/internal/usage/shellparse"
)

// maxLine is the longest command (after joining continuation lines) that is parsed; longer ones are skipped.
const maxLine = 256 << 10

// Use is the developer's use of one tool and target.
type Use struct {
	Last  time.Time // latest timestamped entry; zero when Dated is false
	Dated bool      // false when no entry had a timestamp (unknown, not recent)
	Count int       // entries seen, dated or not
}

// History is the developer use found in shell history.
type History struct {
	uses   map[string]Use
	Unread int // history files that exist but could not be read; the caller must not claim "unused"
}

var (
	zshEntry = regexp.MustCompile(`^: (\d+):\d+;(.*)$`)
	bashTime = regexp.MustCompile(`^#(\d{1,12})$`)
)

// Read parses zsh ($ZDOTDIR or home .zsh_history), bash (.bash_history) and
// $HISTFILE history. Missing files are not an error; unreadable ones count in Unread.
func Read(home string, getenv func(string) string) History {
	h := History{uses: map[string]Use{}}
	zdot := home
	if d := getenv("ZDOTDIR"); d != "" {
		zdot = d
	}
	seen := map[string]bool{}
	for _, p := range []string{filepath.Join(zdot, ".zsh_history"), filepath.Join(home, ".bash_history"), getenv("HISTFILE")} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		f, err := os.Open(p)
		if err != nil {
			if !os.IsNotExist(err) {
				h.Unread++
			}
			continue
		}
		if err := h.scan(f); err != nil {
			h.Unread++
		}
		f.Close()
	}
	return h
}

// readLine returns the next line; tooLong is true when it exceeded maxLine (its text is dropped).
func readLine(r *bufio.Reader) (line string, tooLong bool, err error) {
	var b []byte
	for {
		part, more, err := r.ReadLine()
		if err != nil {
			return "", false, err
		}
		if len(b)+len(part) > maxLine {
			tooLong = true
		} else {
			b = append(b, part...)
		}
		if !more {
			return string(b), tooLong, nil
		}
	}
}

func (h *History) scan(f io.Reader) error {
	r := bufio.NewReaderSize(f, 64<<10)
	var pending int64 // bash "#<unix>" line applies to the next command
	for {
		line, skip, err := readLine(r)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		ts := pending
		pending = 0
		if m := bashTime.FindStringSubmatch(line); m != nil && !skip {
			pending, _ = strconv.ParseInt(m[1], 10, 64)
			continue
		}
		if m := zshEntry.FindStringSubmatch(line); m != nil && !skip {
			ts, _ = strconv.ParseInt(m[1], 10, 64)
			line = m[2]
		}
		// zsh continues an entry onto the next line after a trailing backslash.
		for strings.HasSuffix(line, `\`) {
			next, nskip, err := readLine(r)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			skip = skip || nskip || len(line)+len(next) > maxLine
			if !skip {
				line += "\n" + next
			}
			if !strings.HasSuffix(next, `\`) {
				break
			}
		}
		if !skip {
			h.add(line, ts)
		}
	}
}

func (h *History) add(command string, ts int64) {
	for _, inv := range shellparse.Parse(command) {
		k := inv.Tool + "\x00" + inv.Target
		u := h.uses[k]
		u.Count++
		if ts > 0 {
			if t := time.Unix(ts, 0); !u.Dated || t.After(u.Last) {
				u.Last = t
			}
			u.Dated = true
		}
		h.uses[k] = u
	}
}

// Lookup returns the developer's use of tool with target; target "" matches only un-named use.
func (h History) Lookup(tool, target string) (Use, bool) {
	u, ok := h.uses[tool+"\x00"+target]
	return u, ok
}
