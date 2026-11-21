package aws

import (
	"bufio"
	"io"
	"strings"
)

// parseINI reads an AWS shared-config file. keep maps an allowed key to
// whether its value is stored (true) or only its presence, as "1" (false).
// Every other key is discarded at parse time, so secrets are never retained.
func parseINI(r io.Reader, keep map[string]bool) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	var cur map[string]string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				cur = nil
				continue
			}
			name := strings.TrimSpace(line[1:end])
			if out[name] == nil {
				out[name] = map[string]string{}
			}
			cur = out[name]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || cur == nil {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		store, allowed := keep[k]
		if !allowed {
			continue
		}
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		if !store {
			v = "1"
		}
		cur[k] = v
	}
	return out, sc.Err()
}
