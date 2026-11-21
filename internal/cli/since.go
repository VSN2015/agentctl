package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseSince parses durations such as "30d", "12h", "90m" and "1d12h"; the result must be > 0.
func ParseSince(s string) (time.Duration, error) {
	var total time.Duration
	rest := s
	if i := strings.IndexByte(s, 'd'); i >= 0 {
		days, err := strconv.Atoi(s[:i])
		if err != nil {
			return 0, fmt.Errorf("invalid --since %q", s)
		}
		total = time.Duration(days) * 24 * time.Hour
		rest = s[i+1:]
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid --since %q", s)
		}
		total += d
	}
	if total <= 0 {
		return 0, fmt.Errorf("invalid --since %q: must be greater than zero", s)
	}
	return total, nil
}
