package cli

import (
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	ok := map[string]time.Duration{
		"30d": 720 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute, "1d12h": 36 * time.Hour,
	}
	for in, want := range ok {
		got, err := ParseSince(in)
		if err != nil || got != want {
			t.Errorf("ParseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "-5d", "abc", "30"} {
		if got, err := ParseSince(in); err == nil {
			t.Errorf("ParseSince(%q) = %v, nil; want error", in, got)
		}
	}
}
