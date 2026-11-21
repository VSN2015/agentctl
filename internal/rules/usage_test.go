package rules

import (
	"testing"
	"time"
)

func TestWindowTextSingular(t *testing.T) {
	for w, want := range map[time.Duration]string{time.Hour: "1 hour", 12 * time.Hour: "12 hours", 24 * time.Hour: "1 day", 48 * time.Hour: "2 days"} {
		if got := WindowText(w); got != want {
			t.Errorf("%v: %q, want %q", w, got, want)
		}
	}
}
