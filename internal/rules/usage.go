package rules

import (
	"fmt"
	"time"

	"github.com/VSN2015/agentctl/internal/usage"
)

// UseState says how much the agent used a credential's tool in the window.
type UseState int

const (
	UseUsed           UseState = iota // 3 or more calls
	UseRare                           // 1 or 2 calls in a full-length history
	UseUnused                         // no calls in a full-length history
	UseUnknown                        // history too short or partly unreadable: no claim of "unused"
	UseUnattributable                 // calls exist that cannot be tied to this credential
)

// AgentUse is the agent's use of one credential. Calls holds the attributed calls
// so tool rules can see what the agent ran.
type AgentUse struct {
	Count        int
	Last         time.Time
	State        UseState
	HistoryDays  int
	Calls        []usage.Call
	Unattributed int // calls to the tool that cannot be tied to this credential
}

const usedCalls = 3

func agentUse(u usage.Usage, calls []usage.Call, unattributed int, window time.Duration, now time.Time) AgentUse {
	r := AgentUse{Count: len(calls), HistoryDays: u.HistoryDays(now), Calls: calls, Unattributed: unattributed}
	for _, c := range calls {
		if c.At.After(r.Last) {
			r.Last = c.At
		}
	}
	switch {
	case r.Count >= usedCalls:
		r.State = UseUsed
	case unattributed > 0: // own calls below the "used" threshold may be a fraction of this credential's real use
		r.State = UseUnattributable
	case u.Unread > 0 || u.HistoryStart.IsZero() || now.Sub(u.HistoryStart) < window:
		r.State = UseUnknown
	case r.Count == 0:
		r.State = UseUnused
	default:
		r.State = UseRare
	}
	return r
}

// windowText names the window for people: whole days, or hours when it is under a day or not a whole number of days.
func windowText(w time.Duration) string {
	if w >= 24*time.Hour && w%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", int(w/(24*time.Hour)))
	}
	return fmt.Sprintf("%d hours", max(1, int((w+time.Hour-1)/time.Hour)))
}
