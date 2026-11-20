package rules

import (
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
	Count       int
	Last        time.Time
	State       UseState
	HistoryDays int
	Calls       []usage.Call
}

const usedCalls = 3

func agentUse(u usage.Usage, calls []usage.Call, unattributed int, window time.Duration, now time.Time) AgentUse {
	r := AgentUse{Count: len(calls), HistoryDays: u.HistoryDays(now), Calls: calls}
	for _, c := range calls {
		if c.At.After(r.Last) {
			r.Last = c.At
		}
	}
	switch {
	case r.Count >= usedCalls:
		r.State = UseUsed
	case r.Count == 0 && unattributed > 0:
		r.State = UseUnattributable
	case u.Unread > 0 || r.HistoryDays < int(window/(24*time.Hour)):
		r.State = UseUnknown
	case r.Count == 0:
		r.State = UseUnused
	default:
		r.State = UseRare
	}
	return r
}
