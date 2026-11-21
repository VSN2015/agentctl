// Package render turns a Report into text or JSON. It reads struct fields only
// and knows no tool or agent names.
package render

import (
	"time"

	"github.com/VSN2015/agentctl/internal/model"
)

// Report is everything one run found, as data.
type Report struct {
	SchemaVersion int
	GeneratedAt   time.Time
	Command       string
	Offline       bool
	WindowDays    int
	WindowHours   int
	HistoryDays   int
	HistoryUnread int // agent history items that could not be read
	Agents        []string
	Credentials   []model.Credential
	Findings      []model.Finding
	Notes         []string
}

// Style selects the look of the text report; both false means plain ASCII.
type Style struct{ Color, Fancy bool }
