// Package model holds the types shared by scanners, agents, rules and renderers.
package model

import "time"

type AgentAccess string

const (
	AccessDenied  AgentAccess = "denied"
	AccessAsks    AgentAccess = "asks"
	AccessAllowed AgentAccess = "allowed"
)

type Severity int

const (
	SevOK Severity = iota
	SevLow
	SevMed
	SevHigh
)

func (s Severity) String() string {
	switch s {
	case SevOK:
		return "OK"
	case SevLow:
		return "LOW"
	case SevMed:
		return "MED"
	case SevHigh:
		return "HIGH"
	}
	return "UNKNOWN"
}

type Credential struct {
	Tool, ID, Label, Kind, Source string // Tool is the scanner Name(); ID unique per Tool; Source "file"|"env"|"chain"
	Provider                      string // display name from Scanner.Provider(), set by the pipeline after Discover
	Files                         []string
	EnvVars                       []string // variable NAMES only
	LongLived                     bool
	KeyID                         string // masked only
	Identity                      string // offline-known identity
	Access                        []AgentState
	Resolved                      *Resolution
	Notes                         []string
}

type AgentState struct {
	Agent       string
	Access      AgentAccess // about the tool only
	FileBlocked bool        // a deny rule covers the credential file; does not change Access
}

type Resolution struct {
	Identity           string
	AdminChecked       bool // Admin is meaningful only when AdminChecked; false means the policies could not be read (see AdminWhy)
	Admin              bool
	AdminWhy           string
	Scopes             []string
	ScopesReadable     bool
	KeyChecked         bool
	KeyLastUsed        *time.Time // KeyChecked && nil => provider says never used
	KeyLastUsedService string     // provider's service name for the last use, e.g. "sts"; a last use by "sts" or "iam" may be this tool's own check
}

type Finding struct {
	ID          string
	Rules       []string
	Severity    Severity
	Agent       string
	Tool        string
	Subject     string
	Headline    string
	Details     []string
	Advice      []string
	Access      AgentAccess
	FileBlocked bool
}
