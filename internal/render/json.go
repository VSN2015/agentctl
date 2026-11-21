package render

import (
	"encoding/json"
	"io"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
)

// The model has no json tags by design; these DTOs are the stable --json contract:
// fields are added, never renamed or removed, without bumping schema_version.
type jsonReport struct {
	SchemaVersion int              `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Command       string           `json:"command"`
	Offline       bool             `json:"offline"`
	WindowDays    int              `json:"window_days"`
	WindowHours   int              `json:"window_hours"`
	HistoryDays   int              `json:"history_days"`
	HistoryUnread int              `json:"history_unread"`
	Agents        []string         `json:"agents"`
	Credentials   []jsonCredential `json:"credentials"`
	Findings      []jsonFinding    `json:"findings"`
	Notes         []string         `json:"notes"`
}

type jsonCredential struct {
	Tool      string          `json:"tool"`
	Provider  string          `json:"provider"`
	ID        string          `json:"id"`
	Label     string          `json:"label"`
	Kind      string          `json:"kind"`
	Source    string          `json:"source"`
	Files     []string        `json:"files"`
	EnvVars   []string        `json:"env_vars"`
	LongLived bool            `json:"long_lived"`
	KeyID     string          `json:"key_id"`
	Identity  string          `json:"identity"`
	Agents    []jsonAgent     `json:"agents"`
	Resolved  *jsonResolution `json:"resolved"`
	Notes     []string        `json:"notes"`
}

type jsonAgent struct {
	Agent       string `json:"agent"`
	Access      string `json:"access"`
	FileBlocked bool   `json:"file_blocked"`
}

type jsonResolution struct {
	Identity           string   `json:"identity"`
	AdminChecked       bool     `json:"admin_checked"`
	Admin              bool     `json:"admin"`
	AdminWhy           string   `json:"admin_why"`
	Scopes             []string `json:"scopes"`
	ScopesReadable     bool     `json:"scopes_readable"`
	KeyChecked         bool     `json:"key_checked"`
	KeyLastUsed        *string  `json:"key_last_used"`
	KeyLastUsedService string   `json:"key_last_used_service"`
}

type jsonFinding struct {
	ID          string   `json:"id"`
	Rules       []string `json:"rules"`
	Severity    string   `json:"severity"`
	Agent       string   `json:"agent"`
	Tool        string   `json:"tool"`
	Subject     string   `json:"subject"`
	Headline    string   `json:"headline"`
	Details     []string `json:"details"`
	Advice      []string `json:"advice"`
	Access      string   `json:"access"`
	FileBlocked bool     `json:"file_blocked"`
}

func list(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// JSON writes the report as one indented JSON document.
func JSON(w io.Writer, r Report) error {
	out := jsonReport{
		SchemaVersion: r.SchemaVersion, GeneratedAt: rfc3339(r.GeneratedAt), Command: r.Command, Offline: r.Offline,
		WindowDays: r.WindowDays, WindowHours: r.WindowHours, HistoryDays: r.HistoryDays, HistoryUnread: r.HistoryUnread,
		Agents: list(r.Agents), Notes: list(r.Notes),
		Credentials: make([]jsonCredential, 0, len(r.Credentials)), Findings: make([]jsonFinding, 0, len(r.Findings)),
	}
	for _, c := range r.Credentials {
		out.Credentials = append(out.Credentials, toJSONCredential(c))
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			ID: f.ID, Rules: list(f.Rules), Severity: f.Severity.String(), Agent: f.Agent, Tool: f.Tool, Subject: f.Subject,
			Headline: f.Headline, Details: list(f.Details), Advice: list(f.Advice), Access: string(f.Access), FileBlocked: f.FileBlocked})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func toJSONCredential(c model.Credential) jsonCredential {
	jc := jsonCredential{
		Tool: c.Tool, Provider: c.Provider, ID: c.ID, Label: c.Label, Kind: c.Kind, Source: c.Source, Files: list(c.Files),
		EnvVars: list(c.EnvVars), LongLived: c.LongLived, KeyID: c.KeyID, Identity: c.Identity, Notes: list(c.Notes),
		Agents: make([]jsonAgent, 0, len(c.Access)),
	}
	for _, a := range c.Access {
		jc.Agents = append(jc.Agents, jsonAgent{Agent: a.Agent, Access: string(a.Access), FileBlocked: a.FileBlocked})
	}
	if rs := c.Resolved; rs != nil {
		jr := &jsonResolution{Identity: rs.Identity, AdminChecked: rs.AdminChecked, Admin: rs.Admin, AdminWhy: rs.AdminWhy,
			Scopes: list(rs.Scopes), ScopesReadable: rs.ScopesReadable, KeyChecked: rs.KeyChecked, KeyLastUsedService: rs.KeyLastUsedService}
		if rs.KeyLastUsed != nil {
			v := rfc3339(*rs.KeyLastUsed)
			jr.KeyLastUsed = &v
		}
		jc.Resolved = jr
	}
	return jc
}
