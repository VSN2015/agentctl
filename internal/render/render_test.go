package render

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func at(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func state(a string, access model.AgentAccess, blocked bool) []model.AgentState {
	return []model.AgentState{{Agent: a, Access: access, FileBlocked: blocked}}
}

func fixedReport(cmd string) Report {
	return Report{
		SchemaVersion: 1, GeneratedAt: *at("2026-03-01T12:00:00Z"), Command: cmd, WindowDays: 30, WindowHours: 720, HistoryDays: 45, HistoryUnread: 1,
		Agents: []string{"agent-x"},
		Credentials: []model.Credential{
			{Tool: "t1", ID: "profile:prod", Label: "profile prod", Kind: "static key", Provider: "Prov1", Source: "file",
				KeyID: "AKIA****WXYZ", Identity: "", Access: state("agent-x", model.AccessAllowed, false)},
			{Tool: "t1", ID: "profile:dev", Label: "profile dev", Kind: "sso", Provider: "Prov1", Source: "file",
				EnvVars: []string{"T1_TOKEN"}, KeyID: "AKIA****ABCD",
				Resolved: &model.Resolution{Identity: "arn:dev", AdminChecked: true, Admin: true, AdminWhy: "AdministratorAccess",
					KeyChecked: true, KeyLastUsed: at("2026-02-20T08:00:00Z"), KeyLastUsedService: "s3"},
				Access: state("agent-x", model.AccessAllowed, false)},
			{Tool: "t1", ID: "profile:ro", Label: "profile ro", Kind: "static key", Provider: "Prov1", Source: "file", KeyID: "AKIA****EEEE",
				Resolved: &model.Resolution{Identity: "arn:ro", AdminWhy: "could not read policies"},
				Access:   state("agent-x", model.AccessAsks, false)},
			{Tool: "t2", ID: "github.com", Label: "github.com", Kind: "oauth token", Provider: "Prov2", Source: "file", Identity: "octo",
				Resolved: &model.Resolution{Identity: "octo", Scopes: []string{"repo", "workflow"}, ScopesReadable: true},
				Access:   state("agent-x", model.AccessAsks, false)},
			{Tool: "t2", ID: "ghe.example.com", Label: "ghe.example.com", Kind: "fine-grained", Provider: "Prov2", Source: "file",
				Resolved: &model.Resolution{Identity: "bot"}, Access: state("agent-x", model.AccessDenied, false)},
			{Tool: "t2", ID: "other.example.com", Label: "other.example.com", Kind: "oauth token", Provider: "Prov2", Source: "file",
				Access: state("agent-x", model.AccessAllowed, true)},
		},
		Findings: []model.Finding{
			{ID: "agent-x:t1:profile:dev", Severity: model.SevHigh, Agent: "agent-x", Tool: "t1", Subject: "profile:dev",
				Headline: "AdministratorAccess. Agent can reach it.", Access: model.AccessAllowed, Issue: "admin, unused", Used: "0", Details: []string{"Agent use, last 30 days: none"},
				Advice: []string{"The agent should not work with administrator rights: give it a profile with only the permissions it needs, or block the agent from AWS.",
					"Block the agent: deny t1", "Agent deny rules are advisory unless the agent runs in a sandbox."}},
			{ID: "agent-x:t1:profile:prod", Severity: model.SevHigh, Agent: "agent-x", Tool: "t1", Subject: "profile:prod",
				Headline: "static key, permissions unknown offline", Access: model.AccessAllowed, Issue: "long-lived key", Used: "2", Details: []string{"Agent use, last 30 days: 2 calls"},
				Advice: []string{"Replace the long-lived access key with short-lived credentials: sign in with IAM Identity Center (aws sso login) or use an assumed role."}},
			{ID: "agent-x:t2:github.com", Severity: model.SevMed, Agent: "agent-x", Tool: "t2", Subject: "github.com",
				Headline: "unused scopes", Access: model.AccessAsks, Issue: "extra scopes", Used: "12", Details: []string{"Scopes: repo, workflow"}, Advice: []string{"Replace the token"}},
			{ID: "agent-x:t2:other.example.com", Severity: model.SevMed, Agent: "agent-x", Tool: "t2", Subject: "other.example.com",
				Headline: "token reachable", Access: model.AccessAllowed, Issue: "file blocked, tool allowed", Used: "3?", Details: []string{"credential file blocked, tool still allowed"}, FileBlocked: true},
			{ID: "agent-x:t2:ghe.example.com", Severity: model.SevOK, Agent: "agent-x", Tool: "t2", Subject: "ghe.example.com",
				Headline: "denied by agent settings", Access: model.AccessDenied,
				Details: []string{"Permissions could not be read, so administrator access was not checked"}},
		},
		Notes: []string{"1 agent history file could not be read", "Prov1 profile x: online check skipped: needs login"},
	}
}

func TestRenderGolden(t *testing.T) {
	styles := map[string]Style{"plain": {}, "tty": {Color: true, Fancy: true}}
	for _, cmd := range []string{"doctor", "inventory"} {
		for name, st := range styles {
			var b bytes.Buffer
			if err := Text(&b, fixedReport(cmd), st); err != nil {
				t.Fatal(err)
			}
			if name == "plain" {
				for _, c := range b.Bytes() {
					if c > 0x7f || c == 0x1b {
						t.Fatalf("%s plain output has byte %#x", cmd, c)
					}
				}
			} else if !strings.Contains(b.String(), "·") || (cmd == "doctor" && !strings.Contains(b.String(), "\x1b[")) {
				t.Errorf("%s tty lacks fancy marks:\n%s", cmd, b.String())
			}
			golden(t, cmd+"-"+name+".golden", b.Bytes())
		}
		var b bytes.Buffer
		if err := JSON(&b, fixedReport(cmd)); err != nil {
			t.Fatal(err)
		}
		golden(t, cmd+".json.golden", b.Bytes())
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs; run with -update.\n--- got ---\n%s", name, got)
	}
}

func TestRenderOfflineVariantsAndAdminWording(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, fixedReport("inventory"), Style{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"credential file blocked, tool still allowed", "asks first", "allowed without asking", "denied",
		"permissions could not be read", "permissions cannot be read", "T1_TOKEN", "AKIA****WXYZ",
		"Key last used: 2026-02-20", "Key last used: could not check",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inventory lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not admin") || strings.Contains(out, "never used") {
		t.Errorf("claims on unchecked data:\n%s", out)
	}
}

func TestRenderNeverUsedOnlyWhenChecked(t *testing.T) {
	r := fixedReport("inventory")
	r.Credentials = r.Credentials[:1]
	r.Credentials[0].Resolved = &model.Resolution{KeyChecked: true, AdminChecked: true}
	var b bytes.Buffer
	if err := Text(&b, r, Style{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "never used") || !strings.Contains(b.String(), "Admin: no") {
		t.Errorf("checked credential:\n%s", b.String())
	}
}

func TestRenderSanitises(t *testing.T) {
	evil := "pr\x1b[31mod\u202e"
	r := Report{SchemaVersion: 1, Command: "doctor", Credentials: []model.Credential{{
		Tool: "t", ID: "i", Label: evil, Kind: evil, Provider: evil, Identity: evil, KeyID: evil, EnvVars: []string{evil}, Notes: []string{evil},
		Resolved: &model.Resolution{Identity: evil, AdminWhy: evil, Scopes: []string{evil}, ScopesReadable: true, KeyChecked: true, KeyLastUsedService: evil},
		Access:   state(evil, model.AccessAllowed, false)}},
		Findings: []model.Finding{{Tool: "t", Subject: evil, Headline: evil, Details: []string{evil}, Advice: []string{evil}, Severity: model.SevLow, Agent: evil}},
		Notes:    []string{evil}, Agents: []string{evil}}
	for _, cmd := range []string{"doctor", "inventory"} {
		r.Command = cmd
		var b bytes.Buffer
		if err := Text(&b, r, Style{}); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsRune(b.String(), 0x1b) || strings.ContainsRune(b.String(), 0x202e) || !strings.Contains(b.String(), "pr?[31mod?") {
			t.Errorf("%s not sanitised:\n%q", cmd, b.String())
		}
	}
}

func TestJSONValidAndStable(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, Report{SchemaVersion: 1, Command: "inventory"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema_version": 1`, `"findings": []`, `"credentials": []`, `"notes": []`, `"agents": []`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("empty report lacks %s:\n%s", want, b.String())
		}
	}
	b.Reset()
	r := fixedReport("doctor")
	r.Credentials[0].Label = "a\x1bb"
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Credentials []struct {
			Label    string
			Resolved *struct {
				KeyLastUsed  string `json:"key_last_used"`
				AdminChecked bool   `json:"admin_checked"`
			}
		}
		HistoryUnread int `json:"history_unread"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.Credentials
	if c[0].Label != "a\x1bb" || c[0].Resolved != nil || c[1].Resolved.KeyLastUsed != "2026-02-20T08:00:00Z" || !c[1].Resolved.AdminChecked || doc.HistoryUnread != 1 {
		t.Errorf("doc = %+v", doc)
	}
	if !strings.Contains(b.String(), `"resolved": null`) {
		t.Error("offline credential should have resolved null")
	}
}

func TestRenderEmptyHome(t *testing.T) {
	for _, cmd := range []string{"doctor", "inventory"} {
		var b bytes.Buffer
		if err := Text(&b, Report{SchemaVersion: 1, Command: cmd}, Style{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "No credentials found.") || !strings.Contains(b.String(), "advisory") {
			t.Errorf("%s:\n%s", cmd, b.String())
		}
	}
}

func TestRenderDoctorWithCredentialsButNoFindings(t *testing.T) {
	r := fixedReport("doctor")
	r.Findings = nil
	var b bytes.Buffer
	if err := Text(&b, r, Style{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No findings.\n") || !strings.Contains(b.String(), "  1 agent history") {
		t.Errorf("got:\n%s", b.String())
	}
}
