package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/model"
)

const (
	blockAdv  = `deny "Bash(aws:*)" in ~/.claude/settings.json`
	remindAdv = "revoke a credential you do not use yourself"
	shellAdv  = "restrict the agent's shell, or use a sandbox"
	advisoryA = "Agent deny rules are advisory unless the agent runs in a sandbox."
)

func awsCred(label string) model.Credential {
	return model.Credential{Tool: "aws", ID: "profile:" + label, Label: label, Provider: "AWS", Kind: "sso"}
}

func unusedFinding(label string) model.Finding {
	return model.Finding{ID: "a:aws:profile:" + label, Severity: model.SevMed, Agent: "a", Tool: "aws", Subject: "profile:" + label,
		Access: model.AccessAllowed, Issue: "unused", Used: "0", Advice: []string{blockAdv, remindAdv, advisoryA}}
}

func sixRows() Report {
	const fail = `online check failed: aws identity check failed (for SSO, run "aws sso login")`
	r := Report{SchemaVersion: 1, Command: "doctor", WindowDays: 30, WindowHours: 720, Agents: []string{"a"}}
	for _, l := range []string{"prd", "prd-lw", "stg", "uat"} {
		r.Credentials = append(r.Credentials, awsCred(l))
		r.Findings = append(r.Findings, unusedFinding(l))
		r.Notes = append(r.Notes, l+": "+fail)
	}
	r.Credentials = append(r.Credentials, model.Credential{Tool: "gh", ID: "github.com", Label: "github.com", Provider: "GitHub",
		Resolved: &model.Resolution{}})
	r.Findings = append(r.Findings,
		model.Finding{ID: "a:shell", Severity: model.SevMed, Agent: "a", Tool: "shell", Subject: "shell", Access: model.AccessAllowed,
			Issue: "unrestricted", Advice: []string{shellAdv}},
		model.Finding{ID: "a:gh:github.com", Severity: model.SevOK, Agent: "a", Tool: "gh", Subject: "github.com", Access: model.AccessAllowed,
			Issue: "scopes not checked", Used: "1650"})
	return r
}

func plain(t *testing.T, r Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := Text(&b, r, Style{}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestDoctorTableSixRows(t *testing.T) {
	want := `agentctl doctor - 30 days - online

SEV  TOOL    NAME        AGENT    USED 30d  CHECKED  ISSUE
-----------------------------------------------------------------------
MED  AWS     prd         allowed  0         no       unused
MED  AWS     prd-lw      allowed  0         no       unused
MED  AWS     stg         allowed  0         no       unused
MED  AWS     uat         allowed  0         no       unused
MED  agent   shell       allowed  -         -        unrestricted
OK   GitHub  github.com  allowed  1650      yes      scopes not checked

Fix
  1  deny "Bash(aws:*)" in ~/.claude/settings.json
  2  revoke a credential you do not use yourself
  3  restrict the agent's shell, or use a sandbox

Notes
  prd, prd-lw, stg, uat: online check failed: aws identity check failed (for SSO, run "aws sso login")
  deny rules are advisory without a sandbox
  launch flags are not detected
`
	if got := plain(t, sixRows()); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDoctorTableAlignsAroundALongName(t *testing.T) {
	r := sixRows()
	long := strings.Repeat("n", 40)
	r.Credentials[0].Label = long
	lines := strings.Split(plain(t, r), "\n")
	col := strings.Index(lines[2], "ISSUE")
	if col < 40 {
		t.Fatalf("header %q", lines[2])
	}
	widest := 0
	for _, l := range lines[4:10] {
		widest = max(widest, len(l))
	}
	if lines[3] != strings.Repeat("-", widest) {
		t.Errorf("rule %q is not as wide as the table (%d)", lines[3], widest)
	}
	for _, l := range lines[4:10] {
		if !strings.HasPrefix(l[col:], "unused") && !strings.HasPrefix(l[col:], "unrestricted") && !strings.HasPrefix(l[col:], "scopes") {
			t.Errorf("row not aligned at %d: %q", col, l)
		}
	}
}

func TestDoctorCheckedColumn(t *testing.T) {
	r := sixRows()
	r.Offline = true
	r.Credentials = r.Credentials[:1]
	r.Findings = r.Findings[:1]
	out := plain(t, r)
	if !strings.Contains(out, "agentctl doctor - 30 days - offline\n") || !strings.Contains(out, "  offline  unused") {
		t.Errorf("offline:\n%s", out)
	}
	r.Offline = false
	if out := plain(t, r); !strings.Contains(out, "  no       unused") {
		t.Errorf("online without a resolution:\n%s", out)
	}
}

func TestDoctorUsedCellsAndHeaderWindow(t *testing.T) {
	r := sixRows()
	r.WindowDays, r.WindowHours = 0, 12
	r.Findings = r.Findings[:2]
	r.Findings[0].Used, r.Findings[1].Used = "2?", "?"
	out := plain(t, r)
	for _, want := range []string{"agentctl doctor - 12 hours - online", "USED 12h", "  2?        no", "  ?         no"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	r.WindowDays, r.WindowHours = 1, 24
	if out := plain(t, r); !strings.Contains(out, "- 1 day -") || !strings.Contains(out, "USED 1d") {
		t.Errorf("1 day:\n%s", out)
	}
}

func TestDoctorFixAndNotesBlocksAreOptional(t *testing.T) {
	r := sixRows()
	r.Findings = []model.Finding{r.Findings[5]}
	r.Notes = nil
	out := plain(t, r)
	if strings.Contains(out, "Fix") || !strings.Contains(out, "Notes\n  deny rules are advisory") {
		t.Errorf("no advice:\n%s", out)
	}
	r.Credentials, r.Findings = nil, nil
	if out := plain(t, r); !strings.Contains(out, "No credentials found.") || !strings.Contains(out, "Notes") {
		t.Errorf("empty:\n%s", out)
	}
}

func TestDoctorTableSanitisesCells(t *testing.T) {
	evil := "pr\x1b[31mod\u202e"
	r := sixRows()
	r.Credentials[0].Label, r.Credentials[0].Provider = evil, evil
	r.Findings[0].Issue, r.Findings[0].Used = evil, evil
	r.Findings[0].Advice = []string{evil}
	r.Notes = []string{evil + ": " + evil}
	out := plain(t, r)
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x202e) || strings.Count(out, "pr?[31mod?") < 6 {
		t.Errorf("not sanitised:\n%q", out)
	}
}

func TestDoctorFancyTable(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sixRows(), Style{Color: true, Fancy: true}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "agentctl doctor · 30 days · online") || !strings.Contains(out, "───") || !strings.Contains(out, "\x1b[33mMED\x1b[0m") {
		t.Errorf("fancy:\n%q", out)
	}
}
