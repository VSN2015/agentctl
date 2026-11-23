package gh

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// bound is generous (slow CI runners, race detector): the capped work takes milliseconds; the uncapped quadratic work took 30 s or more.
const bound = 10 * time.Second

func timed(t *testing.T, body string) (n int, notes []string, d time.Duration, kinds map[string]int) {
	t.Helper()
	start := time.Now()
	creds, err := discoverBody(t, body, nil)
	d = time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	kinds = map[string]int{}
	for _, c := range creds {
		kinds[c.Kind]++
	}
	if len(creds) > 0 {
		notes = creds[0].Notes
	}
	return len(creds), notes, d, kinds
}

func TestDiscoverCapsHostEntries(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "h%03d.example.com:\n  user: u\n", i)
	}
	n, notes, _, _ := timed(t, b.String())
	if n != 32 || !contains(notes, "ignored 268 host entries beyond the first 32 in the gh hosts file") {
		t.Errorf("n=%d notes=%q", n, notes)
	}
	// the first 32 in file order are kept
	creds, _ := discoverBody(t, b.String(), nil)
	if got := ids(creds); got[31] != "u@h031.example.com" {
		t.Errorf("last kept %q", got[31])
	}
	_, notes, _, _ = timed(t, b.String()[:0]+"a.example.com:\n  user: u\n")
	if len(notes) != 0 {
		t.Errorf("notes %q", notes)
	}
	var s strings.Builder
	for i := 0; i < 33; i++ {
		fmt.Fprintf(&s, "h%03d.example.com:\n  user: u\n", i)
	}
	if _, notes, _, _ := timed(t, s.String()); !contains(notes, "ignored 1 host entry beyond the first 32 in the gh hosts file") {
		t.Errorf("singular: %q", notes)
	}
}

func TestDiscoverCapsAccountsKeepingActive(t *testing.T) {
	var b strings.Builder
	b.WriteString("github.com:\n  user: u299\n  users:\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "    u%03d:\n", i)
	}
	creds, err := discoverBody(t, b.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 32 {
		t.Fatalf("n=%d", len(creds))
	}
	if c := credByID(t, creds, "u299@github.com"); c.Kind != "file-host" {
		t.Errorf("active: %+v", c)
	}
	credByID(t, creds, "u030@github.com")
	if !contains(creds[0].Notes, "ignored 268 accounts beyond the first 32 for a host in the gh hosts file") {
		t.Errorf("notes %q", creds[0].Notes)
	}
	for _, c := range creds {
		if c.Kind == "file-host" && c.ID != "u299@github.com" {
			t.Errorf("second active %+v", c)
		}
	}
	one := "github.com:\n  users:\n" + strings.Repeat("", 0)
	for i := 0; i < 33; i++ {
		one += fmt.Sprintf("    u%03d:\n", i)
	}
	creds, _ = discoverBody(t, one, nil)
	if !contains(creds[0].Notes, "ignored 1 account beyond the first 32 for a host in the gh hosts file") {
		t.Errorf("singular %q", creds[0].Notes)
	}
}

func TestDiscoverRepeatedHostsAndManyUsersAreFast(t *testing.T) {
	n, notes, d, _ := timed(t, strings.Repeat("github.com: ~\n", 20000))
	t.Logf("20000 repeated hosts: %v", d)
	if n != 32 || d > bound || !contains(notes, "ignored 19968 host entries beyond the first 32 in the gh hosts file") {
		t.Errorf("n=%d d=%v notes=%q", n, d, notes)
	}
	var b strings.Builder
	b.WriteString("github.com:\n  users:\n")
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, "    u%d:\n", i)
	}
	n, notes, d, kinds := timed(t, b.String())
	t.Logf("20000 users: %v", d)
	if n != 33 || d > bound || kinds["file-host"] != 1 || !contains(notes, "ignored 19968 accounts beyond the first 32 for a host in the gh hosts file") {
		t.Errorf("n=%d d=%v kinds=%v notes=%q", n, d, kinds, notes)
	}
}

func decoys(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "d%03d.example.com:\n  user: u\n", i)
	}
	return b.String()
}

func TestDiscoverKeepsDefaultAndEnvHostBeyondCap(t *testing.T) {
	// github.com after 40 decoys is still reported, in effect.
	creds, _ := discoverBody(t, decoys(40)+"github.com: {user: alice, users: {alice: }}\n", nil)
	if c := credByID(t, creds, "alice@github.com"); c.Kind != "file-host" {
		t.Errorf("%+v", c)
	}
	if len(creds) != 33 || !contains(creds[0].Notes, "ignored 8 host entries beyond the first 32 in the gh hosts file") {
		t.Errorf("n=%d notes=%q", len(creds), creds[0].Notes)
	}
	// the host GH_HOST names (any case), placed last.
	creds, _ = discoverBody(t, decoys(40)+"ghe.example.com: {user: alice, users: {alice: }}\n", map[string]string{"GH_HOST": "GHE.example.com"})
	if c := credByID(t, creds, "alice@ghe.example.com"); c.Kind != "file-host" {
		t.Errorf("%+v", c)
	}
	if len(creds) != 33 || !contains(creds[0].Notes, "ignored 8 host entries beyond the first 32 in the gh hosts file") {
		t.Errorf("n=%d notes=%q", len(creds), creds[0].Notes)
	}
	// both exempt entries after the cap: 34 kept; a second github.com is not exempt.
	body := decoys(40) + "github.com: {user: alice, users: {alice: }}\nghe.example.com: {user: bob, users: {bob: }}\ngithub.com: {user: carol, users: {carol: }}\n"
	creds, _ = discoverBody(t, body, map[string]string{"GH_HOST": "ghe.example.com"})
	credByID(t, creds, "alice@github.com")
	credByID(t, creds, "bob@ghe.example.com")
	if contains(ids(creds), "carol@github.com") || len(creds) != 34 || !contains(creds[0].Notes, "ignored 9 host entries beyond the first 32 in the gh hosts file") {
		t.Errorf("n=%d notes=%q", len(creds), creds[0].Notes)
	}
}

func aliasedHosts(hosts, users int) string {
	var b strings.Builder
	for h := 0; h < hosts; h++ {
		if h == 0 {
			b.WriteString("h000.example.com: &m\n  users:\n")
			for i := 0; i < users; i++ {
				fmt.Fprintf(&b, "    0u%d:\n", i)
			}
			continue
		}
		fmt.Fprintf(&b, "h%03d.example.com: *m\n", h)
	}
	return b.String()
}

func TestDiscoverAliasedMappingIsParsedOnce(t *testing.T) {
	n, _, d, _ := timed(t, aliasedHosts(30, 20000))
	t.Logf("20000 users aliased from 30 hosts: %v", d)
	if n != 30*33 || d > bound { // 32 accounts plus the host itself (no user:)
		t.Errorf("n=%d d=%v", n, d)
	}
}

func TestDiscoverWorstCaseAliasedHostsAreFast(t *testing.T) {
	body := aliasedHosts(300, 300)
	n, _, d, _ := timed(t, body)
	t.Logf("300 hosts x 300 users: %v", d)
	if n != 32*33 || d > bound {
		t.Errorf("n=%d d=%v", n, d)
	}
	// environment tokens on every host; names sort before "@".
	start := time.Now()
	creds, err := discoverBody(t, body, map[string]string{"GH_TOKEN": "x", "GH_ENTERPRISE_TOKEN": "x"})
	d = time.Since(start)
	t.Logf("300 hosts x 300 users with environment tokens: %v", d)
	if err != nil || len(creds) != 32*33+32+1 || d > bound { // plus one env-token per kept host and one for github.com
		t.Errorf("n=%d d=%v err=%v", len(creds), d, err)
	}
}

func TestDiscoverCaseVariantKeyTakesNoExemption(t *testing.T) {
	// gh matches host keys exactly, so a differently cased first key is a plain decoy: it neither takes nor consumes the exemption.
	for _, tc := range []struct{ name, first, real, env string }{
		{"mixed", "GitHub.com: {user: decoy, users: {decoy: }}\n", "github.com", ""},
		{"upper", "GITHUB.COM: ~\n", "github.com", ""},
		{"env", "GHE.Example.com: {user: decoy, users: {decoy: }}\n", "ghe.example.com", "ghe.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			if tc.env != "" {
				env["GH_HOST"] = tc.env
			}
			creds, _ := discoverBody(t, tc.first+decoys(32)+tc.real+": {user: victim, users: {victim: , victim-alt: }}\n", env)
			if c := credByID(t, creds, "victim@"+tc.real); c.Kind != "file-host" {
				t.Errorf("%+v", c)
			}
			if c := credByID(t, creds, "victim-alt@"+tc.real); c.Kind != "file-host-inactive" {
				t.Errorf("%+v", c)
			}
			if !contains(creds[0].Notes, "ignored 1 host entry beyond the first 32 in the gh hosts file") && !contains(creds[0].Notes, "ignored 1 host entries beyond the first 32 in the gh hosts file") {
				t.Errorf("notes=%q", creds[0].Notes)
			}
		})
	}
}
