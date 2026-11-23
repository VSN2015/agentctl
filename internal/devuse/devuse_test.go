package devuse

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func write(t *testing.T, home, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadZshExtendedFormat(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".zsh_history",
		": 1700000000:0;aws s3 ls --profile prod\n"+
			": 1700000001:0;echo one \\\nsecond line\\\nthird\n"+
			": 1700000002:0;echo \x83\xa0 meta\n"+
			": 1700000003:0;gh pr list\n")
	h := Read(home, noEnv)
	u, ok := h.Lookup("aws", "prod")
	if !ok || !u.Dated || !u.Last.Equal(time.Unix(1700000000, 0)) || u.Count != 1 {
		t.Errorf("aws prod = %+v %v", u, ok)
	}
	if _, ok := h.Lookup("gh", ""); !ok {
		t.Errorf("entry after multi-line and metafied entries was lost")
	}
	if _, ok := h.Lookup("aws", ""); ok {
		t.Errorf("target \"\" must not match a named profile")
	}
}

func TestReadBashWithAndWithoutTimestamps(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".bash_history", "#1700000000\naws s3 ls\n")
	u, ok := Read(home, noEnv).Lookup("aws", "")
	if !ok || !u.Dated || !u.Last.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("dated bash = %+v %v", u, ok)
	}
	home = t.TempDir()
	write(t, home, ".bash_history", "aws s3 ls\naws s3 ls\n")
	u, ok = Read(home, noEnv).Lookup("aws", "")
	if !ok || u.Dated || !u.Last.IsZero() || u.Count != 2 {
		t.Errorf("undated bash = %+v %v", u, ok)
	}
}

func TestLookupPicksLatest(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".zsh_history", ": 1700000500:0;aws s3 ls\n: 1700000100:0;aws s3 ls\naws s3 ls\n")
	u, _ := Read(home, noEnv).Lookup("aws", "")
	if !u.Dated || !u.Last.Equal(time.Unix(1700000500, 0)) || u.Count != 3 {
		t.Errorf("use = %+v", u)
	}
}

func TestZdotdirAndHistfile(t *testing.T) {
	home, zd, other := t.TempDir(), t.TempDir(), t.TempDir()
	write(t, zd, ".zsh_history", ": 1700000000:0;aws s3 ls --profile z\n")
	write(t, other, "hist", ": 1700000000:0;aws s3 ls --profile h\n")
	env := map[string]string{"ZDOTDIR": zd, "HISTFILE": filepath.Join(other, "hist")}
	h := Read(home, func(k string) string { return env[k] })
	for _, p := range []string{"z", "h"} {
		if _, ok := h.Lookup("aws", p); !ok {
			t.Errorf("profile %s not found", p)
		}
	}
}

func TestReadMissingAndHuge(t *testing.T) {
	h := Read(t.TempDir(), noEnv)
	if _, ok := h.Lookup("aws", ""); ok || h.Unread != 0 {
		t.Errorf("empty home: %+v", h)
	}
	home := t.TempDir()
	write(t, home, ".bash_history",
		"aws s3 ls --profile big "+strings.Repeat("x", 10<<20)+"\n"+
			"gh pr list \xff\xfe\x00\n")
	h = Read(home, noEnv)
	if _, ok := h.Lookup("aws", "big"); ok {
		t.Errorf("10 MiB line should be skipped")
	}
	if _, ok := h.Lookup("gh", ""); !ok {
		t.Errorf("invalid UTF-8 line should still parse")
	}
}

func TestReadCountsUnreadable(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".bash_history"), 0o700); err != nil {
		t.Fatal(err)
	}
	if h := Read(home, noEnv); h.Unread != 1 {
		t.Errorf("Unread = %d, want 1", h.Unread)
	}
}

func TestReadRetainsNoCommandText(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".bash_history", "export AWS_SECRET_ACCESS_KEY=CANARY-SECRET-DO-NOT-PRINT; aws s3 ls\n")
	h := Read(home, noEnv)
	if _, ok := h.Lookup("aws", ""); !ok {
		t.Fatal("aws use not found")
	}
	if s := fmt.Sprintf("%+v", h); strings.Contains(s, "CANARY-SECRET-DO-NOT-PRINT") {
		t.Errorf("canary leaked: %s", s)
	}
}

func TestReadCountsNonRegularHistoryAsUnread(t *testing.T) {
	home := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(home, ".zsh_history"), 0o600); err != nil {
		t.Skip(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".bash_history"), 0o700); err != nil {
		t.Fatal(err)
	}
	done := make(chan History, 1)
	go func() { done <- Read(home, noEnv) }()
	select {
	case h := <-done:
		if h.Unread != 2 {
			t.Errorf("Unread = %d, want 2", h.Unread)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read did not return")
	}
}

func TestLookupFold(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".zsh_history",
		": 1700000000:0;gh pr list --hostname GHE.Example.com\n"+
			": 1700000100:0;gh pr list --hostname ghe.example.com\n"+
			"gh pr list --hostname GHE.EXAMPLE.COM\n"+
			": 1700000500:0;aws s3 ls --profile GHE.Example.com\n")
	h := Read(home, noEnv)
	u, ok := h.LookupFold("gh", "ghe.example.com")
	if !ok || u.Count != 3 || !u.Dated || !u.Last.Equal(time.Unix(1700000100, 0)) {
		t.Errorf("LookupFold = %+v %v", u, ok)
	}
	if _, ok := h.LookupFold("gh", "other.example.com"); ok {
		t.Errorf("unrelated target matched")
	}
	if _, ok := h.LookupFold("gh", ""); ok {
		t.Errorf("empty target must not match a named one")
	}
	if u, ok := h.Lookup("gh", "ghe.example.com"); !ok || u.Count != 1 {
		t.Errorf("exact Lookup changed: %+v %v", u, ok)
	}
	if _, ok := h.Lookup("gh", "Ghe.Example.com"); ok {
		t.Errorf("exact Lookup must stay case-sensitive")
	}
}

func TestLookupFoldUndatedOnly(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".bash_history", "gh pr list --hostname GHE.Example.com\n")
	u, ok := Read(home, noEnv).LookupFold("gh", "ghe.example.com")
	if !ok || u.Dated || u.Count != 1 {
		t.Errorf("= %+v %v", u, ok)
	}
}
