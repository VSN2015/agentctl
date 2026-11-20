package model

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadRegularFile(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok")
	_ = os.WriteFile(ok, []byte("hi"), 0o600)
	if b, err := ReadRegularFile(ok); err != nil || string(b) != "hi" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadRegularFile(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Errorf("missing: %v", err)
	}
	if _, err := ReadRegularFile(dir); !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory: %v", err)
	}
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(big, []byte(strings.Repeat("x", MaxFileSize+1)), 0o600)
	if _, err := ReadRegularFile(big); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the limit: %v", err)
	}
	exact := filepath.Join(dir, "exact")
	_ = os.WriteFile(exact, []byte(strings.Repeat("x", MaxFileSize)), 0o600)
	if _, err := ReadRegularFile(exact); err != nil {
		t.Errorf("exactly the limit: %v", err)
	}
}

func TestReadRegularFileFollowsSymlinkToRegularButRefusesDevice(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "t")
	_ = os.WriteFile(target, []byte("x"), 0o600)
	link := filepath.Join(dir, "l")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if _, err := ReadRegularFile(link); err != nil {
		t.Errorf("symlink to file: %v", err)
	}
	dev := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", dev); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegularFile(dev); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("/dev/zero: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read of /dev/zero did not return")
	}
}
