//go:build unix

package model

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRegularFileFIFOReturnsPromptly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegularFile(p); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read of a FIFO blocked")
	}
}
