package model

import (
	"errors"
	"io"
	"os"
)

// MaxFileSize bounds every untrusted configuration file read through ReadRegularFile.
const MaxFileSize = 1 << 20

var (
	ErrNotRegular = errors.New("not a regular file")
	ErrTooLarge   = errors.New("file too large")
)

// ReadRegularFile reads a file that may be planted by an untrusted repository: it must be a regular
// file (after following symlinks), so /dev/zero, a tty or a FIFO cannot exhaust memory or hang the
// run, and it must not exceed MaxFileSize. A missing file returns the os error unchanged.
func ReadRegularFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileSize {
		return nil, ErrTooLarge
	}
	return b, nil
}
