// Package confirm asks the user, once, before any read-only provider call.
package confirm

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// ErrNoTerminal means there is no one to ask and neither --yes nor --offline was given.
var ErrNoTerminal = errors.New("no terminal to ask on")

// Online decides whether network access is allowed. providers are display names
// ("AWS","GitHub"). Every doubt (EOF, read or write error, odd answer) means false.
func Online(in io.Reader, prompt io.Writer, inIsTTY, offline, yes bool, providers []string) (bool, error) {
	if offline || len(providers) == 0 {
		return false, nil
	}
	if !yes && !inIsTTY {
		return false, ErrNoTerminal
	}
	names := providers[0]
	if n := len(providers); n > 1 {
		names = strings.Join(providers[:n-1], ", ") + " and " + providers[n-1]
	}
	text := "About to ask " + names + " what your credentials can do.\n" +
		"Read-only, but the requests appear in their audit logs.\n"
	if yes {
		_, err := io.WriteString(prompt, text)
		return err == nil, err
	}
	text += "Continue? [y/N] (--yes to skip this question, --offline to stay local) "
	if _, err := io.WriteString(prompt, text); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		if err == io.EOF {
			err = nil
		}
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}
