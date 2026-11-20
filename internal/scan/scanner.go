// Package scan defines the extension point implemented by every tool scanner.
package scan

import (
	"context"

	"github.com/VSN2015/agentctl/internal/model"
)

// Env is the process environment a scanner may look at; it is injected so tests stay hermetic.
type Env struct {
	Home    string
	Getenv  func(string) string
	SysRoot string // default "/sys/class/dmi/id"
}

// Runner runs an external command (read-only use only).
type Runner interface {
	Run(ctx context.Context, name string, args []string, env []string) ([]byte, error)
}

// SkipError means a credential was skipped by design, not that something failed.
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return e.Reason }

type Scanner interface {
	Name() string     // "aws"
	Provider() string // "AWS", used in the prompt
	// Discover is local only and never touches the network.
	Discover(env Env) ([]model.Credential, error)
	// Resolve is read-only; a *SkipError means skipped by design.
	Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error)
}
