package scan

import (
	"bytes"
	"context"
	"os"
	"os/exec"
)

const maxOutput = 1 << 20 // 1 MiB

// ExecRunner is the real Runner. env entries (KEY=VALUE) are appended to the parent's environment.
type ExecRunner struct{}

type capped struct{ buf bytes.Buffer }

// Write discards bytes past the cap but reports success so the child never sees a broken pipe.
func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (ExecRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out capped
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.buf.Bytes(), nil
}
