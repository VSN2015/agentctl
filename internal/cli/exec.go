package cli

import (
	"context"
	"fmt"

	"github.com/VSN2015/agentctl/internal/run"
)

// Exec is the pipeline seam; it returns the exit status 0, 1 or 2.
type Exec func(ctx context.Context, o run.Options, io IO) int

// defaultExec is replaced by the real pipeline in a later task.
var defaultExec Exec = func(_ context.Context, _ run.Options, io IO) int {
	fmt.Fprintln(io.Err, "agentctl: not implemented")
	return 2
}
