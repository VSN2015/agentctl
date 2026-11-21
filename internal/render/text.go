package render

import (
	"fmt"
	"io"

	"github.com/VSN2015/agentctl/internal/model"
)

const (
	advisoryNote       = "agent deny rules are advisory unless the agent runs in a sandbox."
	doctorAdvisoryNote = "deny rules are advisory without a sandbox"
	doctorLaunchNote   = "launch flags are not detected"
	launchNote         = "launch flags (such as skipping all permission prompts) are not visible in configuration files and are not detected."
)

// printer writes the report; the first write error sticks and stops later output mattering.
type printer struct {
	w   io.Writer
	st  Style
	err error
}

func (p *printer) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

// s makes any string that may come from a file or a provider safe to print.
func s(v string) string { return model.Sanitize(v) }

func (p *printer) dot() string {
	if p.st.Fancy {
		return "·"
	}
	return "-"
}

func (p *printer) dash() string {
	if p.st.Fancy {
		return "—"
	}
	return "-"
}

// Text writes the report for people. Plain ASCII unless the style says otherwise.
func Text(w io.Writer, r Report, style Style) error {
	p := &printer{w: w, st: style}
	if r.Command == "doctor" {
		p.doctor(r)
		return p.err
	}
	if len(r.Credentials) == 0 && len(r.Findings) == 0 {
		p.printf("No credentials found.\n")
	} else {
		p.inventory(r)
	}
	p.printf("\n")
	for _, n := range r.Notes {
		p.printf("Note: %s\n", s(n))
	}
	p.printf("Note: %s\n", advisoryNote)
	p.printf("Note: %s\n", launchNote)
	return p.err
}
