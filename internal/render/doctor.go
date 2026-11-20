package render

import (
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
)

const indent = "      " // aligns detail lines under the subject, after "HIGH  "

func (p *printer) sevWord(sv model.Severity) string {
	word := sv.String()
	if p.st.Color {
		code := map[model.Severity]string{model.SevHigh: "31", model.SevMed: "33", model.SevLow: "36", model.SevOK: "32"}[sv]
		word = "\x1b[" + code + "m" + word + "\x1b[0m"
	}
	return word + strings.Repeat(" ", 6-len(sv.String()))
}

// heading names the finding by its credential when one matches, else by tool and subject.
func (p *printer) heading(r Report, f model.Finding) string {
	name := s(f.Subject)
	for _, c := range r.Credentials {
		if c.Tool == f.Tool && c.ID == f.Subject {
			name = s(c.Provider) + " " + p.dot() + " " + s(c.Label)
			break
		}
	}
	if name == s(f.Subject) && f.Tool != f.Subject {
		name = s(f.Tool) + " " + p.dot() + " " + name
	}
	if len(r.Agents) > 1 {
		name += "  [" + s(f.Agent) + "]"
	}
	return name
}

func (p *printer) doctor(r Report) {
	if len(r.Findings) == 0 {
		p.printf("No findings.\n")
	}
	for i, f := range r.Findings {
		if i > 0 {
			p.printf("\n")
		}
		if f.Severity == model.SevOK {
			p.printf("%s%s %s %s\n", p.sevWord(f.Severity), p.heading(r, f), p.dash(), s(f.Headline))
		} else {
			p.printf("%s%s\n", p.sevWord(f.Severity), p.heading(r, f))
			p.printf("%s%s\n", indent, s(f.Headline))
		}
		for _, d := range f.Details {
			p.printf("%s%s\n", indent, s(d))
		}
		for _, a := range f.Advice {
			p.printf("%s%s %s\n", indent, p.arrow(), s(a))
		}
	}
}
