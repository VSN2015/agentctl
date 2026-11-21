package render

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/rules"
)

func (p *printer) sevWord(sv model.Severity) string {
	word := sv.String()
	if p.st.Color {
		code := map[model.Severity]string{model.SevHigh: "31", model.SevMed: "33", model.SevLow: "36", model.SevOK: "32"}[sv]
		word = "\x1b[" + code + "m" + word + "\x1b[0m"
	}
	return word
}

// cell is one table cell: text is what is printed, width is its visible width.
type cell struct {
	text  string
	width int
}

func plainCell(v string) cell { v = s(v); return cell{v, len(v)} }

// row builds the cells of one finding.
func (p *printer) row(r Report, f model.Finding) []cell {
	tool, name, checked := "agent", s(f.Subject), "-"
	for _, c := range r.Credentials {
		if c.Tool == f.Tool && c.ID == f.Subject {
			tool, name = c.Provider, c.Label
			switch {
			case c.Resolved != nil:
				checked = "yes"
			case r.Offline:
				checked = "offline"
			default:
				checked = "no"
			}
			break
		}
	}
	sev := cell{p.sevWord(f.Severity), len(f.Severity.String())}
	return []cell{sev, plainCell(tool), plainCell(name), plainCell(cmp.Or(string(f.Access), "-")),
		plainCell(cmp.Or(f.Used, "-")), plainCell(checked), plainCell(cmp.Or(f.Issue, "-"))}
}

func (p *printer) doctor(r Report) {
	window := time.Duration(r.WindowHours) * time.Hour
	sep := " " + p.dot() + " "
	mode := map[bool]string{true: "offline", false: "online"}[r.Offline]
	p.printf("agentctl doctor%s%s%s%s\n\n", sep, rules.WindowText(window), sep, mode)
	switch {
	case len(r.Credentials) == 0:
		p.printf("No credentials found.\n")
	case len(r.Findings) == 0:
		p.printf("No findings.\n")
	default:
		p.table(r, window)
		p.fix(r)
	}
	p.notes(append(slices.Clone(r.Notes), doctorAdvisoryNote, doctorLaunchNote))
}

func (p *printer) table(r Report, window time.Duration) {
	rows := [][]cell{{plainCell("SEV"), plainCell("TOOL"), plainCell("NAME"), plainCell("AGENT"),
		plainCell("USED " + rules.ShortWindow(window)), plainCell("CHECKED"), plainCell("ISSUE")}}
	for _, f := range r.Findings {
		rows = append(rows, p.row(r, f))
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			widths[i] = max(widths[i], c.width)
		}
	}
	total := 2 * (len(widths) - 1)
	for _, w := range widths {
		total += w
	}
	for i, row := range rows {
		var b strings.Builder
		for j, c := range row {
			b.WriteString(c.text)
			if j < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[j]-c.width+2))
			}
		}
		p.printf("%s\n", b.String())
		if i == 0 {
			p.printf("%s\n", strings.Repeat(p.rule(), total))
		}
	}
}

func (p *printer) rule() string {
	if p.st.Fancy {
		return "─"
	}
	return "-"
}

// fix lists every distinct piece of advice once, in first-appearance order. The advisory
// sentence is a note, not a fix.
func (p *printer) fix(r Report) {
	var lines []string
	for _, f := range r.Findings {
		for _, a := range f.Advice {
			if a != rules.Advisory && !slices.Contains(lines, a) {
				lines = append(lines, a)
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	p.printf("\nFix\n")
	for i, a := range lines {
		p.printf("  %s  %s\n", strconv.Itoa(i+1), s(a))
	}
}

// notes prints the notes block; notes "<label>: <text>" with the same text merge into one line.
func (p *printer) notes(notes []string) {
	type group struct {
		labels []string
		text   string
	}
	var groups []*group
	for _, n := range notes {
		label, text, ok := strings.Cut(n, ": ")
		if !ok {
			label, text = "", n
		}
		var g *group
		for _, e := range groups {
			if e.text == text {
				g = e
			}
		}
		if g == nil {
			g = &group{text: text}
			groups = append(groups, g)
		}
		if label != "" {
			g.labels = append(g.labels, label)
		}
	}
	p.printf("\nNotes\n")
	for _, g := range groups {
		if len(g.labels) == 0 {
			p.printf("  %s\n", s(g.text))
			continue
		}
		p.printf("  %s: %s\n", s(strings.Join(g.labels, ", ")), s(g.text))
	}
}
