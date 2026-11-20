// Package shellparse finds the aws and gh invocations in a shell command line.
package shellparse

import "regexp"

// Invocation is one tool use found in a command. For aws, Target is the profile
// ("" = none named). For gh, Sub is the first word after gh and Target is the host.
type Invocation struct{ Tool, Sub, Target string }

// Tools lists the tools Parse looks for; later tools extend it.
var Tools = []string{"aws", "gh"}

const tokenChars = `[A-Za-z0-9_.@:/+-]+`

var (
	// A tool is a whole word after start, whitespace or one of ;&|(`"' and before whitespace or end.
	awsCall = toolRe("aws", ``)
	ghCall  = toolRe("gh", `(?:\s+([A-Za-z][A-Za-z0-9_-]*))?`)

	profileRe = regexp.MustCompile(`(?:--profile[ =]|AWS_PROFILE=)(` + tokenChars + `)`)
	hostRe    = regexp.MustCompile(`(?:--hostname[ =]|GH_HOST=)(` + tokenChars + `)`)
)

func toolRe(name, after string) *regexp.Regexp {
	return regexp.MustCompile("(?:^|[\\s;&|(`\"'])" + name + after + `(?:\s|$)`)
}

// Parse returns the invocations in command: one per distinct (tool, target) for
// aws and per distinct (sub, target) for gh. It never retains the command text.
//
// shortcut: regex over the whole text, so `echo aws` counts as an aws call and
// any profile or host in the text applies to every call; upgrade to a real shell
// tokenizer if false "used" results prove common.
func Parse(command string) []Invocation {
	var out []Invocation
	seen := map[Invocation]bool{}
	add := func(i Invocation) {
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	for _, tool := range Tools {
		switch tool {
		case "aws":
			if awsCall.MatchString(command) {
				for _, t := range targets(profileRe, command) {
					add(Invocation{Tool: "aws", Target: t})
				}
			}
		case "gh":
			for _, m := range ghCall.FindAllStringSubmatch(command, -1) {
				for _, t := range targets(hostRe, command) {
					add(Invocation{Tool: "gh", Sub: m[1], Target: t})
				}
			}
		}
	}
	return out
}

// targets returns the distinct captures of re in s, or [""] when there are none.
func targets(re *regexp.Regexp, s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}
