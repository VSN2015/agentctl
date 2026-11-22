// Package shellparse finds the aws, gh, docker and kubectl invocations in a shell command line.
package shellparse

import "regexp"

// Invocation is one tool use found in a command. For aws, Target is the profile
// ("" = none named). For gh, Sub is the first word after gh and Target is the host.
// For docker there is one invocation per command, with no Sub or Target. For kubectl,
// Target is the --context ("" = none named).
type Invocation struct{ Tool, Sub, Target string }

// Tools lists the tools Parse looks for; later tools extend it.
var Tools = []string{"aws", "gh", "docker", "kubectl"}

const tokenChars = `[A-Za-z0-9_.@:/+-]+`

var (
	// A tool is a whole word after start, whitespace or one of ;&|(`"' and before whitespace or end.
	awsCall     = toolRe("aws", ``)
	ghCall      = toolRe("gh", `(?:\s+([A-Za-z][A-Za-z0-9_-]*))?`)
	dockerCall  = toolRe("docker(?:-compose)?", ``)
	kubectlCall = toolRe("kubectl", ``)

	profileRe = regexp.MustCompile(`(?:--profile[ =]|AWS_PROFILE=)["']?(` + tokenChars + `)`)
	hostRe    = regexp.MustCompile(`(?:--hostname[ =]|GH_HOST=)["']?(` + tokenChars + `)`)
	// shortcut: `kubectl config use-context X` is not read (counts as no context), upgrade if it matters.
	contextRe = regexp.MustCompile(`(?:--context[ =])["']?(` + tokenChars + `)`)
)

func toolRe(name, after string) *regexp.Regexp {
	return regexp.MustCompile("(?:^|[\\s;&|(`\"'])" + name + after + `(?:\s|$)`)
}

// Parse returns the invocations in command: one per distinct (tool, target) for
// aws, per distinct (sub, target) for gh, one per command for docker and one per
// distinct context for kubectl. It never retains the command text.
//
// shortcut: regex over the whole text, so `echo aws` (or `echo docker`) counts as a call and
// any profile or host in the text applies to every call, biased toward "used";
// upgrade to a real shell tokenizer if false "used" results prove common. When
// calls outnumber profile/host matches a "" target is added too, so
// `export AWS_PROFILE=p; aws a; aws b` also counts as a default-profile use.
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
			if calls := len(awsCall.FindAllString(command, -1)); calls > 0 {
				for _, t := range targets(profileRe, command, calls) {
					add(Invocation{Tool: "aws", Target: t})
				}
			}
		case "gh":
			calls := ghCall.FindAllStringSubmatch(command, -1)
			for _, m := range calls {
				for _, t := range targets(hostRe, command, len(calls)) {
					add(Invocation{Tool: "gh", Sub: m[1], Target: t})
				}
			}
		case "docker":
			if dockerCall.MatchString(command) {
				add(Invocation{Tool: "docker"})
			}
		case "kubectl":
			if calls := len(kubectlCall.FindAllString(command, -1)); calls > 0 {
				for _, t := range targets(contextRe, command, calls) {
					add(Invocation{Tool: "kubectl", Target: t})
				}
			}
		}
	}
	return out
}

// targets returns the distinct captures of re in s, plus "" when there are more
// calls than matches (some call names no target).
func targets(re *regexp.Regexp, s string, calls int) []string {
	var out []string
	seen := map[string]bool{}
	ms := re.FindAllStringSubmatch(s, -1)
	if calls > len(ms) {
		ms = append(ms, []string{"", ""})
	}
	for _, m := range ms {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}
