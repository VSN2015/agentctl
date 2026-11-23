// Package gh finds GitHub CLI credentials and asks GitHub who they belong to.
package gh

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
	"go.yaml.in/yaml/v3"
)

const defaultHost = "github.com"

type Scanner struct {
	run     scan.Runner
	envHost map[string]bool // hosts that have an environment-token credential (set by Discover)
}

func New(r scan.Runner) *Scanner { return &Scanner{run: r, envHost: map[string]bool{}} }

func (s *Scanner) Name() string     { return "gh" }
func (s *Scanner) Provider() string { return "GitHub" }

// validHost keeps host names that cannot change where a URL or `gh --hostname` points.
// Underscores are allowed inside the name (internal DNS names use them); none of these characters is special to a URL or a shell.
var validHost = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?(:[0-9]+)?$`)

// validAccount keeps account names that are safe to paste into a command: GitHub login characters plus _ (enterprise-managed users).
// internal/rules/gh.go repeats this pattern for its advice line.
var validAccount = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$`)

// tokenShaped rejects names that look like a GitHub token. internal/rules/gh.go repeats this pattern (no shared package).
var tokenShaped = regexp.MustCompile(`(?i)^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)`)

// maxAccount is GitHub's login limit; it also stops a 40-character hex token from being taken for a name.
const maxAccount = 39

// Caps keep a hand-made hosts file (up to the 1 MiB read limit) from making the audit run for hours.
const (
	maxHosts           = 32 // kept host entries per file (the first github.com and the GH_HOST entry are kept beyond it)
	maxAccountsPerHost = 32 // kept accounts per host entry
)

func validName(n string) bool {
	return len(n) <= maxAccount && validAccount.MatchString(n) && !tokenShaped.MatchString(n)
}

// account is structurally unable to hold oauth_token: it has no fields, so only the account name (the map key) survives.
type account struct{}

// hostEntry deliberately has no token field: parseHostEntry reads user and the keys of users only,
// so a token value never reaches a result.
type hostEntry struct {
	User  string             `yaml:"user"`
	Users map[string]account `yaml:"users"`

	badUser bool // user is not a scalar: counted as an invalid account name
}

// parseHostEntry reads user and the keys of users from a host entry mapping. It cannot fail:
// it never calls Decode, never follows an alias and never inspects any other key, so no content
// inside one host entry can make the whole file unreadable. A scalar user is kept exactly as
// written (empty for null) and validName judges it. The first user: and the first users: win.
func parseHostEntry(n *yaml.Node) hostEntry {
	var e hostEntry
	seenUser, seenUsers := false, false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch {
		case k.Kind == yaml.ScalarNode && k.Value == "user":
			if seenUser {
				continue
			}
			seenUser = true
			switch {
			case v.Kind != yaml.ScalarNode: // sequence, mapping or alias (never followed: it can copy a token into the name)
				e.badUser = true
			case v.Tag != "!!null":
				e.User = v.Value
			}
		case k.Kind == yaml.ScalarNode && k.Value == "users":
			if seenUsers {
				continue
			}
			seenUsers = true
			if v.Kind != yaml.MappingNode { // anything else is ignored: the host falls back to user
				continue
			}
			e.Users = map[string]account{}
			for j := 0; j+1 < len(v.Content); j += 2 {
				if v.Content[j].Kind == yaml.ScalarNode {
					e.Users[v.Content[j].Value] = account{}
				}
			}
		}
	}
	return e
}

// entryResult is what one host entry mapping yields; aliasing host keys share it, so it is computed once per node.
type entryResult struct {
	names                []string // kept account names, sorted
	active               string   // the listed name that user: selects
	bad, unlisted, extra int
}

func resolveEntry(e hostEntry) *entryResult {
	r := &entryResult{}
	var names []string
	for n := range e.Users {
		if n == "" {
			continue
		}
		if validName(n) {
			names = append(names, n)
		} else {
			r.bad++
		}
	}
	slices.Sort(names)
	active := "" // the listed name that user: selects
	switch {
	case e.badUser:
		r.bad++
	case e.User != "" && !validName(e.User):
		r.bad++
	case e.User != "":
		// GitHub logins are case-insensitive: user: Alice selects a listed alice.
		if i := slices.IndexFunc(names, func(n string) bool { return n == e.User }); i >= 0 {
			active = names[i]
		} else if i := slices.IndexFunc(names, func(n string) bool { return strings.EqualFold(n, e.User) }); i >= 0 {
			active = names[i]
		} else if len(names) > 0 { // gh uses the host token whatever user: says, so an unlisted user: is not a login
			r.unlisted++
		} else { // legacy layout: user: alone is the account
			active = e.User
			names = []string{e.User}
		}
	}
	// Keep the first maxAccountsPerHost names in sorted order (deterministic: file order of map keys is irrelevant),
	// but never lose the active account to the cap: it takes the place of the last kept one.
	if len(names) > maxAccountsPerHost {
		r.extra = len(names) - maxAccountsPerHost
		kept := names[:maxAccountsPerHost]
		if active != "" && !slices.Contains(kept, active) {
			kept[maxAccountsPerHost-1] = active
			slices.Sort(kept)
		}
		names = kept
	}
	r.names, r.active = names, active
	return r
}

func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	// Precedence as gh itself: GH_CONFIG_DIR, XDG_CONFIG_HOME, then ~/.config. An unknown home
	// must not turn into a path relative to the working directory (a cloned repo could plant one).
	dir := ""
	switch {
	case getenv("GH_CONFIG_DIR") != "":
		dir = getenv("GH_CONFIG_DIR")
	case getenv("XDG_CONFIG_HOME") != "":
		dir = filepath.Join(getenv("XDG_CONFIG_HOME"), "gh")
	case env.Home != "":
		dir = filepath.Join(env.Home, ".config", "gh")
	}
	path := filepath.Join(dir, "hosts.yml")
	s.envHost = map[string]bool{}

	var notes []string
	var creds []model.Credential
	ids, labels := map[string]bool{}, map[string]bool{}
	// add keeps IDs and labels unique within the tool: names that sanitise alike can collide.
	// next remembers the last suffix tried per base, so repeats cost linear time overall.
	next := map[string]int{}
	add := func(c model.Credential) {
		id, label := c.ID, c.Label
		key := id + "\x00" + label
		n := max(next[key], 2)
		for ; ids[c.ID] || labels[c.Label]; n++ {
			c.ID, c.Label = id+"#"+strconv.Itoa(n), label+"#"+strconv.Itoa(n)
		}
		next[key] = n // the suffix just used (or 2): the next search starts here, so earlier ones are never retried
		ids[c.ID], labels[c.Label] = true, true
		creds = append(creds, c)
	}
	var fileHosts []string
	var stored []model.Credential // added after the environment tokens so those keep the plain ID and label
	badHosts, badAccounts := 0, 0
	extraHosts, extraAccounts, unlistedActive := 0, 0, 0
	// failed is set in exactly three cases: the file cannot be read, its YAML has a syntax error, or its root is neither a mapping nor null.
	// Nothing inside a host entry can set it (see parseHostEntry): one odd entry must never hide the real logins.
	failed := false
	switch {
	case dir == "":
		notes = append(notes, "hosts file skipped: no home directory")
	case !filepath.IsAbs(dir):
		notes = append(notes, "hosts file skipped: configuration directory is not an absolute path")
	default:
		if buf, err := model.ReadRegularFile(path); err == nil {
			type fileHost struct {
				host string
				r    *entryResult
			}
			memo := map[*yaml.Node]*entryResult{} // many host keys may alias one large mapping
			var hosts []fileHost
			wantHost, seenDefault, seenWant := "", false, false
			if h := getenv("GH_HOST"); validHost.MatchString(h) {
				wantHost = strings.ToLower(h)
			}
			var doc yaml.Node
			if err := yaml.Unmarshal(buf, &doc); err != nil { // never echo err: yaml quotes file content
				notes, failed = append(notes, "could not parse hosts file"), true
			} else if len(doc.Content) > 0 {
				top := doc.Content[0]
				if top.Kind == yaml.ScalarNode && top.Tag == "!!null" { // `---`, `null`, `~`: an empty file
					top = &yaml.Node{}
				} else if top.Kind != yaml.MappingNode {
					notes, failed = append(notes, "could not parse hosts file"), true
				}
				for i := 0; !failed && i+1 < len(top.Content); i += 2 {
					k := top.Content[i]
					if k.Kind != yaml.ScalarNode || !validHost.MatchString(k.Value) { // only plain scalar keys; never echo the key
						badHosts++
						continue
					}
					v := top.Content[i+1]
					if v.Kind == yaml.AliasNode && v.Alias != nil { // a host value may alias a mapping; its names are validated as usual
						v = v.Alias
					}
					if v.Kind != yaml.MappingNode && !(v.Kind == yaml.ScalarNode && v.Tag == "!!null") { // `zz: 1`: skip it, keep the other hosts
						badHosts++
						continue
					}
					host := strings.ToLower(k.Value)
					// file order decides what is kept; the first github.com and the first GH_HOST entry are never pushed out by decoys
					// gh matches keys exactly, so the exemption goes by the raw key: a case variant is a plain decoy
					isDefault, isWant := k.Value == defaultHost, wantHost != "" && k.Value == wantHost
					exempt := (isDefault && !seenDefault) || (isWant && !seenWant)
					seenDefault, seenWant = seenDefault || isDefault, seenWant || isWant
					if len(hosts) >= maxHosts && !exempt {
						extraHosts++
						continue
					}
					fh := fileHost{host: host}
					if v.Kind == yaml.MappingNode {
						if memo[v] == nil {
							memo[v] = resolveEntry(parseHostEntry(v))
						}
						fh.r = memo[v]
					} else {
						fh.r = resolveEntry(hostEntry{})
					}
					hosts = append(hosts, fh)
				}
			}
			if badHosts > 0 {
				if badHosts == 1 {
					notes = append(notes, "ignored 1 entry with an invalid host name or value in the gh hosts file")
				} else {
					notes = append(notes, fmt.Sprintf("ignored %d entries with an invalid host name or value in the gh hosts file", badHosts))
				}
			}
			if extraHosts > 0 {
				word := "entries"
				if extraHosts == 1 {
					word = "entry"
				}
				notes = append(notes, fmt.Sprintf("ignored %d host %s beyond the first %d in the gh hosts file", extraHosts, word, maxHosts))
			}
			// Both entries are kept (nothing may be hidden); the count only tells the reader the file repeats a name.
			count, dups := map[string]int{}, 0
			for _, fh := range hosts {
				if count[fh.host]++; count[fh.host] == 2 {
					dups++
				}
			}
			if dups == 1 {
				notes = append(notes, "1 host name appears more than once in the gh hosts file")
			} else if dups > 1 {
				notes = append(notes, fmt.Sprintf("%d host names appear more than once in the gh hosts file", dups))
			}
			sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].host < hosts[j].host })
			for _, fh := range hosts {
				h := fh.host
				fileHosts = append(fileHosts, h)
				r := fh.r
				badAccounts += r.bad
				unlistedActive += r.unlisted
				extraAccounts += r.extra
				names, active := r.names, r.active
				// gh takes the token from the host entry whatever user: says, so every host needs one in-effect credential:
				// the host itself (no account name) when no listed account is the active one.
				if active == "" {
					stored = append(stored, model.Credential{Tool: "gh", ID: h, Label: h, Kind: "file-host",
						Source: "file", Files: []string{path}, Host: h})
				}
				for _, n := range names {
					kind := "file-host-inactive"
					if n == active {
						kind = "file-host"
					}
					id := n + "@" + h
					stored = append(stored, model.Credential{Tool: "gh", ID: id, Label: id, Kind: kind,
						Source: "file", Files: []string{path}, Identity: n, Host: h})
				}
			}
			if badAccounts > 0 {
				word := "accounts"
				if badAccounts == 1 {
					word = "account"
				}
				notes = append(notes, fmt.Sprintf("ignored %d %s with an invalid name in the gh hosts file", badAccounts, word))
			}
			if extraAccounts > 0 {
				word := "accounts"
				if extraAccounts == 1 {
					word = "account"
				}
				notes = append(notes, fmt.Sprintf("ignored %d %s beyond the first %d for a host in the gh hosts file", extraAccounts, word, maxAccountsPerHost))
			}
			if unlistedActive == 1 {
				notes = append(notes, "1 host in the gh hosts file names an active account that is not in its account list")
			} else if unlistedActive > 1 {
				notes = append(notes, fmt.Sprintf("%d hosts in the gh hosts file name an active account that is not in their account list", unlistedActive))
			}
		} else if !os.IsNotExist(err) {
			notes, failed = append(notes, "could not read hosts file"), true
		}
	}

	hosts := slices.Clone(fileHosts)
	if h := getenv("GH_HOST"); h != "" {
		if validHost.MatchString(h) {
			hosts = append(hosts, strings.ToLower(h))
		} else {
			notes = append(notes, "ignored GH_HOST: invalid host name")
		}
	}
	hosts = append(hosts, defaultHost)
	setOf := func(names ...string) (set []string) {
		for _, n := range names {
			if getenv(n) != "" {
				set = append(set, n)
			}
		}
		return set
	}
	// The environment token is its own credential: gh prefers it over any stored account.
	addEnv := func(host string, set []string) {
		if len(set) == 0 {
			return
		}
		add(model.Credential{Tool: "gh", ID: "@" + host, Label: model.Sanitize(set[0] + "@" + host), Kind: "env-token",
			Source: "env", EnvVars: set, Host: host})
		s.envHost[host] = true
	}
	enterprise := setOf("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
	seenHost, haveEnterpriseHost := map[string]bool{}, false
	for _, h := range hosts {
		if seenHost[h] {
			continue
		}
		seenHost[h] = true
		if h == defaultHost || strings.HasSuffix(h, ".ghe.com") || h == "github.localhost" {
			addEnv(h, setOf("GH_TOKEN", "GITHUB_TOKEN"))
		} else {
			haveEnterpriseHost = true
			addEnv(h, enterprise)
		}
	}
	for _, c := range stored {
		add(c)
	}
	// A real host always keeps its name: placeholders (no Host, never queried) are added only when the ID is free.
	placeholder := func(c model.Credential) {
		if !ids[c.ID] {
			add(c)
		}
	}
	if len(enterprise) > 0 && !haveEnterpriseHost {
		placeholder(model.Credential{Tool: "gh", ID: "enterprise", Label: "enterprise", Kind: "env-token", Source: "env",
			EnvVars: enterprise, Notes: []string{"host unknown"}})
	}
	if (failed || badHosts+badAccounts > 0) && len(creds) == 0 {
		placeholder(model.Credential{Tool: "gh", ID: "unreadable", Label: "unreadable", Kind: "unknown", Source: "file", Files: []string{path}})
	}

	sort.Slice(creds, func(i, j int) bool { return creds[i].ID < creds[j].ID })
	for i := range creds {
		creds[i].Notes = append(creds[i].Notes, notes...)
	}
	return creds, nil
}
