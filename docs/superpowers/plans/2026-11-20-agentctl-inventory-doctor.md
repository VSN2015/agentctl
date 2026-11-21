# agentctl inventory + doctor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `agentctl inventory` and `agentctl doctor` for Claude Code with `aws` and `gh` scanners, as static binaries for macOS and Linux (x86-64, arm64) that other people can install.

**Architecture:** Built for extension along three axes, each behind one small interface and each listed in exactly one place (`internal/registry/registry.go`): a `scan.Scanner` per tool (discover from local files, optionally resolve online, read-only) paired with a `rules.ToolRule` per tool; an `agent.Agent` per coding agent (usage for a window, access classification, block advice); and one cobra subcommand per file under `internal/cli/`. The pipeline (`internal/run`) and renderers (`internal/render`) iterate over those lists and never branch on a tool or agent name, so `fix`, kubectl/docker/MCP, and Codex later are new files plus one registration line each. Provider calls sit behind interfaces so tests make no network calls.

**Tech Stack:** Go (stdlib `encoding/json`, `os/exec`); `github.com/spf13/cobra` for the command line (to be confirmed); `go.yaml.in/yaml/v3` for gh `hosts.yml` (the maintained successor of `gopkg.in/yaml.v3`; to be confirmed); `github.com/aws/aws-sdk-go-v2` (`config`, `service/sts`, `service/iam`) for AWS (to be confirmed); the installed `gh` CLI (via `gh api`) for GitHub scopes. No gh library: shelling out keeps the token out of this process.

**Spec:** `/Users/sang/Projects/individual-projects/agentctl/docs/superpowers/specs/2026-11-20-agentctl-design.md` (this plan implements item 1 of its "Order of work" only). Executors read the spec and this plan.

## Global Constraints

- Local only. No AI model, no telemetry, no update check. (Set `GH_NO_UPDATE_NOTIFIER=1` for every `gh` call.)
- Online by default; `--offline` disables all network access and reports only what the files show.
- macOS and Linux, laptops and servers. Single binary, no runtime dependencies, written in Go. License Apache-2.0.
- Linux builds for x86-64 and arm64, statically linked (`CGO_ENABLED=0`); macOS builds for x86-64 and arm64.
- Flags: `--offline`; `--since <duration>` (default 30 days); `--json` (for `inventory` and `doctor`); `--yes` (answers yes to the online prompt).
- Secret values are never read into output, logs, or errors. Tokens are passed to provider calls only, by the provider's own SDK or CLI.
- Every provider call is read-only and has a timeout. The providers to be contacted are printed before any call is made.
- Online checks are never interactive: a profile that would need a browser login, an MFA code, or an expired session to be renewed is skipped with a note and reported from files only.
- One prompt per run, listing every provider about to be contacted and noting the audit-log effect. Answering no continues offline. The answer is not remembered between runs: no state file. `--yes` skips the prompt; `--offline` makes it unnecessary. With no terminal and neither flag, exit status 2 with a message naming the two flags.
- A failed or unauthorized provider call degrades that finding to the offline result with a note; it does not fail the run.
- No proxy, daemon, state file, or background process. Nothing is written to disk by these two commands.
- `doctor` exits 0 when there are no HIGH findings, 1 when there are, 2 on an error. Plain output (no colour, no symbols that need a special font) when not attached to a terminal.
- Anti-goals (project failure if violated): printing, logging, or transmitting a secret value; sending anything to anyone but the provider a credential belongs to; any provider call that is not read-only; changing a file without showing the change and getting a yes (these commands change no file); recommending revocation of a credential the developer still uses; presenting agent deny rules as a hard security boundary (output must say they are advisory without a sandbox).
- A run covers the whole machine: agent usage is summed across every project's session history.
- Reachability: reachable = exists on the machine and agent configuration does not deny the tool. Denying only the credential file is not "denied" (the tool can still pick the credential up from the environment or another source): it is shown as "credential file blocked, tool still allowed" and the risk finding stands. States shown: denied, asks first, allowed without asking. Launch flags (such as skipping all permission prompts) are not visible in configuration files and are not detected; the output says so.
- Usage rules: unused = no agent use in the window; rarely used = fewer than 3 agent uses in the window, lower severity, "consider removing"; if history covers less than the window, say how many days of history were available instead of claiming "unused". When use cannot be attributed, say so and do not claim "unused".
- `aws` with no profile in the command or its inline environment counts as use of the default profile.
- Developer use vs agent use: shell history (zsh, bash) can only prove the developer does use a tool, never absence. Only provider last-used data (AWS access keys, online) proves absence. Known recent developer use (dated shell history or provider data): recommend blocking the agent only. Shell history without timestamps counts as unknown. Provider data shows no use by anyone in the window: recommend revoking the credential. Otherwise unknown: block the agent only, plus one line saying to revoke if the developer does not use it either. Revocation is never recommended on a guess.
- Fine-grained and GitHub App tokens do not report scopes: listed with "permissions cannot be read" and no scope finding. Agent use maps to scopes coarsely, by `gh` command group.
- Server sources: report credentials present in the environment by variable name, never value; online, resolve AWS through the standard credential chain (instance or container role). A server with no `~/.aws` must not be reported as having no AWS access. Whose access: the account `agentctl` runs as.
- Offline cannot say what a credential can do. Mapping agent commands to provider permissions is coarse: tool level for all, scope level for GitHub. Fine-grained AWS action analysis is not attempted.
- Testing: scanners and readers run against fixture home directories; provider calls behind an interface with fakes (no network in tests); rules are pure functions.
- Scope fence: no `fix`, kubectl/docker/MCP scanners or rules, Codex, nono output. Interfaces leave room for them; no code for them.
- Dependencies minimal: stdlib first; third-party only cobra, a maintained YAML library, and the AWS SDK. Commit messages follow the session's attribution rule.
- Extensibility (owner's request): subcommands, tools, and agents are each added by new files plus one line in one registry; `internal/run` and `internal/render` contain no per-tool or per-agent branching; no plugin loading and no configuration files.
- JSON contract: `--json` output carrying `schema_version` is a stable contract for a future user interface or other programs: fields are added, never renamed or removed, without bumping `schema_version`. The pipeline produces the report as data (`run.Collect`) before any printing.
- Command line: cobra must not change exit statuses (0 / 1 / 2 exactly as the spec states) and must write nothing to stdout except the report, `--help`, and `--version`; in `--json` mode stdout carries only the JSON document.

## Review Focus

Inputs the spec implies but its own tests do not pin; each has a named test in the owning task.

1. Missing, empty, or unreadable inputs (no `~/.aws`, no gh config, no `~/.claude`, a permission-denied file, empty files): expected a clear "nothing found" result, exit 0, no crash. Tests: Tasks 3, 5, 7, 8, 12.
2. Session files with multi-megabyte lines, a truncated final line, non-JSON lines, the same `tool_use` id repeated across records or files: expected skipped lines and de-duplicated counts (counts drive the "fewer than 3" rule). Test: Task 7.
3. Hostile or odd text in names (control characters, ANSI escapes, bidi overrides in profile names, hosts, ARNs; spaces and unicode in profile names; `[profile default]` vs `[default]`): expected sanitised terminal output and valid JSON. Tests: Tasks 2, 3, 12.
4. Secret canaries in the credentials file, environment, shell commands, session history, and gh hosts file: expected to appear nowhere in stdout, stderr, JSON, notes, or errors. Test: Task 13 (end to end), plus parser-level checks in Tasks 3, 5, 6.
5. Compound or nested shell commands (`bash -c '...'`, `$(...)`, `sudo`, `env X=y`, pipes, `--profile=x`, `gh api`): expected to be counted as use, never as "unused". Tests: Tasks 6, 10.

## Facts established on this machine

Observed means seen locally (structure and key names only; no content was copied). Assumed means the implementer must confirm against current documentation in the task's first step.

| Fact | Status |
|---|---|
| Go installed: `go1.27.3 darwin/arm64` at `/opt/homebrew/bin/go`. Module floor chosen as `go 1.24` (planner's call); `go get` of the AWS SDK may force a higher `go` line, in which case keep the SDK's. Third-party modules are not in the local module cache. | Observed |
| Session history: JSONL files at `~/.claude/projects/<cwd path with separators replaced by "-">/<sessionId>.jsonl`, plus `<sessionId>/subagents/*.jsonl`. Records have `type` (`assistant`, `user`, `system`, `attachment`, others), `timestamp` (ISO-8601 UTC with milliseconds, `Z`), `sessionId`, `cwd`, `isSidechain`. Assistant records carry `message.content[]`; items of `type:"tool_use"` have `id`, `name`, `input`, `caller`. Shell calls are `name:"Bash"` with `input.command` (also `description`, sometimes `timeout`). MCP calls are `name:"mcp__<server>__<tool>"` (thousands seen). Records appear to be written one per content block (key `apiBlockIndex`), so the same `tool_use` id may recur: de-duplicate by id. | Observed |
| Retention of session files follows setting `cleanupPeriodDays` (key observed in `~/.claude/settings.json`; meaning assumed). `CLAUDE_CONFIG_DIR` overrides `~/.claude`. | Assumed |
| Permission settings: user `~/.claude/settings.json` has `permissions.defaultMode`; `~/.claude/settings.local.json` and project `.claude/settings.local.json` exist; `permissions.allow` is an array of strings, rule form `Tool` observed (`WebSearch`). Also seen: `env`, `hooks`, `enabledPlugins` keys in the same file (never decode these: `env` may hold secrets). | Observed |
| `permissions.ask` and `permissions.deny` arrays; rule grammar `Tool(specifier)` with Bash specifiers `aws:*`, `aws *`, exact text; MCP rules `mcp__server` and `mcp__server__tool`; `Read(path)` rules; mode value `bypassPermissions`; precedence deny, then ask, then allow; project file `<project>/.claude/settings.json`; managed file `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS) and `/etc/claude-code/managed-settings.json` (Linux; neither directory exists on this machine). | Assumed |
| gh stores hosts in `$GH_CONFIG_DIR/hosts.yml`, else `$XDG_CONFIG_HOME/gh/hosts.yml`, else `~/.config/gh/hosts.yml`; top-level key per host; indented keys `user`, `users`, `git_protocol`, and `oauth_token` only when the token is not in the keychain. A safety hook on this machine blocked the attempt to inspect that file, so nothing about it was observed. Env tokens: `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`; `GH_HOST` selects the default host. `gh api -i --hostname H user` prints status line, headers (including `X-Oauth-Scopes` for classic and OAuth tokens, absent for fine-grained and App tokens), blank line, JSON body. | Assumed |
| `~/.aws` was not inspected (same restriction). AWS files: `~/.aws/config` (`[default]`, `[profile x]`, `[sso-session x]`), `~/.aws/credentials` (`[x]`), overridable by `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`. | Assumed |
| AWS library: `github.com/aws/aws-sdk-go-v2/config`, `.../service/sts`, `.../service/iam` (official, v2). `config.WithSharedConfigProfile`, `config.WithDefaultRegion`, `config.WithRetryMaxAttempts` exist. Whether env credentials override an explicitly chosen profile must be checked in the SDK source in Task 4 Step 1. | Assumed |
| gh library: none. Scopes come from running `gh` itself, so the token never enters this process. | Planner's call |
| YAML library `go.yaml.in/yaml/v3` (the YAML organisation's maintained continuation of `gopkg.in/yaml.v3`, whose repository was archived). Not in the local module cache; module path and current maintenance status to be confirmed in Task 5 Step 1. yaml error text can quote the offending value, so error text is never printed. | Assumed |
| CLI library `github.com/spf13/cobra` (`Command.ExecuteC`, `SilenceUsage`, `SilenceErrors`, `SetOut`, `SetErr`, `SetFlagErrorFunc`, `CompletionOptions.DisableDefaultCmd`, `Version` and `SetVersionTemplate`). Not in the local module cache; to be confirmed in Task 1 Step 2. | Assumed |
| EC2 hint: `/sys/class/dmi/id/sys_vendor` equals `Amazon EC2` on Nitro instances. | Assumed |

## Decisions made by the planner

- Module path is `github.com/OWNER/agentctl` (owner's GitHub name unknown). Task 13 replaces it with one command before release. Question for the owner.
- CLI: cobra, one file per subcommand, flags defined once in `internal/cli/flags.go`. Cobra never prints (`SilenceUsage`, `SilenceErrors`) and never exits the process; `cli.Run` maps every outcome to 0 / 1 / 2 and prints messages itself, to stderr. The prompt also writes to stderr so stdout stays clean data.
- Agent interface has five methods (`Name`, `ReadUsage`, `Classify`, `BlockAdvice`, `Posture`), one more than the owner listed: `BlockAdvice` is needed because the text for blocking a tool is agent-specific (Claude Code deny-rule syntax), and `Posture` carries "unrestricted shell" and settings-file notes. Both would otherwise force Claude-specific strings into per-tool rules.
- Tool rules (`rules.ToolRule`) are paired with scanners in the registry; the generic engine in `rules/rules.go` handles denied credentials, unused/rare classification, severity merging, advice composition, and the advisory sentence.
- Finding ID form: `<agent>:<tool>:<subject>` (for example `claude-code:aws:prod`, `claude-code:gh:github.com`) and `<agent>:shell` for the unrestricted-shell finding. One finding per (agent, credential), carrying every rule that fired in `Rules`.
- Severity: AWS admin HIGH; AWS long-lived key MED; GitHub unused scopes MED; unrestricted shell MED; usage "unused" MED, "rarely used" LOW. A finding's severity is the maximum of what fired. "Asks first" is shown on the finding but does not change severity. Credentials whose tool is denied produce an OK line, never a risk finding. A blocked credential file with the tool not denied still produces risk findings, labelled "credential file blocked, tool still allowed".
- The spec example prints `agentctl fix ...`; `fix` is not in this plan, so advice prints the deny rule text to add by hand (`Bash(aws:*)`, `Bash(gh:*)` in `permissions.deny` of `~/.claude/settings.json`) and never names `fix`.
- Shell history without timestamps counts as unknown developer use (spec text); only dated history within the window is "known recent". The output may say "found in shell history, no dates" but the recommendation follows the unknown branch.
- When history is shorter than the window, a count under 3 (including 0) is reported as a number of uses in N days of history, with no "unused" or "rarely used" claim.
- Shell attribution is a regex over the whole command text, biased toward "used" (see Task 6). Shortcut: `echo aws` counts as an aws call; upgrade to a real shell tokenizer if false "used" results prove common.
- gh calls attribute to the host named by `--hostname` or `GH_HOST=` in the command, else to the default host (`GH_HOST` from the environment, else `github.com`).
- AWS profiles with `credential_process` or `mfa_serial` are not resolved online (they can prompt or run external code); they are skipped with a note.
- Credential-file deny rules (`Read(~/.aws/**)` style) do not make a credential "denied". They set `Credential.FileBlocked`; the label "credential file blocked, tool still allowed" is shown and risk findings still apply (spec correction).
- Online resolution is sequential, 20 s per credential, Ctrl-C cancels the run (exit 2).
- No CI workflow and no GoReleaser; a shell script builds the release archives.

## File Structure

```
cmd/agentctl/main.go                      thin main
internal/cli/root.go                      cobra root; the ONLY place subcommands are registered
internal/cli/{inventory,doctor}.go        one file per subcommand
internal/cli/flags.go since.go exec.go    shared flags (defined once), --since parsing, default Exec
internal/registry/registry.go             the ONLY lists of scanners, tool rules, and agents
internal/model/                           shared types, Sanitize, MaskKeyID
internal/scan/scanner.go                  Scanner interface, Env, Runner, SkipError
internal/scan/aws/                        ini.go discover.go admin.go resolve.go sdk.go
internal/scan/gh/                         discover.go resolve.go
internal/usage/usage.go                   Usage types
internal/usage/shellparse/                command text to Invocations
internal/agent/agent.go                   Agent interface
internal/agent/claude/                    reader.go (usage) settings.go (permissions) agent.go (implements Agent)
internal/devuse/                          shell-history developer use
internal/rules/                           rules.go (generic engine, ToolRule), aws.go, gh.go, agent.go (per-tool / per-agent files)
internal/confirm/                         online prompt
internal/run/                             options.go, pipeline
internal/render/                          text and JSON output
scripts/build.sh  README.md  LICENSE  .gitignore  go.mod
```

---

### Task 1: Project skeleton and cobra command line

**Files:**
- Create: `go.mod`, `.gitignore` (`dist/`, `*.test`, `coverage.out`, `.DS_Store`, `.claude/settings.local.json`), `cmd/agentctl/main.go`, `internal/run/options.go`, `internal/cli/root.go`, `internal/cli/inventory.go`, `internal/cli/doctor.go`, `internal/cli/flags.go`, `internal/cli/since.go`, `internal/cli/exec.go`
- Test: `internal/cli/cli_test.go`, `internal/cli/since_test.go`

**Interfaces:**
- Produces:
  ```go
  package run // internal/run/options.go
  type Options struct { Command string; Offline, Yes, JSON bool; Since time.Duration }

  package cli
  type IO struct { In io.Reader; Out, Err io.Writer; InIsTTY, OutIsTTY bool; Getenv func(string) string; Home, Cwd string }
  type Exec func(ctx context.Context, o run.Options, io IO) int      // the pipeline seam; returns 0 / 1 / 2
  func Run(args []string, io IO) int                                 // builds ctx with signal.NotifyContext(os.Interrupt, SIGTERM); returns the exit status
  func newRoot(io IO, exec Exec) *cobra.Command                      // test seam; the one line `root.AddCommand(newInventoryCmd(io, exec), newDoctorCmd(io, exec))` is the only registration point
  type ExitError struct{ Code int; Msg string }                      // carries a status out of RunE; Msg (if non-empty) is printed to Err
  type commonFlags struct { offline, yes, json bool; since string }
  func (f *commonFlags) register(cmd *cobra.Command)                 // --offline, --since (default "30d"), --json, --yes: defined here once, called by every subcommand that needs them
  func (f *commonFlags) options(command string) (run.Options, error)
  func ParseSince(s string) (time.Duration, error)                   // "30d", "12h", "90m", "1d12h"; > 0 only
  var Version = "dev"                                                // set by -ldflags in Task 13
  var defaultExec Exec                                               // Task 1: prints "not implemented" to Err, returns 2; Task 12 replaces it with the real pipeline
  ```
  Adding `fix` later is `internal/cli/fix.go` (its own `newFixCmd` calling `commonFlags.register`) plus one added argument in the `AddCommand` line.
  Status contract in `Run`: `ExecuteC` returns the failing command and an error. nil gives 0. `*ExitError` gives its `Code` (printing `Msg` if any). Any other error (unknown command, unknown flag, extra argument, bad `--since`, no subcommand) prints `agentctl: <error>` and that command's `UsageString()` to Err and gives 2. Subcommand `RunE` returns `&ExitError{Code: code}` with empty `Msg` for a non-zero `Exec` result. Root and subcommands set `SilenceUsage: true`, `SilenceErrors: true`, `SetOut(io.Out)`, `SetErr(io.Err)`, `CompletionOptions{DisableDefaultCmd: true}`, `Args: cobra.NoArgs`; the root has a `RunE` that returns a usage error so that no arguments gives 2, not help with status 0. `Version` is shown through the root's `Version` field and `SetVersionTemplate("agentctl {{.Version}}\n")`.

- [ ] **Step 1: Initialise the repository and module.** Run `git init -b main` and `go mod init github.com/OWNER/agentctl` in `/Users/sang/Projects/individual-projects/agentctl`, then set the `go` line to `1.24`. Create `.gitignore`. Confirm `git status` shows `docs/` and `.claude/` untracked.

- [ ] **Step 2: Add and confirm cobra.** `go get github.com/spf13/cobra`. Check in the module source that the API names listed under Facts exist and that, with `SilenceUsage` and `SilenceErrors`, `ExecuteC` prints nothing itself. Record the resolved version in the commit message.

- [ ] **Step 3: Write the failing tests** (all use `newRoot` with a fake `Exec` that records calls)

```go
func TestParseSince(t *testing.T) { // table
  // "30d"->720h, "12h"->12h, "90m"->90m, "1d12h"->36h
  // errors: "", "0", "-5d", "abc", "30"
}
func TestOptionsMapping(t *testing.T) { // ["doctor"] => Exec called with Command "doctor", Since 720h, !Offline, !Yes, !JSON
  // ["inventory","--offline","--json","--yes","--since","7d"] => all set, Since 168h, Command "inventory"
}
func TestExecStatusPassesThroughUntouched(t *testing.T) { // fake Exec returns 0, 1, 2 for "doctor --json"
  // Run returns the same status each time; Out is empty; Err is empty (no "Error:", no "Usage:", nothing cobra-printed)
}
func TestUsageErrorsExit2(t *testing.T) { // table: [], ["bogus"], ["doctor","--nope"], ["doctor","extra"], ["inventory","--since","abc"], ["doctor","--since","0"], ["completion"]
  // each: Run returns 2; Err contains "agentctl:" and a "Usage:" block (for [] and ["bogus"] the block names "inventory" and "doctor"); fake Exec never called
}
func TestJSONModeUsageErrorsLeaveStdoutEmpty(t *testing.T) { // ["doctor","--json","--nope"], ["inventory","--json","--since","x"], ["doctor","--json","extra"]
  // Run returns 2; Out.Len()==0; the message is on Err
}
func TestHelpAndVersionGoToStdoutAndExit0(t *testing.T) { // ["--help"] => 0, Out names "inventory" and "doctor", Err empty
  // ["doctor","--help"] => 0, Out contains "--offline", "--since", "--json", "--yes"
  // ["--version"] => 0, Out == "agentctl dev\n"
}
func TestSharedFlagsDefinedOnce(t *testing.T) { // for inventory and doctor: flag names {"offline","since","json","yes"} exist with identical defaults and usage strings
  // a throwaway command in the test calling (&commonFlags{}).register gets the same four flags (proves a future fix.go reuses them without redefining)
}
func TestExitErrorMessagePrinted(t *testing.T) { // fake Exec path returning ExitError{2,"boom"} through RunE helper => Err contains "boom", status 2
}
```
- [ ] **Step 4: Run to verify failure.** `go test ./internal/cli/ -v` expects FAIL (undefined symbols).

- [ ] **Step 5: Implement** the files above and `main.go` (`os.Exit(cli.Run(os.Args[1:], io))`, TTY detection by `os.Stdin.Stat()` and `os.Stdout.Stat()` `Mode()&os.ModeCharDevice != 0`, `Home` from `os.UserHomeDir()`, `Cwd` from `os.Getwd()`). `ParseSince` accepts a `d` suffix (days) combined with `time.ParseDuration` units by pre-splitting on the `d`.

- [ ] **Step 6: Run to verify pass.** `go test ./internal/cli/ -v` PASS; `go vet ./...` clean; `go run ./cmd/agentctl bogus; echo $?` prints a message and `2`.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum .gitignore cmd internal/cli internal/run
git commit -m "feat: project skeleton and cobra command line"
```

---

### Task 2: Shared model, sanitising, key masking

**Files:**
- Create: `internal/model/model.go`, `internal/model/sanitize.go`
- Test: `internal/model/sanitize_test.go`

**Interfaces:**
- Produces:
  ```go
  package model
  type AgentAccess string // "denied" | "asks" | "allowed"
  type Severity int       // SevOK < SevLow < SevMed < SevHigh; String() "OK","LOW","MED","HIGH"
  type Credential struct {
    Tool, ID, Label, Kind, Source string // Tool is the scanner Name() ("aws", "gh", later others); ID unique per Tool; Source "file"|"env"|"chain"
    Provider  string   // display name from Scanner.Provider(), set by the pipeline after Discover; used by prompt and renderers
    Files     []string // absolute paths backing it (for file-deny matching)
    EnvVars   []string // variable NAMES only
    LongLived bool
    KeyID     string   // masked only
    Identity  string   // offline-known identity, e.g. role ARN, gh user
    Access    []AgentState // one entry per registered agent, in registry order; set by the pipeline
    Resolved  *Resolution
    Notes     []string
  }
  type AgentState struct {
    Agent       string      // agent Name()
    Access      AgentAccess // about the tool only
    FileBlocked bool        // a deny rule covers the credential file; does not change Access (spec)
  }
  type Resolution struct {
    Identity string
    Admin    bool; AdminWhy string
    Scopes   []string; ScopesReadable bool
    KeyChecked bool; KeyLastUsed *time.Time // KeyChecked && nil => provider says never used
  }
  type Finding struct {
    ID string; Rules []string; Severity Severity; Agent, Tool, Subject, Headline string
    Details, Advice []string; Access AgentAccess; FileBlocked bool
  }
  func Sanitize(s string) string  // C0, DEL, C1 controls and U+202A-202E, U+2066-2069 become '?'; tab and newline too
  func MaskKeyID(id string) string // "AKIAIOSFODNN7EXAMPLE" -> "AKIA****MPLE"; len<12 -> "****"
  ```

- [ ] **Step 1: Write the failing tests** (Review Focus 3)

```go
func TestSanitize(t *testing.T) {
  // "prod" -> "prod"; "pr\x1b[31mod" -> "pr?[31mod"; "a‮b" -> "a?b"; "tab\there" -> "tab?here"; "naïve 名前" unchanged
}
func TestMaskKeyID(t *testing.T) { // masks as above; "" -> ""; "short" -> "****"
}
func TestSeverityString(t *testing.T) { // SevHigh.String()=="HIGH"; SevHigh > SevMed
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/model/ -v`
- [ ] **Step 3: Implement** the types and the two functions in the files above.
- [ ] **Step 4: Run, expect PASS.** Same command.
- [ ] **Step 5: Commit** `git add internal/model && git commit -m "feat: shared model and sanitising"`

---

### Task 3: Scanner interface and AWS discovery (files and environment)

**Files:**
- Create: `internal/scan/scanner.go`, `internal/scan/aws/ini.go`, `internal/scan/aws/discover.go`
- Test: `internal/scan/aws/discover_test.go`; fixtures `internal/scan/aws/testdata/home-basic/.aws/{config,credentials}`, `home-empty/` (a bare directory with `.gitkeep`), `home-weird/.aws/config`

**Interfaces:**
- Produces:
  ```go
  package scan
  type Env struct { Home string; Getenv func(string) string; SysRoot string } // SysRoot default "/sys/class/dmi/id"
  type Runner interface { Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) }
  type SkipError struct{ Reason string }; func (e *SkipError) Error() string
  type Scanner interface {
    Name() string     // "aws"
    Provider() string // "AWS", used in the prompt
    Discover(env Env) ([]model.Credential, error)                                  // local only, never network
    Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error)    // read-only; *SkipError means skipped by design
  }
  ```
  `package aws`: `type Scanner struct{...}`; `func New(api APIFactory) *Scanner` (Task 4 defines `APIFactory`); `func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error)`. Credential IDs: profile name, `environment` (env access keys), `chain` (web identity, container role, or EC2 hint). `Kind` values: `access-key`, `sso`, `assume-role`, `web-identity`, `credential-process`, `unknown`.

- [ ] **Step 1: Confirm assumptions.** Read current AWS docs/SDK source for the shared config file format and the file-override variables listed under Facts; adjust the allow-list below only if they differ.

- [ ] **Step 2: Write the failing tests**

```go
func TestParseINIKeepsOnlyAllowedKeys(t *testing.T) {
  // input has aws_secret_access_key = CANARY-SECRET-DO-NOT-PRINT in [prod]
  // parseINI(r, keep) result for prod has aws_access_key_id but no value anywhere equal to the canary; secret key reported only as present=true
  // handles comments (# and ;), blank lines, "key=value" without spaces, CRLF, a header with trailing comment
}
func TestDiscoverBasic(t *testing.T) { // home-basic: config [default], [profile prod] (role_arn+source_profile), [profile dev-sso] (sso_session), [sso-session s] (must not become a profile); credentials [default] with key
  // want IDs {"default","prod","dev-sso"}; default.Kind=="access-key", LongLived; KeyID masked "AKIA****MPLE"; prod.Kind=="assume-role", prod.Identity==role ARN; dev-sso.Kind=="sso"; Files contain the absolute config/credentials path
}
func TestDiscoverTemporaryKeyIsNotLongLived(t *testing.T) { // key with aws_session_token, or ASIA prefix => LongLived=false
}
func TestDiscoverEnvironment(t *testing.T) { // Getenv has AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (canary value)
  // => credential ID "environment", EnvVars==["AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"], KeyID masked, canary absent from fmt.Sprintf("%+v", creds)
}
func TestDiscoverChainTriggers(t *testing.T) { // AWS_WEB_IDENTITY_TOKEN_FILE set => "chain"; AWS_CONTAINER_CREDENTIALS_RELATIVE_URI set => "chain"
  // SysRoot dir with sys_vendor "Amazon EC2" and no other AWS creds => "chain"; same but a profile exists => no "chain"
}
func TestDiscoverEmptyHome(t *testing.T) { // Review Focus 1: home-empty, no env => no credentials, nil error
  // also: ~/.aws/credentials is a directory or chmod 000 => no panic, error nil, Notes mention "could not read" without file contents
}
func TestDiscoverFileOverrides(t *testing.T) { // AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE point elsewhere => those are read
}
func TestDiscoverOddProfileNames(t *testing.T) { // Review Focus 3: home-weird: "[profile my team]", "[profile 名前]", "[profile bad\x1b[31m]"
  // IDs are the raw names; Label is model.Sanitize'd; "[default]" and "[profile default]" are the same profile
}
```
- [ ] **Step 3: Run, expect FAIL.** `go test ./internal/scan/... -v`
- [ ] **Step 4: Implement** `parseINI(r io.Reader, keep map[string]bool) (map[string]map[string]string, error)` which discards every non-allow-listed key at parse time. Allow-list: `aws_access_key_id`, `aws_session_token` (stored as "1", never the value), `aws_secret_access_key` (stored as "1"), `role_arn`, `source_profile`, `credential_source`, `sso_session`, `sso_start_url`, `web_identity_token_file`, `credential_process` (stored as "1"), `mfa_serial` (stored as "1"). `Discover` merges config and credentials by profile name, strips the `profile ` prefix, ignores `sso-session` and `services` sections, keeps the raw access key id inside the `Scanner` (map by credential ID, never in `model.Credential`), and sets the chain candidate per the tests (`InstanceRoleHint` reads `SysRoot/sys_vendor`).
- [ ] **Step 5: Run, expect PASS.** Same command; `go vet ./...`.
- [ ] **Step 6: Commit** `git add internal/scan && git commit -m "feat: scanner interface and aws file discovery"`

---

### Task 4: AWS online resolution (identity, admin check, key last-used)

**Files:**
- Create: `internal/scan/aws/admin.go`, `internal/scan/aws/resolve.go`, `internal/scan/aws/sdk.go`
- Modify: `go.mod`, `go.sum` (via `go get`)
- Test: `internal/scan/aws/admin_test.go`, `internal/scan/aws/resolve_test.go`, `internal/scan/aws/sdk_test.go`

**Interfaces:**
- Consumes: `scan.Scanner`, `scan.SkipError`, `model.Resolution` (Tasks 2-3); the scanner's internal raw key-id map from Task 3.
- Produces:
  ```go
  package aws
  type Identity struct{ ARN, Account, Kind, Name string } // Kind "user"|"role"|"root"|"other"
  type Policy struct{ Name, ARN string; Document []byte } // Document is decoded JSON; may be nil for AWS-managed AdministratorAccess
  type API interface {
    CallerIdentity(ctx context.Context) (Identity, error)
    Policies(ctx context.Context, id Identity) ([]Policy, error)           // attached managed (documents resolved), inline, and for users the groups' policies
    AccessKeyLastUsed(ctx context.Context, keyID string) (*time.Time, error) // nil => never used
  }
  type APIFactory func(ctx context.Context, profile string) (API, error)     // profile "" = default credential chain
  func IsAdmin(ps []Policy) (bool, string)
  func NewSDK() APIFactory
  func (s *Scanner) Resolve(ctx context.Context, c model.Credential) (*model.Resolution, error)
  ```

- [ ] **Step 1: Confirm against the SDK.** `go get github.com/aws/aws-sdk-go-v2/config github.com/aws/aws-sdk-go-v2/service/sts github.com/aws/aws-sdk-go-v2/service/iam`. In the module source, check (a) whether environment credentials override a profile chosen with `config.WithSharedConfigProfile`; if they do, resolve explicit profiles with a config whose credentials provider is built from that profile only, and write the chosen approach as a code comment; (b) that `GetCallerIdentity` with no region fails and `config.WithDefaultRegion("us-east-1")` fixes it; (c) that a `credential_process` or MFA profile is the only chain step that can prompt.

- [ ] **Step 2: Write the failing tests**

```go
func TestIsAdmin(t *testing.T) { // table
  // ARN arn:aws:iam::aws:policy/AdministratorAccess => true, why mentions "AdministratorAccess"
  // inline Allow Action "*" Resource "*" => true; Action ["s3:*","*"], Resource ["*"] => true; Statement as single object => true
  // Allow Action "s3:*" Resource "*" => false; Effect Deny "*":"*" => false; Allow "*" on Resource "arn:aws:s3:::b" => false
  // Allow "*" "*" with a Condition block => false (not equivalent)
  // empty policy list => false
}
func TestResolveAdminRoleViaFake(t *testing.T) { // fake API: assumed-role identity + AdministratorAccess => Resolution{Identity: ARN, Admin: true}
}
func TestResolveRootIsAdmin(t *testing.T) { // Kind "root" => Admin true without policy calls
}
func TestResolveKeyLastUsed(t *testing.T) { // credential with a file key: fake returns time T => Resolution{KeyChecked:true, KeyLastUsed:&T}; fake returns nil => KeyChecked true, KeyLastUsed nil
  // fake returns access-denied error for AccessKeyLastUsed only => Resolution still returned, KeyChecked false, no error
}
func TestResolveSkipsPromptingProfiles(t *testing.T) { // credential_process profile and mfa_serial profile => *scan.SkipError, factory never called
}
func TestResolveErrorsAreSanitisedAndDegrade(t *testing.T) { // CallerIdentity returns error => Resolve returns error whose text has no control chars and is <=200 chars
}
func TestResolveUsesChainForEnvironmentAndChain(t *testing.T) { // ID "environment" and "chain" call factory with profile "", file profiles with their name
}
func TestSDKInterfacesAreReadOnly(t *testing.T) { // reflect over the unexported stsAPI and iamAPI interfaces: every method name starts with "Get" or "List"
}
func TestSDKPoliciesDecodesAndPages(t *testing.T) { // fake iamAPI: user with 2 pages of attached policies, one inline policy returned URL-encoded, one group => Policy list contains all, documents decoded
}
```
- [ ] **Step 3: Run, expect FAIL.** `go test ./internal/scan/aws/ -v`
- [ ] **Step 4: Implement** `IsAdmin` (pure; Allow statements only, `Action` or `Resource` string or list, any element `*`, no `Condition`, no `NotAction`), `Resolve` (selects the factory profile; 20 s is applied by the caller; returns `*scan.SkipError` for `credential-process` and MFA profiles; degrades `AccessKeyLastUsed` and `Policies` failures into notes via a returned partial resolution), and `sdk.go`: a `config.LoadDefaultConfig` with `WithDefaultRegion("us-east-1")` and `WithRetryMaxAttempts(2)`, adapters over narrow `stsAPI` (`GetCallerIdentity`) and `iamAPI` (`ListAttachedUserPolicies`, `ListUserPolicies`, `GetUserPolicy`, `ListGroupsForUser`, `ListAttachedGroupPolicies`, `ListGroupPolicies`, `GetGroupPolicy`, `ListAttachedRolePolicies`, `ListRolePolicies`, `GetRolePolicy`, `GetPolicy`, `GetPolicyVersion`, `GetAccessKeyLastUsed`) interfaces. Role name comes from the `assumed-role/<ROLE>/<session>` ARN. Permission boundaries, SCPs, and session policies are not evaluated; the Admin result says "attached policies only" in `AdminWhy`.
- [ ] **Step 5: Run, expect PASS.** `go test ./internal/scan/aws/ -v && go vet ./...`
- [ ] **Step 6: Commit** `git add go.mod go.sum internal/scan/aws && git commit -m "feat: aws online resolution"`

---

### Task 5: GitHub scanner (hosts and scopes)

**Files:**
- Create: `internal/scan/gh/discover.go`, `internal/scan/gh/resolve.go`
- Modify: `go.mod`, `go.sum` (`go get go.yaml.in/yaml/v3`)
- Test: `internal/scan/gh/gh_test.go`; fixtures `testdata/home-basic/.config/gh/hosts.yml` (two hosts, one with a synthetic `oauth_token: CANARY-SECRET-DO-NOT-PRINT`), `home-empty/`

**Interfaces:**
- Consumes: `scan.Scanner`, `scan.Runner`, `scan.SkipError`, `scan.Env`.
- Produces:
  ```go
  package gh
  func New(r scan.Runner) *Scanner        // scan.Scanner; Name "gh", Provider "GitHub"
  func ParseAPIResponse(raw []byte) (login string, scopes []string, scopesReadable bool, err error)
  ```
  Credential IDs are host names (`github.com`, `ghe.example.com`); Kind `file-host` or `env-token`; `EnvVars` holds token variable NAMES.

- [ ] **Step 1: Confirm assumptions.** Confirm the YAML module path `go.yaml.in/yaml/v3` resolves with `go get` and is currently maintained (fall back to the module the `gopkg.in/yaml.v3` README points to). Check current `gh` docs for `hosts.yml` layout, `GH_CONFIG_DIR`/`XDG_CONFIG_HOME` handling, `gh api --include` output, and that the `X-Oauth-Scopes` header is absent for fine-grained tokens. If `gh` is installed locally, run `gh --version` and `gh api --help` only; run nothing that calls GitHub.

- [ ] **Step 2: Write the failing tests**

```go
func TestDiscoverHosts(t *testing.T) { // hosts.yml with hosts github.com (user alice) and ghe.example.com (user bob)
  // IDs {"github.com","ghe.example.com"}; Identity "alice"/"bob"; Files==[hosts.yml path]
  // the canary token never appears in fmt.Sprintf("%+v", creds) (Review Focus 4)
}
func TestDiscoverConfigDirPrecedence(t *testing.T) { // GH_CONFIG_DIR beats XDG_CONFIG_HOME beats ~/.config
}
func TestDiscoverEnvTokens(t *testing.T) { // GH_TOKEN set => credential for the default host, Kind "env-token", EnvVars ["GH_TOKEN"]; value never stored
  // GH_ENTERPRISE_TOKEN with GH_HOST=ghe.example.com => credential for that host
  // GH_TOKEN and a hosts.yml entry for github.com => one credential for github.com carrying EnvVars (no duplicate)
}
func TestDiscoverEmptyAndUnreadable(t *testing.T) { // Review Focus 1: no gh dir => none, nil error; hosts.yml a directory / empty / garbage => none, no panic
}
func TestDiscoverYAMLErrorsNeverEchoContent(t *testing.T) { // Review Focus 4: hosts.yml "github.com: CANARY-SECRET-DO-NOT-PRINT" (scalar where a mapping is expected; yaml type-error text would quote it)
  // and "github.com:\n  user: [CANARY-SECRET-DO-NOT-PRINT]" => no credentials, notes say only "could not parse hosts file", canary absent from creds, notes, and the returned error
}
func TestHostEntryHasNoTokenField(t *testing.T) { // reflect over the decode struct type: its only field is User; fails if any field name contains "token" (case-insensitive)
}
func TestParseAPIResponse(t *testing.T) { // table over raw `gh api -i` output
  // "HTTP/2.0 200 OK\r\nX-Oauth-Scopes: repo, workflow, admin:org\r\n...\r\n\r\n{\"login\":\"alice\"}" => alice, [repo workflow admin:org], true
  // header present but empty => scopes [], readable true
  // header absent => readable false
  // header name in lower case (x-oauth-scopes) works; body not JSON => error
}
func TestResolveRunsExactlyOneReadOnlyCommand(t *testing.T) { // fake Runner records call
  // name "gh", args ["api","-i","--hostname","ghe.example.com","user"]; env contains GH_NO_UPDATE_NOTIFIER=1 and GH_PROMPT_DISABLED=1
}
func TestResolveDegrades(t *testing.T) { // gh not found (exec.ErrNotFound) => *scan.SkipError "gh not installed"; non-zero exit => error with no raw output text
}
```
- [ ] **Step 3: Run, expect FAIL.** `go test ./internal/scan/gh/ -v`
- [ ] **Step 4: Implement.** Discovery decodes `hosts.yml` with the YAML library into `map[string]hostEntry` where `type hostEntry struct{ User string `yaml:"user"` }` has no token field, so `oauth_token` and `users` are skipped by the decoder and the token value is never stored in a result. The file buffer holds the token transiently during parsing (unavoidable); it is never copied. Any decode error is replaced by the fixed note "could not parse hosts file": yaml error text is never printed or returned. `Resolve` runs the command above through `Runner` (cap output at 1 MiB), parses with `ParseAPIResponse`, and returns `Resolution{Identity: login, Scopes, ScopesReadable}`. A real `Runner` (`ExecRunner`) lives in `internal/scan/runner.go` using `exec.CommandContext` and the given env appended to the parent's.
- [ ] **Step 5: Run, expect PASS.** `go test ./internal/scan/... && go vet ./...`
- [ ] **Step 6: Commit** `git add go.mod go.sum internal/scan && git commit -m "feat: gh scanner"`

---

### Task 6: Shell command attribution

**Files:**
- Create: `internal/usage/shellparse/shellparse.go`
- Test: `internal/usage/shellparse/shellparse_test.go`

**Interfaces:**
- Produces:
  ```go
  package shellparse
  type Invocation struct{ Tool, Sub, Target string } // Tool "aws"|"gh"; aws: Target=profile ("" = none named); gh: Sub=first word after gh, Target=host ("" = none named)
  var Tools = []string{"aws", "gh"}                   // extension point for later tools
  func Parse(command string) []Invocation             // one Invocation per (tool, target) for aws, per (sub, target) for gh, per command text; never retains the command
  ```

- [ ] **Step 1: Write the failing tests** (Review Focus 5)

```go
func TestParseAWS(t *testing.T) { // table; Tool "aws" in every row
  // "aws s3 ls" -> Target ""
  // "aws s3 ls --profile prod" -> "prod"; "aws --profile=prod s3 ls" -> "prod"
  // "AWS_PROFILE=prod aws s3 ls" -> "prod"; "env AWS_PROFILE=prod aws sts get-caller-identity" -> "prod"
  // "sudo aws s3 ls" -> ""; "cd x && aws s3 ls | head" -> ""
  // "bash -c 'aws s3 ls --profile prod'" -> "prod"; "echo $(aws sts get-caller-identity --profile dev)" -> "dev"
  // "aws s3 ls --profile a && aws s3 ls --profile b" -> two Invocations a and b
  // "awscli-wrapper x", "naws x", "paws" -> none (whole-word only)
}
func TestParseGH(t *testing.T) {
  // "gh pr list" -> Sub "pr"; "gh api repos/x/y" -> Sub "api"; "gh --version" -> Sub "" ; "GH_HOST=ghe.example.com gh issue list" -> Target "ghe.example.com"
  // "gh pr list --hostname ghe.example.com" -> Target "ghe.example.com"; "ghost x" -> none; "gh pr list && gh run list" -> two (pr, run)
}
func TestParseNoneForOtherTools(t *testing.T) { // "ls -la", "git push", "" -> empty slice
}
func TestParseDoesNotRetainSecrets(t *testing.T) { // command "AWS_SECRET_ACCESS_KEY=CANARY-SECRET-DO-NOT-PRINT aws s3 ls" -> fmt.Sprintf("%+v", result) lacks the canary
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/usage/shellparse/ -v`
- [ ] **Step 3: Implement `Parse`** by regex over the whole text: a tool is a whole word preceded by start, whitespace, or one of `;&|(` `` ` `` `"` `'` and followed by whitespace or end. The window for a profile is the whole command text (`--profile[ =]X` or `AWS_PROFILE=X` anywhere, token chars `[A-Za-z0-9_.@:/+-]`). Bias is toward "used"; keep the shortcut comment from the plan's Decisions.
- [ ] **Step 4: Run, expect PASS.** Same command.
- [ ] **Step 5: Commit** `git add internal/usage/shellparse && git commit -m "feat: shell command attribution"`

---

### Task 7: Claude Code session-history reader

**Files:**
- Create: `internal/usage/usage.go`, `internal/agent/claude/reader.go`
- Test: `internal/agent/claude/reader_test.go`; fixtures built by a test helper writing JSONL into `t.TempDir()` (synthetic records only)

**Interfaces:**
- Consumes: `shellparse.Parse`, `shellparse.Invocation`.
- Produces:
  ```go
  package usage
  type Call struct{ At time.Time; shellparse.Invocation }
  type MCPCall struct{ At time.Time; Server, Tool string }
  type Usage struct {
    Agent string; Since, HistoryStart time.Time // HistoryStart zero when no history
    Shell []Call; MCP []MCPCall
  }
  func (u Usage) HistoryDays(now time.Time) int          // whole days from HistoryStart to now; 0 if none
  func (u Usage) Calls(tool string) []Call
  ```
  ```go
  package claude // internal/agent/claude; wrapped by the Agent in Task 8
  func readUsage(ctx context.Context, configDir string, since, now time.Time) (usage.Usage, error) // configDir already resolved (CLAUDE_CONFIG_DIR or ~/.claude)
  ```
  There is no usage-reader interface: the per-agent extension point is `agent.Agent` (Task 8).

- [ ] **Step 1: Confirm the format.** Re-check current Claude Code documentation for the session file location and the `tool_use` record shape listed under Facts; adjust the test helper's record shape if it differs. Also confirm `cleanupPeriodDays` semantics.

- [ ] **Step 2: Write the failing tests**

```go
func TestReadShellAndMCPAcrossProjects(t *testing.T) { // two project dirs, one session each, plus <session>/subagents/x.jsonl
  // records: Bash "aws s3 ls --profile prod" at T1 (in window), Bash "git status" (dropped), mcp__fs__read_file at T2
  // => Shell has 1 Call{Tool aws,Target prod,At T1}; MCP has {Server "fs", Tool "read_file"}; subagent file is included
}
func TestReadWindowAndBoundary(t *testing.T) { // call exactly at since is included; 1ns before is excluded; timestamp in the future (> now+24h) is ignored
}
func TestReadDeduplicatesToolUseIDs(t *testing.T) { // Review Focus 2: same tool_use id in two records of one file and in a second file => counted once
}
func TestReadSurvivesBadLines(t *testing.T) { // Review Focus 2: a 5 MiB line, a non-JSON line, a truncated last line, an empty line => other records still read, nil error
}
func TestReadHistoryStart(t *testing.T) { // oldest file's first timestamp is 10 days ago, window 30d => HistoryStart ~10 days ago, HistoryDays(now)==10
  // a file older than the window (mtime before since) is not fully parsed but still sets HistoryStart from its first timestamped record
}
func TestReadMissingOrEmptyDir(t *testing.T) { // Review Focus 1: configDir absent, projects/ absent, projects/ empty, unreadable project dir => Usage with zero HistoryStart, nil error
}
func TestReadNeverRetainsCommandText(t *testing.T) { // Bash command containing CANARY-SECRET-DO-NOT-PRINT plus "aws s3 ls" => fmt.Sprintf("%+v", usage) lacks the canary
}
```
- [ ] **Step 3: Run, expect FAIL.** `go test ./internal/agent/claude/ -run TestRead -v`
- [ ] **Step 4: Implement `readUsage`.** Walk `<configDir>/projects` for `*.jsonl` (recursive, so `subagents/` is included). Read with `bufio.Reader.ReadBytes('\n')` (no line-length limit); skip any line not containing `"tool_use"` before decoding; decode into a minimal struct (`type`, `timestamp`, `message.content[]` with `type`, `id`, `name`, `input.command` only). Files whose mtime is before `since` are only probed for their first timestamp (first 50 lines). Check `ctx.Err()` between files and return it. A `Bash` command is passed to `shellparse.Parse` and only the result is stored; `mcp__<server>__<tool>` names split on the first `__` pair after the `mcp__` prefix.
- [ ] **Step 5: Run, expect PASS.** `go test ./internal/agent/claude/ -run TestRead -v && go vet ./...`
- [ ] **Step 6: Commit** `git add internal/usage internal/agent && git commit -m "feat: claude code session-history reader"`

---

### Task 8: Agent interface and the Claude Code agent (permissions + usage)

**Files:**
- Create: `internal/agent/agent.go`, `internal/agent/claude/settings.go`, `internal/agent/claude/agent.go`
- Test: `internal/agent/claude/settings_test.go`, `internal/agent/claude/agent_test.go`

**Interfaces:**
- Consumes: `model.Credential`, `model.AgentAccess`, `model.AgentState` (Task 2); `usage.Usage` and `readUsage` (Task 7).
- Produces:
  ```go
  package agent // internal/agent/agent.go: the single extension point for coding agents; Codex later is one new package implementing it
  type Agent interface {
    Name() string                                                             // "claude-code"
    ReadUsage(ctx context.Context, since, now time.Time) (usage.Usage, error) // every project on the machine; Usage.Agent == Name()
    Classify(c model.Credential) model.AgentState                             // Agent == Name(); Access is about the tool only; FileBlocked is separate
    BlockAdvice(tool string) string                                           // agent-specific text for blocking a tool; excludes the advisory sentence (the rules engine adds it)
    Posture() Posture
  }
  type Posture struct{ UnrestrictedShell bool; Notes []string }               // Notes: unreadable or invalid settings files (path only, never contents)

  package claude // internal/agent/claude
  type Settings struct{ Allow, Ask, Deny []string; DefaultMode string; Sources []string; Notes []string }
  func Load(configDir, projectDir string, managed []string) Settings // user, user local, project, project local, managed; never errors
  func ManagedPaths(goos string) []string                            // darwin and linux paths from Facts
  // access reflects the tool only (rules for Bash(<tool>...)); fileBlocked is true when a Read deny covers any of c.Files. Neither affects the other.
  func (s Settings) Classify(c model.Credential, home string) (access model.AgentAccess, fileBlocked bool)
  func (s Settings) UnrestrictedShell() bool
  func New(configDir, projectDir, home, goos string) agent.Agent    // Name "claude-code"; compile-time assertion var _ agent.Agent = (*claudeAgent)(nil)
  ```

- [ ] **Step 1: Confirm the format.** Check current Claude Code settings documentation for locations, the three rule lists, rule grammar, `defaultMode` values, and precedence (assumed deny, ask, allow). Adjust the table below if the docs differ.

- [ ] **Step 2: Write the failing tests**

```go
func TestLoadMergesSources(t *testing.T) { // user allow ["Bash(aws:*)"], project deny ["Bash(gh:*)"], managed deny ["Read(~/.aws/**)"] => all present in Settings, Sources lists the three
  // a settings file with env {"X":"CANARY-SECRET-DO-NOT-PRINT"} and hooks => canary absent from fmt.Sprintf("%+v", s) (only "permissions" is decoded)
}
func TestLoadTolerantOfBadFiles(t *testing.T) { // Review Focus 1: missing, empty, invalid JSON, permissions of wrong type, directory in place of file => no panic; invalid ones add a Note naming the file path only
}
func TestClassifyTool(t *testing.T) { // table for credential Tool "aws" (home /h, no files); mode "default" unless stated
  // no rules => asks
  // allow ["Bash(aws:*)"] => allowed; ["Bash(aws *)"] => allowed; ["Bash(aws)"] => allowed; ["Bash"] => allowed; ["Bash(*)"] => allowed
  // allow ["Bash(aws s3 ls:*)"] => asks (partial rules ignored); allow ["Bash(awscli:*)"] => asks
  // ask ["Bash(aws:*)"] + allow ["Bash(aws:*)"] => asks (ask beats allow); deny ["Bash(aws:*)"] + allow ["Bash"] => denied; deny ["Bash"] => denied
  // DefaultMode "bypassPermissions" => allowed unless denied; "acceptEdits" and "plan" => asks
}
func TestClassifyCredentialFileDeny(t *testing.T) { // credential Files ["/h/.aws/credentials"]; spec correction: file deny never means denied
  // deny ["Read(~/.aws/**)"] only => (asks, true); with allow ["Bash(aws:*)"] => (allowed, true); ["Read(/h/.aws/credentials)"] => (asks, true); ["Read(~/.aws/config)"] => (asks, false); ["Read(~/.ssh/**)"] => (asks, false)
  // deny ["Read(~/.aws/**)"] + deny ["Bash(aws:*)"] => (denied, true)
  // credential with no Files (env) and only a Read deny => (asks, false)
}
func TestUnrestrictedShell(t *testing.T) { // allow ["Bash"] or ["Bash(*)"] => true; bypassPermissions => true; deny ["Bash"] with allow ["Bash"] => false; allow ["Bash(aws:*)"] => false
}
func TestAgentName(t *testing.T) { // New(...).Name() == "claude-code"
}
func TestAgentClassifyStampsAgentName(t *testing.T) { // Classify(cred) returns AgentState{Agent:"claude-code", Access, FileBlocked} matching Settings.Classify for the same input
}
func TestAgentReadUsageUsesConfigDir(t *testing.T) { // temp configDir with one synthetic session => ReadUsage returns Usage with Agent "claude-code" and the one Call; a missing configDir => zero Usage, nil error
}
func TestAgentBlockAdvice(t *testing.T) { // BlockAdvice("aws") == `Block the agent: add "Bash(aws:*)" to permissions.deny in ~/.claude/settings.json`; BlockAdvice("gh") uses "Bash(gh:*)"
}
func TestAgentPosture(t *testing.T) { // allow ["Bash"] => Posture.UnrestrictedShell true; an invalid settings file => Posture.Notes has one entry naming the path, not its contents
}
```
- [ ] **Step 3: Run, expect FAIL.** `go test ./internal/agent/... -v`
- [ ] **Step 4: Implement.** Decode only `permissions.{allow,ask,deny,defaultMode}`. A rule applies to tool `T` when the tool part is `Bash` and the specifier is empty, `*`, `T`, `T *`, `T:*`; file rules are `Read(...)` with `~` expanded against `home`, matching exact path or a directory prefix when the pattern ends with `/**` or `/*`. Tool access order (file rules never enter it): any deny match gives denied; any ask match gives asks; any allow match or `bypassPermissions` gives allowed; else asks. `claudeAgent` holds a loaded `Settings` and wraps `readUsage`.
- [ ] **Step 5: Run, expect PASS.** Same command; `go vet ./...`.
- [ ] **Step 6: Commit** `git add internal/agent && git commit -m "feat: agent interface and claude code agent"`

---

### Task 9: Developer use from shell history

**Files:**
- Create: `internal/devuse/devuse.go`
- Test: `internal/devuse/devuse_test.go`

**Interfaces:**
- Consumes: `shellparse.Parse`.
- Produces:
  ```go
  package devuse
  type Use struct{ Last time.Time; Dated bool; Count int } // Dated false when no entry had a timestamp
  type History struct{ ... }
  func Read(home string, getenv func(string) string) History     // zsh: $HISTFILE-less defaults ~/.zsh_history (or $ZDOTDIR/.zsh_history), bash: ~/.bash_history
  func (h History) Lookup(tool, target string) (Use, bool)       // target "" matches only un-named use
  ```

- [ ] **Step 1: Write the failing tests**

```go
func TestReadZshExtendedFormat(t *testing.T) { // ": 1700000000:0;aws s3 ls --profile prod" => Lookup("aws","prod") Dated, Last==unix 1700000000, Count 1
  // multi-line zsh entries (trailing backslash) and metafied bytes do not break the next entry
}
func TestReadBashWithAndWithoutTimestamps(t *testing.T) { // "#1700000000\naws s3 ls" => Dated; plain "aws s3 ls" lines => Use found, Dated false
}
func TestLookupPicksLatest(t *testing.T) { // two entries for the same key => Last is the later, Count 2
}
func TestReadMissingAndHuge(t *testing.T) { // Review Focus 1: no history files => empty History, no panic; 10 MiB single line is skipped; invalid UTF-8 ok
}
func TestReadRetainsNoCommandText(t *testing.T) { // history line "export AWS_SECRET_ACCESS_KEY=CANARY-SECRET-DO-NOT-PRINT; aws s3 ls" => canary absent from fmt.Sprintf("%+v", h)
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/devuse/ -v`
- [ ] **Step 3: Implement** `Read` and `Lookup`, keyed by `tool + "\x00" + target`; each history line passes through `shellparse.Parse` and is then discarded.
- [ ] **Step 4: Run, expect PASS.** Same command.
- [ ] **Step 5: Commit** `git add internal/devuse && git commit -m "feat: developer use from shell history"`

---

### Task 10: Rules (generic engine plus per-tool files)

**Files:**
- Create: `internal/rules/rules.go` (types, engine), `internal/rules/usage.go` (agentUse), `internal/rules/agent.go` (per-agent posture finding), `internal/rules/aws.go`, `internal/rules/gh.go` (one `ToolRule` per tool)
- Test: `internal/rules/rules_test.go` (engine, with a fake `ToolRule`), `internal/rules/aws_test.go`, `internal/rules/gh_test.go`

**Interfaces:**
- Consumes: `model.*` (Task 2), `usage.Usage`/`usage.Call` (Task 7), `devuse.History` (Task 9), `shellparse.Invocation` (Task 6).
- Produces:
  ```go
  package rules
  type Context struct { Agent string; Now time.Time; Window time.Duration; Offline bool; Dev devuse.History; Getenv func(string) string; HistoryDays int }
  type AgentInput struct { Name string; Usage usage.Usage; UnrestrictedShell bool; BlockAdvice func(tool string) string } // built by the pipeline from agent.Agent
  type UseState int // UseUsed, UseRare, UseUnused, UseUnknown (history shorter than window), UseUnattributable
  type AgentUse struct{ Count int; Last time.Time; State UseState; HistoryDays int }
  type Risk struct { Rule string; Severity model.Severity; Headline string; Details, Advice []string }
  type DevState int // DevKnownRecent, DevNobody, DevUnknown
  type DevUse struct { State DevState; Why string }
  type ToolRule interface {                      // one per tool; a new tool adds a file implementing this plus one registry line
    Tool() string                                // matches Credential.Tool and Scanner.Name()
    Attribute(c model.Credential, calls []usage.Call, x Context) (own []usage.Call, unattributed int)
    Risks(c model.Credential, st model.AgentState, use AgentUse, x Context) []Risk   // not called when st.Access == "denied"
    DeveloperUse(c model.Credential, use AgentUse, x Context) DevUse
    Revoke(c model.Credential, x Context) string // provider-side revoke advice, or "" when the tool has none
  }
  type Input struct { Creds []model.Credential; Agents []AgentInput; Dev devuse.History; Getenv func(string) string; Now time.Time; Window time.Duration; Offline bool }
  func Evaluate(in Input, tools []ToolRule) []model.Finding // sorted by Severity desc, then ID asc; the list is supplied by the caller (registry)
  func agentUse(u usage.Usage, calls []usage.Call, unattributed int, window time.Duration, now time.Time) AgentUse
  type AWSRule struct{}; type GHRule struct{}                // implement ToolRule; listed in registry (Task 12)
  ```
  Engine, per (agent, credential) with no branching on tool names: find the `ToolRule` by `c.Tool` (none: an OK finding saying no rules exist for the tool); find the agent's `AgentState` in `c.Access` (absent: treated as asks). If denied: an OK finding "denied by agent settings", no risks. Otherwise: `Attribute` over `a.Usage.Calls(c.Tool)`, `agentUse`, `Risks`; usage severity unused MED, rare LOW, unknown and unattributable add detail lines only (no claim of "unused"). Severity is the maximum of risks and usage; with none, OK "used N times". Advice, when use is unused or rare: if `DeveloperUse` is `DevNobody` and use is unused and `Revoke` is non-empty, advice is the revoke text only; if `DevKnownRecent`, `a.BlockAdvice(c.Tool)` only; otherwise `BlockAdvice` plus the line `If you do not use it either, revoke the credential.`. Any finding carrying block advice also gets `Agent deny rules are advisory unless the agent runs in a sandbox.` once. Details include "Agent use, last N days: ..." and, when state is asks, "Agent asks first before running it", and, when `FileBlocked` and not denied, "credential file blocked, tool still allowed". Finding ID `<agent>:<tool>:<credential ID>`. `agent.go` adds `<agent>:shell` MED rule `agent.unrestricted-shell` when `AgentInput.UnrestrictedShell`.
  `AWSRule.Attribute`: profile `P` takes `Target == P` plus `Target == ""` when `P == "default"`; `environment` and `chain` take `Target == ""`. `GHRule.Attribute`: host `H` takes `Target == H`, plus `Target == ""` when `H` equals `x.Getenv("GH_HOST")` (or `github.com` when unset).

- [ ] **Step 1: Write the failing tests** (Review Focus 5 for gh; spec values in comments)

```go
// engine, fake ToolRule that returns scripted Risks / DevUse
func TestAgentUseStates(t *testing.T) { // window 30d, now fixed
  // 0 calls, history 45 days => UseUnused; 2 calls, history 45 => UseRare; 3 calls => UseUsed
  // 0 calls, history 10 days => UseUnknown with HistoryDays 10 ; 2 calls, history 10 => UseUnknown (count reported)
  // no history at all (HistoryStart zero) => UseUnknown with HistoryDays 0
  // 0 own calls and unattributed 4 => UseUnattributable
}
func TestEngineDeniedIsOKAndSkipsRisks(t *testing.T) { // AgentState denied => OK finding, ToolRule.Risks never called
}
func TestEngineFileBlockedStillRisky(t *testing.T) { // FileBlocked true, Access allowed, scripted HIGH risk => SevHigh and Details contain "credential file blocked, tool still allowed"
  // FileBlocked true with Access denied => OK finding, risks not evaluated
}
func TestEngineAsksFirstShownNotDowngraded(t *testing.T) { // Access asks, scripted HIGH risk => SevHigh, Details contain "asks first"
}
func TestEngineAdviceBranches(t *testing.T) { // use unused, 45 days history
  // DevKnownRecent => Advice [BlockAdvice(tool), advisory sentence], no revoke, no reminder
  // DevNobody + Revoke non-empty => Advice [revoke text] only (and no block line)
  // DevNobody but use Rare => BlockAdvice + reminder (no revoke)
  // DevNobody but Revoke == "" => BlockAdvice + reminder
  // DevUnknown => BlockAdvice + "If you do not use it either, revoke the credential." + advisory sentence
  // finding with block advice always contains "advisory" once; revoke-only finding does not
}
func TestEngineUsageSeverity(t *testing.T) { // no risks: unused => SevMed, rare => SevLow, used (>=3) => SevOK "used N times"; short history => detail line "N days of history available", SevOK
}
func TestEngineNoRuleForTool(t *testing.T) { // credential Tool "zzz" with no registered ToolRule => OK finding, no panic
}
func TestEngineOneFindingPerAgentAndCredential(t *testing.T) { // two AgentInputs and two credentials => four findings with IDs "<agent>:<tool>:<id>"
}
func TestUnrestrictedShellFinding(t *testing.T) { // AgentInput.UnrestrictedShell true => finding ID "claude-code:shell", SevMed, Rules "agent.unrestricted-shell"; false => none
}
func TestEvaluateOrderingAndEmpty(t *testing.T) { // HIGH before MED before LOW before OK, ties by ID; no credentials => empty non-nil slice
}
// AWS rule
func TestAWSAdminHigh(t *testing.T) { // online, Resolved.Admin => Risks has Rule "aws.admin" SevHigh; not admin or offline => none
}
func TestAWSLongLivedKeyMed(t *testing.T) { // LongLived => Rule "aws.long-lived-key" SevMed; temporary key => none
}
func TestAWSAttribution(t *testing.T) { // call Target "" counts for "default", "environment" and "chain", not for "prod"; Target "prod" counts only for "prod"
}
func TestAWSDeveloperUse(t *testing.T) { // credential "prod", use unused, 45 days history; undated shell history is unknown (spec)
  // dev history dated within the window => DevKnownRecent
  // KeyChecked && KeyLastUsed nil => DevNobody; Revoke text mentions the masked key id and "update-access-key --status Inactive", never the full id
  // KeyLastUsed within window while agent unused => DevKnownRecent (developer use proven by provider data)
  // KeyChecked false (offline) and no dev data => DevUnknown
  // dev history undated only => DevUnknown, never DevKnownRecent
  // agent used 5 times and KeyLastUsed nil => not DevNobody (contradiction ignored)
}
// GH rule
func TestGHUnusedScopes(t *testing.T) { // Resolved scopes [repo workflow admin:org], readable; agent calls: gh pr x3 => Risk "gh.unused-scopes" SevMed, Details "Scopes: repo, workflow, admin:org", "Agent's commands needed: repo", unused [workflow admin:org]
  // gh run => needs workflow; gh issue/repo/release/pr => repo; gh gist => gist; gh org => read:org; admin:org covers read:org and write:org; repo covers repo:status
}
func TestGHApiCallsSuppressScopeFinding(t *testing.T) { // Review Focus 5: any "gh api" call => no gh.unused-scopes, Details say scope need cannot be attributed
}
func TestGHFineGrainedUnreadable(t *testing.T) { // ScopesReadable false online => Details "permissions cannot be read", no scope rule
}
func TestGHAttributionDefaultHost(t *testing.T) { // Getenv GH_HOST unset: Target "" counts for github.com only; GH_HOST=ghe.example.com: Target "" counts for ghe.example.com
}
func TestGHAdviceAndRevokeNone(t *testing.T) { // Revoke("") for gh is ""; scope advice links https://github.com/settings/tokens, and https://ghe.example.com/settings/tokens for that host
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/rules/ -v`
- [ ] **Step 3: Implement** the files above. Severity per the Decisions section. Revoke text for AWS: `Nobody used this key in the last <N> days according to AWS. Revoke it at AWS (IAM console, or "aws iam update-access-key --status Inactive") for key <masked>.` No text names `agentctl fix`.
- [ ] **Step 4: Run, expect PASS.** `go test ./internal/rules/ -v && go vet ./...`
- [ ] **Step 5: Commit** `git add internal/rules && git commit -m "feat: rules engine with aws and gh tool rules"`

---

### Task 11: Online confirmation prompt

**Files:**
- Create: `internal/confirm/confirm.go`
- Test: `internal/confirm/confirm_test.go`

**Interfaces:**
- Produces:
  ```go
  package confirm
  var ErrNoTerminal = errors.New("no terminal to ask on")
  // Online decides whether network access is allowed. providers are display names ("AWS","GitHub").
  func Online(in io.Reader, prompt io.Writer, inIsTTY, offline, yes bool, providers []string) (bool, error)
  ```
  Rules: `offline` returns `(false, nil)` and prints nothing; no providers returns `(false, nil)` and prints nothing; `yes` prints the provider notice (first two lines only) and returns `(true, nil)`; no TTY without either flag returns `(false, ErrNoTerminal)` and prints nothing to the provider; otherwise prints the full prompt and reads one line, `y`/`yes` (any case) gives true, anything else (including EOF) false.

- [ ] **Step 1: Write the failing tests**

```go
func TestPromptText(t *testing.T) { // providers ["AWS","GitHub"], TTY, input "y\n" => prompt output equals exactly:
  // "About to ask AWS and GitHub what your credentials can do.\nRead-only, but the requests appear in their audit logs.\nContinue? [y/N] (--yes to skip this question, --offline to stay local) "
  // single provider ["AWS"] => "About to ask AWS what your credentials can do."; three => "AWS, GitHub and Foo"
}
func TestAnswers(t *testing.T) { // "y","Y","yes","YES" => true; "","n","no","maybe", EOF => false; both without error
}
func TestNoTerminalWithoutFlags(t *testing.T) { // inIsTTY false, yes false, offline false, providers non-empty => (false, ErrNoTerminal)
}
func TestYesPrintsNoticeAndSkipsQuestion(t *testing.T) { // yes, no TTY => true; output has the two notice lines and not "Continue?"
}
func TestOfflineBeatsYes(t *testing.T) { // offline && yes => (false, nil), nothing printed
}
func TestNoProvidersNeverPrompts(t *testing.T) { // providers empty, TTY => (false, nil), no output, reader untouched
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/confirm/ -v`
- [ ] **Step 3: Implement** `Online` as specified; the exact prompt text is the spec's wording above.
- [ ] **Step 4: Run, expect PASS.** Same command.
- [ ] **Step 5: Commit** `git add internal/confirm && git commit -m "feat: online confirmation prompt"`

---

### Task 12: Registry, pipeline, rendering, and command wiring

**Files:**
- Create: `internal/registry/registry.go`, `internal/run/run.go`, `internal/render/text.go`, `internal/render/json.go`
- Modify: `internal/cli/exec.go` (replace the Task 1 stub `defaultExec` with the real wiring: build `scan.Env`, `registry.*`, `run.Deps`, call `run.Execute`)
- Test: `internal/registry/registry_test.go`, `internal/run/run_test.go`, `internal/run/extension_test.go`, `internal/render/render_test.go`, golden files `internal/render/testdata/{doctor,inventory}-{plain,tty}.golden` and `*.json.golden`

**Interfaces:**
- Consumes: everything above. `cli.IO`, `cli.Exec` (Task 1); `run.Options` (Task 1).
- Produces:
  ```go
  package registry // the ONLY file listing scanners, tool rules, and agents; adding a tool or agent is a new package/file plus one line here
  func Scanners(r scan.Runner) []scan.Scanner       // aws.New(aws.NewSDK()), gh.New(r)
  func ToolRules() []rules.ToolRule                 // rules.AWSRule{}, rules.GHRule{}
  type AgentParams struct{ Getenv func(string) string; Home, Cwd, GOOS string }
  func Agents(p AgentParams) []agent.Agent          // claude.New(configDir, p.Cwd, p.Home, p.GOOS) with configDir = CLAUDE_CONFIG_DIR else <Home>/.claude

  package run
  type Deps struct {
    Scanners []scan.Scanner; Agents []agent.Agent; Rules []rules.ToolRule
    Dev func() devuse.History // lazily read, doctor only
    Env scan.Env; Now func() time.Time
    Confirm func(providers []string) (bool, error) // injectable online confirmation; cli builds it from confirm.Online (Task 11) over IO.In/IO.Err; a non-terminal caller supplies its own answer; may return confirm.ErrNoTerminal
    Out, Err io.Writer; OutIsTTY bool              // used by Execute only; Collect never touches them
  }
  // Collect gathers everything and returns it as data: no printing, no writers, no exit status. Any UI or program calls this.
  func Collect(ctx context.Context, o Options, d Deps) (render.Report, error) // errors: confirm.ErrNoTerminal (returned as is), ctx.Err(), a ReadUsage error
  // Execute is a thin wrapper: Collect, render (Text or JSON per o.JSON), map to a status.
  func Execute(ctx context.Context, o Options, d Deps) int

  package render
  type Report struct {
    SchemaVersion int; GeneratedAt time.Time; Command string; Offline bool; WindowDays, HistoryDays int
    Agents []string; Credentials []model.Credential; Findings []model.Finding; Notes []string
  }
  func Text(w io.Writer, r Report, style Style) error // Style{Color, Fancy bool}; plain when both false
  func JSON(w io.Writer, r Report) error              // SchemaVersion 1; snake_case keys via render-local DTO structs; no nil arrays (use [])
  ```
  Pipeline order (no branching on tool or agent names; everything iterates the three lists): `Discover` on every scanner, setting `Credential.Provider = Scanner.Provider()`; collect the distinct providers in order; unless `o.Offline` or there are no providers, call `d.Confirm(providers)` (answer false means continue offline and add a note that online checks were declined; an error aborts `Collect`); if allowed, `Resolve` each credential through the scanner whose `Name()` equals `Credential.Tool`, sequentially under a 20 s `context.WithTimeout` (a `*scan.SkipError` or any error becomes a note on that credential, never a failed run); for every agent, `Classify` every credential and append the `AgentState` to `Credential.Access`; for `doctor` only, `ReadUsage` for every agent over the window, read `Dev()`, build `rules.AgentInput` from each agent (`Posture().UnrestrictedShell`, `BlockAdvice`), call `rules.Evaluate(in, d.Rules)`; add every `Posture().Notes` entry and every per-credential note to `Report.Notes`, then return the `Report`. That is the end of `Collect`; it prints nothing. `Execute` then renders and returns 0, or for `doctor` 1 when `Report.Findings` holds any HIGH finding, and 2 when `Collect` returns an error (for `confirm.ErrNoTerminal` the message on Err names `--yes` and `--offline`; for cancellation or other errors a one-line message), or on a render error. Notes appear in the text report and in the JSON `notes` field; Err carries only the prompt and error messages. `cli.Run` already owns the signal context (Task 1).
  Text output: spec layout for `doctor` (severity word, subject, detail lines, advice lines, ending with the advisory note and the launch-flag note). `inventory` groups credentials by `Credential.Provider` and shows kind, identity, whatever `Resolved` holds (admin text if set, scopes if readable, "permissions cannot be read" when the scope list is unreadable, key last used), one access line per `AgentState` (denied / asks first / allowed without asking, plus the label "credential file blocked, tool still allowed" when `FileBlocked` and not denied), and `EnvVars` names. The renderers read struct fields only and never compare `Tool`, `Provider`, or agent names to literals. Fancy style uses the spec's `·` and `→`; plain uses `-` and `->`; colour only when `OutIsTTY`, `NO_COLOR` unset, `TERM != "dumb"`. Every name and identity string goes through `model.Sanitize` in the text renderer.

- [ ] **Step 1: Write the failing tests**

```go
// registry
func TestRegistryEveryScannerHasToolRule(t *testing.T) { // set of Scanners(...) Name() == set of ToolRules() Tool(); names unique
}
func TestRegistryAgents(t *testing.T) { // Agents(params) has exactly one entry, Name "claude-code"; CLAUDE_CONFIG_DIR in Getenv changes its config dir (observable through a synthetic session there)
}
// pipeline
func TestExecuteOfflineNeverResolves(t *testing.T) { // fake scanner whose Resolve calls t.Fatal; Offline true => returns 0
}
func TestCollectReturnsReportAsData(t *testing.T) { // calls run.Collect directly with fake scanner, fake ToolRule, fake agent and a fake Confirm returning (true, nil); no writer exists anywhere in the call
  // asserts on the returned Report: Command "doctor", Offline false, Credentials[0].Resolved set, Credentials[0].Access[0].Agent == "fake-agent", Findings[0].ID == "fake-agent:fake:<id>", Findings[0].Severity == model.SevMed, Agents == ["fake-agent"], SchemaVersion == 1; the fake Confirm saw providers ["Fakery"] before any Resolve call
  // a second call with Confirm returning (false, nil) => Report.Offline true, no Resolve call, Notes mention the declined online checks; Confirm returning confirm.ErrNoTerminal => error is confirm.ErrNoTerminal and the Report is zero
}
func TestExecuteDeclineContinuesOffline(t *testing.T) { // Confirm returns (false, nil) => Resolve never called; Report.Offline true; output contains a note that online checks were declined; exit 0
}
func TestExecuteNoTerminalExit2(t *testing.T) { // Confirm returns confirm.ErrNoTerminal, creds exist => exit 2; Err mentions "--yes" and "--offline"; Out empty; Resolve never called
}
func TestExecuteConfirmCalledBeforeResolve(t *testing.T) { // fake Confirm records the providers it was given (["AWS","GitHub"]) and returns (true, nil); fake records that Confirm ran before any Resolve call
  // the real prompt text and --yes behaviour are tested in Task 11 and through cli in Task 13
}
func TestExecuteNoCredentialsSkipsPrompt(t *testing.T) { // Review Focus 1: scanners return nothing => exit 0, output says nothing was found, Confirm never called
}
func TestExecuteProviderFailureDegrades(t *testing.T) { // Resolve returns error for one credential, SkipError for another, ok for a third => exit 0; first two carry Notes; third Resolved set
}
func TestExecuteDoctorExitCodes(t *testing.T) { // credentials producing a HIGH finding => 1; only MED => 0; ReadUsage error => 2
}
func TestExecuteFileBlockedStillRisky(t *testing.T) { // fake agent classifies AgentState{Access:"allowed", FileBlocked:true} for an admin credential => HIGH finding present, text shows "credential file blocked, tool still allowed", doctor exit 1
}
func TestExecuteInventoryDoesNotReadUsage(t *testing.T) { // fake agent whose ReadUsage t.Fatal()s; command "inventory" => exit 0
}
func TestExecuteCancelledContextExit2(t *testing.T) { // ctx cancelled before Resolve => 2
}
func TestExecuteSinceWindowPassed(t *testing.T) { // Since 7d => fake agent's ReadUsage receives since == now-7d
}
func TestExecuteMultipleAgentsAppendStates(t *testing.T) { // two fake agents => each credential has two AgentState entries in agent order
}
// extension: the owner's requirement that new tools and agents need no changes elsewhere (internal/run/extension_test.go)
func TestFakeToolAndAgentFlowThroughPipelineAndRenderers(t *testing.T) {
  // Deps{Scanners: [fakeScanner{Name "fake", Provider "Fakery"}], Rules: [fakeRule{Tool "fake", one MED Risk}], Agents: [fakeAgent{Name "fake-agent", Classify allowed, ReadUsage returns zero calls with 45 days history}]} defined in the test file only
  // doctor text: output contains "Fakery"/credential label, the MED risk headline, finding ID "fake-agent:fake:<id>" is in the JSON; exit 0
  // doctor --json: valid JSON, findings[0].agent == "fake-agent", findings[0].tool == "fake", credentials[0].agents[0].agent == "fake-agent"
  // inventory text and --json include the fake credential and its "fake-agent" access state
  // no file other than the test is touched; the non-test sources of internal/run and internal/render contain no double-quoted string literal equal to "aws", "gh", or "claude-code" (a test scans them with go/parser and fails on a match)
}
// rendering
func TestRenderGolden(t *testing.T) { // fixed Report with HIGH aws (offline and online variants), MED gh, OK denied credential, one credential with FileBlocked and tool allowed (label shown); compare to golden in plain and tty styles; -update flag regenerates
  // plain output contains no byte >0x7F and no ESC; tty contains "→"
}
func TestRenderSanitises(t *testing.T) { // Review Focus 3: Subject "pr\x1b[31mod‮" => text output has no ESC and no U+202E
}
func TestJSONValidAndStable(t *testing.T) { // output parses with json.Unmarshal; "schema_version":1; empty findings render as []; Resolution times are RFC 3339 UTC; offline credentials have "resolved": null; a name with \x1b round-trips as valid JSON string
}
func TestRenderEmptyHome(t *testing.T) { // Review Focus 1: no credentials => text says "No credentials found." and still prints the advisory note
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/registry/ ./internal/run/ ./internal/render/ -v`
- [ ] **Step 3: Implement the registry, `run.Collect`, `run.Execute`, `render.Text`, `render.JSON`** per the Interfaces block, then replace `defaultExec` in `internal/cli/exec.go`: it builds `run.Deps` from `registry.Scanners(scan.ExecRunner{})`, `registry.ToolRules()`, `registry.Agents(...)`, `devuse.Read` (wrapped lazily), the `scan.Env` from `cli.IO`, and calls `run.Execute`. It builds `Deps.Confirm` as `func(p []string) (bool, error) { return confirm.Online(io.In, io.Err, io.InIsTTY, o.Offline, o.Yes, p) }`. Stdout carries only the report; the prompt and error messages go to Err. `Collect` is the only function a future user interface needs to call; no UI code is added now.
- [ ] **Step 4: Run, expect PASS.** `go test ./... && go vet ./...`
- [ ] **Step 5: Smoke-run offline.** `go run ./cmd/agentctl doctor --offline --json | jq .schema_version` prints `1`; `go run ./cmd/agentctl inventory --offline` prints without error. Check the output for no secret values by eye (the real machine's files are read here, so do not paste the output anywhere).
- [ ] **Step 6: Commit** `git add internal cmd && git commit -m "feat: registry, pipeline and text/json rendering"`

---

### Task 13: Build, packaging, and end-to-end safety test

**Files:**
- Create: `scripts/build.sh`, `README.md`, `LICENSE` (canonical Apache-2.0 text), `internal/run/e2e_test.go`, `internal/cli/e2e_test.go`, `internal/run/testdata/home-canary/` (fixture home with canary values in `.aws/credentials`, a gh `hosts.yml`, a zsh history line, a Claude session record with a Bash command, and a `settings.json` `env` key)
- Modify: `go.mod` and every import (module path), `internal/cli/cli.go` (`Version`)

**Interfaces:**
- Consumes: `run.Execute`, `cli.Version`.
- Produces: `scripts/build.sh <version>` writes `dist/agentctl_<version>_<os>_<arch>.tar.gz` for `darwin`/`linux` x `amd64`/`arm64`, each archive containing `agentctl`, `LICENSE`, `README.md`, and `dist/SHA256SUMS`. The script runs `go mod verify` and `go build -mod=readonly` first, so the cobra, YAML, and AWS SDK dependencies resolve from `go.sum` only.

- [ ] **Step 1: Write the failing end-to-end test** (Review Focus 4)

```go
func TestE2ENoSecretReachesOutput(t *testing.T) {
  // build Deps over testdata/home-canary with real scanners' Discover, a fake gh Runner and fake aws API that return normal data and, in their errors, would echo nothing secret
  // run doctor and inventory in text, plain text, and --json, offline and --yes; capture Out and Err
  // assert none of: "CANARY-SECRET-DO-NOT-PRINT", the full fake access key id "AKIAIOSFODNN7EXAMPLE", the fake gh token string appears in Out or Err; masked "AKIA****MPLE" may appear
  // assert the doctor run with a HIGH fixture returns 1 and the same fixture offline returns 0
}
func TestE2EEmptyHome(t *testing.T) { // Review Focus 1: empty home, --offline => exit 0, Out non-empty, Err empty
}
// internal/cli/e2e_test.go: full cobra path with the real registry, IO.Home pointing at the fixture
func TestE2ECLIJSONStdoutIsOnlyJSON(t *testing.T) { // cli.Run(["doctor","--offline","--json"]) => Out parses as one JSON document and nothing else (no trailing text); Err has no usage text; same canary assertions as above
}
func TestE2ECLINoTerminalExit2(t *testing.T) { // cli.Run(["doctor"]) with InIsTTY false over the canary home (credentials present) => 2, Err names --yes and --offline, Out empty
}
```
- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/run/ -run E2E -v` (fixture missing). Then create the fixture and re-run; if it fails for a real leak, fix the leak in the owning package before continuing.

- [ ] **Step 3: Implement the build.** `scripts/build.sh`: `set -euo pipefail`; for each target `CGO_ENABLED=0 GOOS=... GOARCH=... go build -trimpath -ldflags "-s -w -X github.com/<module>/internal/cli.Version=$1" -o dist/<dir>/agentctl ./cmd/agentctl`; tar.gz with `LICENSE` and `README.md`; `shasum -a 256 dist/*.tar.gz > dist/SHA256SUMS`. README covers install (`go install` and archive + checksum), what it reads (names only, never values), what it contacts and when (the prompt, `--offline`, `--yes`), exit statuses, plain output, running on servers, that deny rules are advisory, that launch flags are not detected, and `agentctl fix` is not available yet.

- [ ] **Step 4: Set the real module path.** Obtain the owner's GitHub path (question in the hand-off); run `go mod edit -module <path>` and rewrite imports with `grep -rl 'github.com/OWNER/agentctl' . | xargs sed -i '' 's#github.com/OWNER/agentctl#<path>#g'` (macOS sed), then `gofmt -l .` and `go build ./...`. Update the `-X` flag path in `scripts/build.sh`.

- [ ] **Step 5: Verify the build.** Run `go mod tidy && git diff --exit-code go.mod go.sum && go test ./... && go vet ./... && scripts/build.sh 0.1.0`. Expect four archives plus `SHA256SUMS` in `dist/`. `file dist/*/agentctl` shows Mach-O for darwin and `ELF ... statically linked` for linux. Run the darwin binary native: `dist/agentctl_0.1.0_darwin_arm64/agentctl --version` prints `agentctl 0.1.0`. On a Linux machine or container (manual, see below) run the linux binary.

- [ ] **Step 6: Commit** `git add -A && git commit -m "feat: build script, readme, license and end-to-end safety test"`

---

## Self-Review

1. **Spec coverage.** Commands and flags: Tasks 1, 12. Prompt, no-terminal, exit statuses: 11, 12, and the cobra contract tests in 1. AWS files, env, chain, last-used, admin: 3, 4. gh hosts and scopes: 5. Usage reader (shell and MCP, all projects, history days): 6, 7. Permission settings and three states, with file-blocked as a separate flag: 8. Developer-use detection (undated history is unknown): 9, 10. Rules for aws, gh, and agent configuration; unused/rare/short-history; default-profile attribution; two-level removal: 10. Text, JSON, plain output: 12. Static builds: 13. Safety requirements: read-only guard tests (4, 5), timeouts and non-interactive skips (4, 12), degrade on failure (12). Anti-goals: canary tests (5, 13), advisory text (10, 12). Extension requirements: one `Agent` interface (8), one registry file (12), `ToolRule` per tool file (10), one cobra file per subcommand with shared flags (1), and the fake-tool/fake-agent test plus the no-literal-names grep (12). Deliberately not planned (out of scope): MCP-never-called rule, docker, kubectl, `fix`, Codex, nono.
2. **Step scan.** Each step names a signature, a test, or a command; no step says "handle edge cases"; edge cases are named in test lists.
3. **Type consistency.** Checked across Interfaces blocks: `model.Credential` has `Provider` and `Access []AgentState` (Task 2) and nothing refers to the removed single `Access`/`FileBlocked` fields on a credential; `Finding.Access/FileBlocked/Agent` are per (agent, credential). `claude.Settings.Classify` returns `(model.AgentAccess, bool)` (8) and `claudeAgent.Classify` wraps it into `model.AgentState` (8), consumed by `run.Execute` (12) and read by `rules` through `c.Access` (10). `agent.Agent` (8) is consumed by `registry.Agents` and `run.Deps.Agents` (12); `rules.AgentInput` is built from it in the pipeline. There is no `usage.Reader`; `readUsage` (7) is used by the Claude agent (8). `rules.ToolRule` and `rules.Evaluate(in, tools)` (10) match `registry.ToolRules()` and `run.Deps.Rules` (12). `run.Options` is defined once (Task 1) and used by `cli.Exec`, `run.Collect`, and `run.Execute`; `run.Collect` returns `render.Report`, which `run.Execute` passes to `render.Text`/`render.JSON`; `run.Deps.Confirm` is built in `cli/exec.go` from `confirm.Online` (Task 11). `scan.Scanner` (3) is implemented by aws (3-4) and gh (5). Finding ID form is `<agent>:<tool>:<id>` in Decisions, Task 10, and Task 12 tests.
4. **Review Focus.** Five lines, each mapped to named tests above; Task 5 now also pins that yaml error text never reaches output.
5. **Proportion.** Signatures, test names and assertions only; no function bodies. The plan grew with the extension work (interfaces and the registry); the code it describes grew by the same files.

## Done when

### Automated
- `go test ./... && go vet ./... && gofmt -l .` prints no failures and no files.
- `scripts/build.sh 0.1.0` produces four `.tar.gz` archives and `SHA256SUMS` in `dist/`; `file` reports static ELF for both Linux archives.
- `go run ./cmd/agentctl doctor --offline --json | jq -e '.schema_version == 1'` succeeds.
- `go run ./cmd/agentctl doctor </dev/null` (no flags, credentials present) exits 2 and names `--yes` and `--offline`.
- `go run ./cmd/agentctl doctor --json --nope 2>/dev/null; echo $?` prints only `2` (nothing on stdout from cobra).
- `go test ./internal/run/ -run TestCollectReturnsReportAsData` passes (the report is available as data without any writer).
- `go test ./internal/run/ -run TestFakeToolAndAgentFlowThroughPipelineAndRenderers` passes with only the test file defining the fake tool and agent.

### Manual
- Run the linux/amd64 and linux/arm64 binaries on a Linux host or container: `--version`, `inventory --offline`, and on a host with an instance or container role, `doctor --yes` reports AWS without `~/.aws`.
- On a real laptop with an AWS profile and `gh` logged in, run `doctor` interactively: the prompt appears first, answering `n` stays offline, answering `y` resolves, and nothing secret is printed.
- Confirm in CloudTrail and the GitHub audit log that only read calls (`GetCallerIdentity`, `List*`, `Get*`, `GET /user`) were made.
- Open the installed binary's output in a terminal and over `ssh ... | cat`: coloured with symbols on the terminal, plain ASCII when piped.
- Owner decides, after trying it on real machines, whether to continue to item 2 of the spec.
