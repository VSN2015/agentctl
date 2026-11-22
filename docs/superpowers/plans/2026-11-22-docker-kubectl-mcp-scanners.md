# docker, kubectl and MCP scanners Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `agentctl inventory` and `agentctl doctor` report the Docker socket, kubectl contexts and Claude Code MCP servers, with their risk rules, using only local files and sockets.

**Architecture:** Each tool is one new `scan.Scanner` package, one new `rules.ToolRule` file and one line each in `internal/registry/registry.go`. All three are offline only: a new optional marker interface `scan.LocalOnly` tells the pipeline not to list them in the online prompt and not to call their `Resolve`. Shell attribution gains `docker` and `kubectl` in `shellparse`; MCP use reaches its rule through one new field on `rules.Context`; the Claude agent learns MCP deny-rule syntax. `internal/run` and `internal/render` stay free of tool names.

**Tech Stack:** Go stdlib (`net`, `os`, `encoding/json`, `regexp`); `go.yaml.in/yaml/v3` for kubeconfig (already in `go.mod`, used by the `gh` scanner). No new dependency.

**Spec:** `/Users/sang/Projects/individual-projects/agentctl/docs/superpowers/specs/2026-11-20-agentctl-design.md` (this plan implements item 2 of its "Order of work"). Style and conventions follow `docs/superpowers/plans/2026-11-20-agentctl-inventory-doctor.md`. Executors read the spec and this plan.

## Global Constraints

- Local only. No AI model, no telemetry, no update check. Docker, kubectl and MCP make no network call and add no provider prompt entry (`--offline` or not).
- Secret values are never read into output, logs, or errors. Kubeconfig `users` and `clusters` sections, MCP `env`, `headers`, `args`, `url` and `command`, and `DOCKER_HOST` URLs are never decoded into a result or an error message. Error text never echoes file content (yaml and json errors can quote it).
- Every provider call is read-only and has a timeout (none are added here).
- Nothing is written to disk by `inventory` or `doctor`.
- Unused: no agent use in the window. Rarely used: fewer than 3 agent uses in the window. If session history covers less than the window, say how many days of history were available instead of claiming "unused".
- `kubectl` with no context in the command cannot be attributed. If the agent never ran `kubectl` in the window, every context is unused. If it ran `kubectl` without naming a context, no context is called unused; the finding says "agent ran kubectl N times without naming a context" and the production-context risk finding still stands. When use cannot be attributed, `agentctl` says so and does not claim "unused".
- A kubectl context is treated as production when its name or cluster matches `prod`. Online Kubernetes permission resolution is out of v1. Kubernetes service-account tokens mounted inside a pod are reported as present; resolving what they can do is out of v1.
- Risk rules in v1 for these tools: Docker socket reachable; Kubernetes production context reachable; MCP server configured and never called.
- Reachability: reachable = exists on the machine and agent configuration does not deny the tool. States shown: denied, asks first, allowed without asking. Agent deny rules are advisory without a sandbox; the output says so (the engine already adds this).
- `doctor` exits 0 when there are no HIGH findings, 1 when there are, 2 on an error. With only local-only credentials present, no terminal and neither `--yes` nor `--offline`, the run must still succeed (no prompt is needed).
- `--json` carries `schema_version`: fields are added, never renamed or removed. This plan adds no JSON field.
- Extensibility: a tool is a new package plus one line in `internal/registry/registry.go`; `internal/run` and `internal/render` contain no per-tool literals (`TestSourcesHaveNoPerToolLiterals`).
- Out of scope: `fix`, Codex, online Kubernetes checks, gcloud/npm/ssh or any other tool, README changes beyond one line.
- Test hygiene (owner's safety hook, see memory `safety-hook-credential-paths`): no committed fixture files; every fixture is generated inside the test (`t.TempDir()`, or `os.MkdirTemp("", "ac")` for unix sockets because macOS limits socket paths to about 104 bytes). Nobody runs `agentctl`, `go run ./cmd/agentctl` or the built binary against the real home directory; smoke runs point `HOME` and every config-dir variable at an empty temp dir. Put both rules in every implementer brief.
- Commits: one per task, on branch `feat/docker-kubectl-mcp`, each ending with the trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (second `-m` argument).
- Standing verification after every task: `cd /Users/sang/Projects/individual-projects/agentctl && gofmt -l . && go vet ./... && go test ./... -count=1` prints no gofmt output and ends with every package `ok`.

## Review Focus

Failure modes the spec implies but its own text does not pin; each has a named test in the owning task.

1. A server or CI machine that has only a Docker socket, kubeconfig or MCP config (no AWS, no gh), run without a terminal and without `--yes`: expected to run and report, not exit 2 asking for `--yes`. Tests: Task 1 `TestLocalOnlyScannerNeverPromptsOrResolves`, Task 4 `TestE2ELocalOnlyNeedsNoPrompt`.
2. Odd or hostile config files (invalid YAML or JSON, empty file, over 1 MiB, a directory in place of the file, a relative `KUBECONFIG` entry or `CLAUDE_CONFIG_DIR`, `mcpServers: null`, names with ANSI escapes or bidi characters): expected a note via the scan error, other files still used, no crash, sanitized labels. Tests: Task 6 `TestDiscoverBadFiles`, `TestDiscoverHostileNames`; Task 10 `TestDiscoverBadFiles`, `TestDiscoverNames`.
3. Secret canaries in kubeconfig `users`, MCP `env`/`headers`/`url`, and `DOCKER_HOST` credentials: expected nowhere in output, JSON, notes or errors. Tests: Task 3 `TestDiscoverRemoteDockerHost`, Task 6 `TestDiscoverNeverReturnsSecrets`, Task 10 `TestDiscoverNeverReturnsSecrets`, end-to-end in Tasks 7 and 11.
4. Docker socket oddities: the macOS `/var/run/docker.sock` symlink to a user socket (list once), a stale socket file with no daemon (not "reachable"), a socket the user may not open, `DOCKER_HOST=tcp://...` (say it was not checked), a regular file at the path. Tests: Task 3.
5. Attribution forms: `kubectl --context=prod`, `--context prod`, an EKS ARN context name, mixed named and unnamed calls in one command, `docker-compose`, `docker compose`, MCP server names with spaces or dots (Claude Code calls them with `_`), MCP deny forms `mcp__server`, `mcp__server__*` (deny) versus `mcp__server__tool` and `mcp__server2` (not a deny). Tests: Tasks 2, 5, 8, 9.

## Decisions made by the planner

- **Interface change 1 (pipeline):** the confirmation list in `run.discover` is built from every discovered credential's provider, and `resolveAll` calls `Resolve` on every credential, so a `SkipError` alone would still list "Docker" in the prompt and add an "online check skipped" note per credential. Smallest fix: optional marker `scan.LocalOnly` (one method, one assertion in each of the two places). `Scanner` itself is unchanged; each new scanner still implements `Resolve` (returns a `SkipError`, never called by the pipeline).
- **Interface change 2 (MCP usage):** the engine hands a rule only shell calls (`a.Usage.Calls(c.Tool)`); MCP use sits in `Usage.MCP`. Smallest fix: `rules.Context` gains `MCP []usage.MCPCall`, filled in `Evaluate`. `ToolRule.Attribute` keeps its signature; `MCPRule.Attribute` ignores its `calls` argument and returns the matching `MCPCall`s as `usage.Call{Invocation{Tool: "mcp", Sub: tool, Target: server}}`, so `AgentUse` and the generic unused/rare logic work unchanged. Rejected: a second Attribute method (touches every rule and fake) and putting MCP into `Usage.Shell` (corrupts shell data).
- **Interface change 3 (block advice):** `Agent.BlockAdvice(tool string)` cannot name an MCP server, and Claude's text for it is `deny "mcp__<server>"`, not `Bash(...)`. It becomes `BlockAdvice(c model.Credential) string` (8 mechanical call-site edits, listed in Task 8). Rejected: a generic placeholder advice (wrong for the user).
- **MCP scanner reads Claude Code's configuration directly** (`<CLAUDE_CONFIG_DIR or ~>/.claude.json`, keys `mcpServers` and `projects.<path>.mcpServers`), not through the `Agent` interface. The spec lists MCP as a scanner, and a second agent later adds its own file to the same scanner. Covered: user and local (per-project) scope servers. Not covered, said in the README line and the scanner doc comment: `.mcp.json` project files, plugin servers, claude.ai connectors, managed MCP files, `disabledMcpServers`. Observed on this machine (key names only): `~/.claude.json` has top-level `mcpServers` (null) and `projects.<path>.mcpServers`; file is about 258 KB, so `model.ReadRegularFile`'s 1 MiB cap can eventually be exceeded: that case becomes a scan note, not silence (Task 10).
- **MCP risk is the engine's `usage.unused`:** "configured and never called" is exactly "unused with enough history", so `MCPRule.Risks` returns nothing and no `mcp.*` rule id exists. Unused is MED, rare LOW, used OK.
- **Production context severity is MED** (my call): the spec's doctor example shows `MED kubectl · context production` and `HIGH Docker`; HIGH would make every developer with a `prod` context fail `doctor` in automation. Rule id `kubectl.production-context`, `Block: true`.
- **`prod` matching is a case-insensitive substring** of the context name or its cluster name, except an occurrence directly preceded by `non`, `non-` or `non_` (controller ruling: `nonprod` is by its own name not production). Flags `production`, `Prod-eu`, `prod-cluster`, `product-x`; does not flag `nonprod`, `non-prod`, `NON_PRODUCTION`. A name with both (`nonprod-to-prod`) is flagged.
- **Docker scope covered:** `DOCKER_HOST` with `unix://` (if set it is the only candidate, as the Docker CLI does); otherwise `/var/run/docker.sock`, `~/.docker/run/docker.sock` (Docker Desktop on macOS), `~/.colima/default/docker.sock`, `$XDG_RUNTIME_DIR/docker.sock` (rootless Linux). Not covered: Docker CLI contexts (`~/.docker/config.json`), Rancher Desktop, Podman, `tcp://` and `ssh://` hosts (a note says "not checked"). Accessibility means a plain `connect()` to the socket that sends nothing and closes at once (local IPC, no network); a stale file or refused connect is "socket-unreachable", not a HIGH risk.
- **Docker calls are not split per socket:** a `docker` command names no socket, so every `docker`/`docker-compose` call counts as use of every Docker credential (errs toward "used"). `docker-compose` is counted because it talks to the same socket.
- **kubectl contexts:** one credential per context name across `KUBECONFIG` (split on the OS path-list separator) or else `~/.kube/config`; the first file defining a name wins, as in kubectl. `Kind` is `context` or `production-context`; `Identity` is the cluster name; `Provider()` is `kubectl` (the spec example prints "kubectl · context production"). The in-cluster service account is one more credential (`Kind: serviceaccount`, ID `serviceaccount:in-cluster`), present only when `KUBERNETES_SERVICE_HOST` is set and the token file exists; its content is never opened. Unnamed `kubectl` calls count as its use.
- **Scan problems use the existing error path:** a scanner returns the credentials it found plus an error whose text names the problem (path only, never content); `run.discover` already prints it as "<Provider> scan failed: ...". No new note mechanism.
- **Hermetic tests:** the only non-home absolute location read is `/var/run/docker.sock` (and the pod token path). Both are fields on the scanner, overridden in tests; test environments that run the real registry set `DOCKER_HOST` to a missing path (Task 4 edits `emptyHomeIO` and `canaryhome`).
- **Wording left alone:** the generic advice line "revoke a credential you do not use yourself" appears on kubectl and MCP findings; the spec's "remove the context" wording is not worth a per-tool advice hook now.
- **Dependency:** none added; `go.yaml.in/yaml/v3 v3.0.6` is already required.

## Files

- Create `internal/scan/docker/docker.go`, `internal/scan/docker/docker_test.go`
- Create `internal/scan/kubectl/kubectl.go`, `internal/scan/kubectl/kubectl_test.go`
- Create `internal/scan/mcp/mcp.go`, `internal/scan/mcp/mcp_test.go`
- Create `internal/rules/docker.go`, `internal/rules/kubectl.go`, `internal/rules/mcp.go` and their `_test.go` files
- Create `internal/run/e2e_local_test.go`
- Modify `internal/scan/scanner.go` (`LocalOnly`), `internal/run/run.go` (`discover`, `resolveAll`), `internal/run/run_test.go`, `internal/run/extension_test.go` (banned literals)
- Modify `internal/usage/shellparse/shellparse.go` and its test (`docker`, `kubectl`)
- Modify `internal/rules/rules.go` (`Context.MCP`, `AgentInput.BlockAdvice`), `internal/rules/rules_test.go` (helper)
- Modify `internal/agent/agent.go`, `internal/agent/claude/agent.go`, `internal/agent/claude/settings.go` and tests (MCP classify, `BlockAdvice(c)`), `internal/run/run_test.go` (fake agent)
- Modify `internal/registry/registry.go` (three lines in each list)
- Modify `internal/cli/exec_test.go`, `internal/canaryhome/canaryhome.go` (hermetic `DOCKER_HOST`)
- Modify `README.md` (one line)

---

### Task 1: Pipeline support for local-only scanners

**Files:**
- Modify: `internal/scan/scanner.go`
- Modify: `internal/run/run.go` (`discover`, `resolveAll`)
- Modify: `internal/run/extension_test.go` (`banned`)
- Test: `internal/run/run_test.go`

**Interfaces:**
- Consumes: `scan.Scanner`, `fakeScanner`, `newRig()` (existing test helpers).
- Produces: `scan.LocalOnly` (`interface{ LocalOnly() }`); a scanner that implements it is left out of the `providers` list passed to `Deps.Confirm`, never has `Resolve` called, and gets no "online check" note or progress line.

- [ ] **Step 1: Create the branch and write the failing tests**

Run `git switch -c feat/docker-kubectl-mcp`. In `internal/run/run_test.go` add:

```go
type localScanner struct{ *fakeScanner }

func (localScanner) LocalOnly() {}

func TestLocalOnlyScannerNeverPromptsOrResolves(t *testing.T) {
	r := newRig()
	r.confirm = func([]string) (bool, error) { t.Fatal("Confirm called"); return false, nil }
	r.sc.resolve = func(context.Context, model.Credential) (*model.Resolution, error) {
		t.Fatal("Resolve called")
		return nil, nil
	}
	d := r.deps()
	d.Scanners = []scan.Scanner{localScanner{r.sc}}
	d.Confirm = func([]string) (bool, error) { return false, confirm.ErrNoTerminal } // a prompt here would be exit 2
	rep, err := Collect(context.Background(), doctor(), d)
	if err != nil || rep.Offline || len(rep.Credentials) != 1 || rep.Credentials[0].Resolved != nil || r.sc.resolved != 0 {
		t.Fatalf("err %v report %+v", err, rep)
	}
	if n := strings.Join(rep.Notes, "\n"); strings.Contains(n, "online check") {
		t.Errorf("notes: %s", n)
	}
	if code := Execute(context.Background(), doctor(), d); code != 0 {
		t.Errorf("exit %d err %q", code, r.errb)
	}
}

func TestLocalOnlyMixedWithOnlineScanner(t *testing.T) {
	r := newRig() // r.sc provider "Fakery"
	online := &fakeScanner{name: "other", provider: "GitHub", creds: []model.Credential{cred("other", "o1")}, log: &r.log}
	d := r.deps()
	d.Scanners = []scan.Scanner{localScanner{r.sc}, online}
	d.Rules = append(d.Rules, fakeRule{"other", model.SevMed})
	var got, msgs []string
	d.Confirm = func(p []string) (bool, error) { got = p; return true, nil }
	d.Progress = func(m string) { msgs = append(msgs, m) }
	if _, err := Collect(context.Background(), inventory(), d); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "GitHub" || r.sc.resolved != 0 || online.resolved != 1 {
		t.Errorf("providers %v local resolved %d online resolved %d", got, r.sc.resolved, online.resolved)
	}
	if !slices.Contains(msgs, "checking GitHub label o1 (1/1)") { // the counter counts only credentials that are checked
		t.Errorf("progress %q", msgs)
	}
}
```

In `internal/run/extension_test.go` extend `banned` with `"docker": true, "kubectl": true, "mcp": true` (it passes now; it guards later tasks).

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/run -run 'TestLocalOnly' -count=1`
Expected: FAIL (the prompt is called with provider "Fakery", `Resolve` is called).

- [ ] **Step 3: Implement**

In `internal/scan/scanner.go` add `type LocalOnly interface{ LocalOnly() }` with a doc comment: a scanner that has nothing to resolve online implements it; the pipeline neither lists its provider in the prompt nor calls its `Resolve`. In `internal/run/run.go`: in `discover`, add a credential's provider to `providers` only when `sc` does not implement `scan.LocalOnly`; in `resolveAll`, count the credentials whose owner is not `scan.LocalOnly` as `total`, `continue` past local ones before the progress call and `Resolve`, and print `(done/total)` using a counter of checked credentials.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/run -count=1` then the standing verification.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/scan/scanner.go internal/run
git commit -m "feat: let scanners opt out of the online prompt and Resolve" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Group A: docker

### Task 2: Attribute `docker` shell calls

**Files:**
- Modify: `internal/usage/shellparse/shellparse.go`
- Test: `internal/usage/shellparse/shellparse_test.go`

**Interfaces:**
- Consumes: `shellparse.Invocation`, `toolRe`, `Tools`.
- Produces: `Parse` returns `Invocation{Tool: "docker"}` (no Sub, no Target) once per command that calls `docker` or `docker-compose`. `devuse` and the Claude reader pick it up unchanged (both iterate `Parse`).

- [ ] **Step 1: Write the failing test** `TestParseDocker`, table of command to expected `[]Invocation`:

```go
{"docker ps", []Invocation{{Tool: "docker"}}},
{"docker-compose up -d", []Invocation{{Tool: "docker"}}},
{"docker compose up", []Invocation{{Tool: "docker"}}},
{"sudo docker run --rm x && docker ps", []Invocation{{Tool: "docker"}}}, // one per command
{"echo $(docker ps -q)", []Invocation{{Tool: "docker"}}},
{"cd /srv/docker/app && ls", nil},
{"dockerd --debug", nil},
{"mydocker ps", nil},
```

Also assert `Parse("aws s3 ls; docker ps")` returns both tools.

- [ ] **Step 2: Run** `go test ./internal/usage/shellparse -run TestParseDocker -count=1` → FAIL.
- [ ] **Step 3: Implement**: append `"docker"` to `Tools`; add `dockerCall = toolRe("docker(?:-compose)?", "")` and a `case "docker":` that adds `Invocation{Tool: "docker"}` when `dockerCall` matches. Update the package comment ("the aws, gh, docker and kubectl invocations") and the existing `shortcut:` note to say `echo docker` counts as a call.
- [ ] **Step 4: Run** `go test ./internal/usage/... ./internal/devuse -count=1` → PASS.
- [ ] **Step 5: Commit** `feat: attribute docker and docker-compose shell calls`.

### Task 3: Docker scanner

**Files:**
- Create: `internal/scan/docker/docker.go`
- Test: `internal/scan/docker/docker_test.go`

**Interfaces:**
- Consumes: `scan.Scanner`, `scan.LocalOnly`, `scan.Env`, `scan.SkipError`, `model.Credential`, `model.Sanitize`.
- Produces: `docker.New() *Scanner`; `Name() "docker"`, `Provider() "Docker"`, `LocalOnly()`, `Resolve` returning `nil, &scan.SkipError{Reason: "nothing to resolve online"}`. `Discover` returns one `model.Credential` per distinct real socket path: `Tool "docker"`, `ID` the absolute path after `filepath.EvalSymlinks`, `Label` that path with a leading home directory shown as `~`, `Kind` `"socket"` (connect succeeded) or `"socket-unreachable"` (with a fixed-text note: `permission denied`, `nothing is listening`, or `could not connect`), `Source` `"env"` with `EnvVars: ["DOCKER_HOST"]` when it came from `DOCKER_HOST`, else `"file"`; no `Files`. `Scanner` has an unexported `systemSocket string` (default `/var/run/docker.sock`) that tests override. Candidate order and rules are in the Decisions section; every candidate path must be absolute; an `os.Stat` result that is not a socket or does not exist is skipped silently. `DOCKER_HOST` set to anything but `unix://<absolute path>` returns no credential and the error `DOCKER_HOST is a <scheme> endpoint, not a unix socket; not checked` (scheme only, never the rest of the URL).

- [ ] **Step 1: Write the failing tests** in `docker_test.go`. Helpers: `sockDir(t)` makes `os.MkdirTemp("", "ac")` with cleanup; `listen(t, path)` listens on a unix socket, and its goroutine accepts connections, counts bytes read until EOF into an `atomic.Int64`, and closes. `env(home, vars)` builds a `scan.Env`.
  - `TestDiscoverDockerHost`: `DOCKER_HOST=unix://<sock>` with a listener gives one credential, `ID == sock`, `Kind "socket"`, `Source "env"`, `EnvVars ["DOCKER_HOST"]`.
  - `TestDiscoverDockerHostOverridesDefaults`: a listener exists at `<home>/.docker/run/docker.sock`, `DOCKER_HOST` points at a missing path: no credentials, nil error.
  - `TestDiscoverDefaultSockets`: home with listeners at `.docker/run/docker.sock` and `.colima/default/docker.sock`: two credentials, labels `~/.docker/run/docker.sock` and `~/.colima/default/docker.sock`; `XDG_RUNTIME_DIR=<dir>` with a listener at `<dir>/docker.sock` adds a third.
  - `TestDiscoverSymlinkListedOnce` (Review Focus 4): `systemSocket` is a symlink to `<home>/.docker/run/docker.sock`: one credential whose `ID` is the real path.
  - `TestDiscoverStaleSocket`: listener with `SetUnlinkOnClose(false)` then closed, so the file remains: `Kind "socket-unreachable"`, note contains `nothing is listening`.
  - `TestDiscoverPermissionDenied`: skip if `os.Geteuid() == 0`; `chmod 0` on a live socket: `socket-unreachable`, note contains `permission denied`.
  - `TestDiscoverIgnoresNonSockets`: a regular file at `systemSocket`, relative `DOCKER_HOST=unix://rel.sock`, nothing at all: no credentials, nil error.
  - `TestDiscoverRemoteDockerHost`: `DOCKER_HOST=tcp://user:CANARY-PW@10.0.0.1:2375`: no credentials, error contains `tcp`, does not contain `CANARY` or `10.0.0.1`.
  - `TestDiscoverSendsNothing`: after `Discover`, the listener goroutine's byte count is 0.
  - `TestResolveSkips`: `errors.As(err, &*scan.SkipError)`.

- [ ] **Step 2: Run** `go test ./internal/scan/docker -count=1` → FAIL (package does not compile).
- [ ] **Step 3: Implement** the scanner. Probe with `net.DialTimeout("unix", real, time.Second)` and close immediately; classify the failure with `errors.Is(err, fs.ErrPermission)` and `errors.Is(err, syscall.ECONNREFUSED)`; never put `err.Error()` in a note. Dedupe on the real path. Return credentials sorted by `ID`. Doc comment lists what is and is not covered.
- [ ] **Step 4: Run** `go test ./internal/scan/docker -count=1 -race` → PASS.
- [ ] **Step 5: Commit** `feat: docker socket scanner`.

### Task 4: Docker rule, registry line, hermetic environments, end to end

**Files:**
- Create: `internal/rules/docker.go`, `internal/rules/docker_test.go`, `internal/run/e2e_local_test.go`
- Modify: `internal/registry/registry.go`, `internal/cli/exec_test.go` (`emptyHomeIO`), `internal/canaryhome/canaryhome.go`

**Interfaces:**
- Consumes: `rules.ToolRule`, `rules.Risk`, `devuse.History.Lookup`, test helpers `run`, `agentIn`, `hist`, `calls`, `devHistory`, `cred` in `rules_test.go`; Task 2 (`docker` calls), Task 3 (`docker.New()`).
- Produces: `rules.DockerRule{}` (`Tool() "docker"`). `Attribute` returns all calls, 0 unattributed. `Risks`: for `Kind == "socket"` one `Risk{Rule: "docker.socket", Severity: SevHigh, Headline: "Docker socket is reachable by the agent (equivalent to root on this machine)", Short: "socket reachable", Block: true}`; none for `socket-unreachable`. `DeveloperUse`: `DevKnownRecent` when `x.Dev.Lookup("docker", "")` is dated within the window, else `DevUnknown`. `Revoke` returns `""`. In `e2e_local_test.go` (package `run_test`): helper `runLocal(t, dir string, extraEnv map[string]string, o run.Options) (code int, out, errb string)` which builds `run.Deps` from `registry.Scanners(scan.ExecRunner{})`, `registry.ToolRules()`, `claude.New(<dir>/.claude, dir, dir, "")`, `scan.Env{Home: dir, SysRoot: dir, Getenv: <map>}` and `confirm.Online(strings.NewReader(""), &eb, false, o.Offline, o.Yes, p)`; the map holds `HOME`, `CLAUDE_CONFIG_DIR`, `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE`, `GH_CONFIG_DIR`, `XDG_CONFIG_HOME`, `HISTFILE`, `ZDOTDIR`, `KUBECONFIG` (all inside `dir`), `DOCKER_HOST` (missing path), then `extraEnv`. Later tasks reuse it.

- [ ] **Step 1: Write the failing tests.**
  - `rules/docker_test.go`: `TestDockerRisks` (socket gives one HIGH `docker.socket` with `Block` true; `socket-unreachable` gives none); `TestDockerAttributeAll` (3 calls in, 3 out, 0 unattributed); `TestDockerDeveloperUse` (`devHistory(t, ": <unix now-1h>:0;docker ps")` gives `DevKnownRecent`; empty history gives `DevUnknown`); `TestDockerEvaluate`: `run(dockerCred, agentIn(hist(45)), DockerRule{})` gives `SevHigh`, `Rules` containing `docker.socket` and `usage.unused`, `Advice` containing `block docker`; with `Access: denied` gives `SevOK` and Headline `denied by agent settings`.
  - `run/e2e_local_test.go`: `TestE2EDockerSocketIsHigh`: a listener in `os.MkdirTemp` socket dir, `DOCKER_HOST` set to it, `doctor --offline`: exit 1, output contains `Docker` and `socket reachable`; the same with `permissions.deny: ["Bash(docker:*)"]` written to `<dir>/.claude/settings.json`: exit 0 and the JSON finding `access` is `denied`. `TestE2ELocalOnlyNeedsNoPrompt` (Review Focus 1): same socket, `Offline: false, Yes: false`, no terminal: exit 1 (HIGH), stderr empty of `--yes`, stdout non-empty.
  - Hermetic check: `TestE2EDockerNotFoundWhenHostMissing` with `DOCKER_HOST` pointing at a missing path: JSON `credentials` has no `docker` tool.

- [ ] **Step 2: Run** `go test ./internal/rules ./internal/run -run 'Docker|LocalOnly' -count=1` → FAIL.
- [ ] **Step 3: Implement** `DockerRule`. In `registry.go` add `docker.New()` to `Scanners` and `rules.DockerRule{}` to `ToolRules`. In `exec_test.go` add `"DOCKER_HOST": "unix://" + filepath.Join(dir, "docker.sock")` to `emptyHomeIO`'s map and the same to `canaryhome.New`'s `Env` (Dir-based), so no test reads the machine's real socket.
- [ ] **Step 4: Run** the standing verification (also proves `TestRegistryEveryScannerHasToolRule`, `TestDefaultExecEmptyHomeOffline` and the canary end-to-end tests still pass on a machine with a live Docker socket).
- [ ] **Step 5: Commit** `feat: report the Docker socket in inventory and doctor`.

---

## Group B: kubectl

### Task 5: Attribute `kubectl --context`

**Files:**
- Modify: `internal/usage/shellparse/shellparse.go`
- Test: `internal/usage/shellparse/shellparse_test.go`

**Interfaces:**
- Consumes: `targets`, `toolRe`, `tokenChars`.
- Produces: `Parse` returns `Invocation{Tool: "kubectl", Target: <context>}`, one per distinct context; `Target ""` when a call names none (same convention as `aws` profiles, via the existing `targets` helper). `Sub` is empty.

- [ ] **Step 1: Write the failing test** `TestParseKubectl`:

```go
{"kubectl get pods", {kubectl, ""}},
{"kubectl --context prod get pods", {kubectl, "prod"}},
{"kubectl --context=prod get pods", {kubectl, "prod"}},
{`kubectl get pods --context "arn:aws:eks:us-east-1:123456789012:cluster/prod"`, {kubectl, "arn:aws:eks:us-east-1:123456789012:cluster/prod"}},
{"kubectl --context a get po; kubectl get po", {kubectl, "a"}, {kubectl, ""}},
{"kubectl --context a get po; kubectl --context b get po", {kubectl, "a"}, {kubectl, "b"}},
{"kubectl config use-context prod", {kubectl, ""}}, // documented limit: names no --context
{"kubectl", {kubectl, ""}},
{"kubectlx get pods", nil}, {"k get pods", nil}, {"helm --kube-context prod ls", nil},
```

- [ ] **Step 2: Run** `go test ./internal/usage/shellparse -run TestParseKubectl -count=1` → FAIL.
- [ ] **Step 3: Implement**: append `"kubectl"` to `Tools`; add `kubectlCall = toolRe("kubectl", "")`, `contextRe = (?:--context[ =])["']?(tokenChars)` and a `case "kubectl":` mirroring the `aws` case with `contextRe`. Add a `shortcut:` comment that `use-context` is not read.
- [ ] **Step 4: Run** `go test ./internal/usage/... ./internal/devuse -count=1` → PASS.
- [ ] **Step 5: Commit** `feat: attribute kubectl calls to the context they name`.

### Task 6: kubectl scanner

**Files:**
- Create: `internal/scan/kubectl/kubectl.go`
- Test: `internal/scan/kubectl/kubectl_test.go`

**Interfaces:**
- Consumes: `scan.Scanner`, `scan.LocalOnly`, `model.ReadRegularFile`, `model.Sanitize`, `yaml.Unmarshal`.
- Produces: `kubectl.New() *Scanner` (unexported `saToken string`, default `/var/run/secrets/kubernetes.io/serviceaccount/token`, overridden in tests); `Name() "kubectl"`, `Provider() "kubectl"`, `LocalOnly()`, `Resolve` returning a `SkipError`. `Discover` returns, sorted by `ID`: one credential per context name (`Tool "kubectl"`, `ID` raw name, `Label` sanitized name, `Kind "context"` or `"production-context"`, `Identity` sanitized cluster name, `Source "file"`, `Files` the defining file); plus, when `KUBERNETES_SERVICE_HOST` is non-empty and `saToken` is a regular file (stat only, never opened), `ID "serviceaccount:in-cluster"`, `Label "in-cluster service account"`, `Kind "serviceaccount"`, `Files [saToken]`, one note `token mounted in this pod; what it can do is not resolved`. `KUBECONFIG` non-empty selects the list (split on `os.PathListSeparator`, empty entries dropped), else `<Home>/.kube/config` when `Home != ""`. Decode only `contexts[].name` and `contexts[].context.cluster`. A relative path, an unreadable or unparsable file, a directory or a file over 1 MiB adds to the returned error (`could not read or parse <sanitized path>` or `kubeconfig path is not absolute`); a missing file is silent; found credentials are still returned alongside the error. A context with an empty name is skipped. Production: unexported `isProd(s string) bool`, true when the lowercased string has an occurrence of `prod` not directly preceded by `non`, `non-` or `non_`; applied to name and cluster (either one true is enough).

- [ ] **Step 1: Write the failing tests** (kubeconfigs are written by a helper into `t.TempDir()`):
  - `TestDiscoverContexts`: contexts `dev` (cluster `dev-1`), `production` (cluster `c1`), `Prod-eu`, `staging` (cluster `prod-cluster`), `nonprod`, `non-prod`, `NON_PRODUCTION`, `nonprod-to-prod`: Kinds are `context`, `production-context`, `production-context`, `production-context`, `context`, `context`, `context`, `production-context`; `Identity` of `staging` is `prod-cluster`; `Files` is the config path; default path is `<home>/.kube/config`.
  - `TestDiscoverKubeconfigList`: `KUBECONFIG=<a>:<missing>:<b>` with the same context name in a and b: one credential, `Files[0]` is a; a missing entry gives no error; `KUBECONFIG` overrides the default home file.
  - `TestDiscoverNeverReturnsSecrets` (Review Focus 3): kubeconfig whose `users` hold `token`, `client-key-data`, `exec.args` and `auth-provider.config` with `CANARY-...` values, and a cluster `server` URL with a canary: `json.Marshal` of the credentials and the error text contain no canary.
  - `TestDiscoverBadFiles` (Review Focus 2): invalid YAML containing a canary, a YAML scalar, an empty file, a directory, a file over 1 MiB, a relative `KUBECONFIG` entry next to a valid file: the valid file's contexts are still returned, the error is non-nil for the bad ones and contains no canary, an empty or missing file gives nil error.
  - `TestDiscoverHostileNames`: context name `prod\x1b[31m‮` gives a `Label` with no control or bidi character and still `production-context`.
  - `TestDiscoverServiceAccount`: env var set plus a temp token file containing a canary: credential present, canary absent from marshalled output; env var unset: absent; env var set, file missing: absent.
  - `TestResolveSkips`.

- [ ] **Step 2: Run** `go test ./internal/scan/kubectl -count=1` → FAIL (does not compile).
- [ ] **Step 3: Implement.** Never print yaml errors. Keep the doc comment listing what is covered (kubeconfig contexts, in-cluster token) and not (users, exec plugins, cluster calls).
- [ ] **Step 4: Run** `go test ./internal/scan/kubectl -count=1 -race` → PASS.
- [ ] **Step 5: Commit** `feat: kubectl context scanner`.

### Task 7: kubectl rule, registry line, end to end

**Files:**
- Create: `internal/rules/kubectl.go`, `internal/rules/kubectl_test.go`
- Modify: `internal/registry/registry.go`, `internal/run/e2e_local_test.go`

**Interfaces:**
- Consumes: Task 5 (`Target` is the context), Task 6 (`Kind`, `ID`), `plural` and `contains` in package `rules`, `runLocal` from Task 4.
- Produces: `rules.KubectlRule{}` (`Tool() "kubectl"`).
  - `Attribute(c, calls, x)`: for `Kind "serviceaccount"` the calls with `Target == ""` are its own, 0 unattributed; otherwise own = calls with `Target == c.ID`, unattributed = number of calls with `Target == ""`.
  - `Risks`: `Kind "production-context"` gives `Risk{Rule: "kubectl.production-context", Severity: SevMed, Headline: "Production Kubernetes context is reachable by the agent", Short: "production", Block: true}`; for a non-`serviceaccount` credential with `use.Unattributed > 0` an extra `Risk{Severity: SevOK, Details: []string{"Agent ran kubectl N times without naming a context"}}` (`N` via `plural(n, "time")`, so `1 time`).
  - `DeveloperUse`: `DevKnownRecent` when `x.Dev.Lookup("kubectl", c.ID)` is dated within the window, else `DevUnknown`. `Revoke` returns `""`.

- [ ] **Step 1: Write the failing tests.**
  - `TestKubectlAttribute`: calls = 2 with target `prod`, 1 with `dev`, 3 with `""`; credential `prod`: 2 own, 3 unattributed; `dev`: 1 own, 3 unattributed; `serviceaccount:in-cluster`: 3 own, 0.
  - `TestKubectlSpecCases` via `run(...)` with `agentIn`: (a) no kubectl calls, 45 days of history: a `dev` context has `Rules == [usage.unused]`, `SevMed`; a `production-context` has `Rules` containing both `kubectl.production-context` and `usage.unused`. (b) 4 unnamed calls, 45 days: `dev` has `Used "?"`, `Rules` does not contain `usage.unused`, `Details` contains `Agent ran kubectl 4 times without naming a context`; the production context still has `kubectl.production-context` and the same detail. (c) 3 calls naming `dev`: `dev` is `SevOK`, `Used "3"`; production stays `SevMed`. (d) `Access: denied`: `SevOK`, no risk. (e) 1 unnamed call: detail says `1 time`.
  - `TestKubectlDeveloperUse`: dated history `kubectl --context prod get pods` within the window gives `DevKnownRecent` for `prod`, `DevUnknown` for `dev`; undated or unnamed use gives `DevUnknown`.
  - e2e: `TestE2EKubectlProductionContext` writes `<dir>/.kube/config` with contexts `dev` and `production` (token canary in `users`), and a session file with a first timestamp 40 days ago and no kubectl call: `doctor --offline --json` exit 0 (MED only), findings `claude-code:kubectl:production` has rule `kubectl.production-context`, `dev` has `usage.unused`, no canary anywhere; with an added `Bash` call `kubectl get pods` in the session, `dev`'s `details` contains `Agent ran kubectl 1 time without naming a context` and its `rules` lack `usage.unused`.

- [ ] **Step 2: Run** `go test ./internal/rules ./internal/run -run 'Kubectl' -count=1` → FAIL.
- [ ] **Step 3: Implement** `KubectlRule`; add `kubectl.New()` and `rules.KubectlRule{}` to the registry lists.
- [ ] **Step 4: Run** the standing verification.
- [ ] **Step 5: Commit** `feat: report kubectl contexts, flag production`.

---

## Group C: MCP

### Task 8: Claude agent understands MCP credentials

**Files:**
- Modify: `internal/agent/agent.go`, `internal/agent/claude/agent.go`, `internal/agent/claude/settings.go`, `internal/rules/rules.go` (`AgentInput.BlockAdvice` type and its two call sites, lines about 232 and 250), `internal/rules/rules_test.go` (`agentIn`), `internal/run/run_test.go` (`fakeAgent.BlockAdvice`), `internal/agent/claude/agent_test.go` (two existing calls)
- Test: `internal/agent/claude/settings_test.go`, `internal/agent/claude/agent_test.go`

**Interfaces:**
- Consumes: `bashMatches`, `Settings.Classify`.
- Produces: `Agent.BlockAdvice(c model.Credential) string` (was `(tool string)`); `rules.AgentInput.BlockAdvice func(c model.Credential) string`. In `claude`: `const mcpTool = "mcp"`; `mcpMatches(rule, server string) bool` is true for `mcp__<server>` and `mcp__<server>__*` only; `Settings.Classify` uses `mcpMatches(r, c.ID)` instead of `bashMatches(r, c.Tool)` when `c.Tool == mcpTool`; `BlockAdvice` for an MCP credential is `deny "mcp__<c.ID>" in ~/.claude/settings.json`, otherwise unchanged text from `c.Tool`.

- [ ] **Step 1: Write the failing tests.** `TestClassifyMCP` over credential `{Tool: "mcp", ID: "filesystem"}`: deny `["mcp__filesystem"]` is denied; deny `["mcp__filesystem__*"]` denied; deny `["mcp__filesystem__read"]` asks; deny `["mcp__other"]` asks; deny `["mcp__filesystem2"]` asks (prefix trap); deny `["Bash(mcp:*)"]` asks (a Bash rule does not apply); allow `["mcp__filesystem"]` allowed; ask `["mcp__filesystem"]` asks; `DefaultMode "dontAsk"` with no rule is denied; deny `["mcp__filesystem"]` does not deny a `{Tool: "aws"}` credential. `TestAgentBlockAdviceMCP`: `a.BlockAdvice(model.Credential{Tool: "mcp", ID: "filesystem"})` equals `deny "mcp__filesystem" in ~/.claude/settings.json`. Update the two existing `BlockAdvice("aws")` and `BlockAdvice("gh")` assertions to pass `model.Credential{Tool: ...}`.
- [ ] **Step 2: Run** `go test ./internal/agent/... -count=1` → FAIL (does not compile or wrong access).
- [ ] **Step 3: Implement** the signature change at the eight sites listed under Files and the two claude changes.
- [ ] **Step 4: Run** the standing verification.
- [ ] **Step 5: Commit** `feat: Claude agent classifies and advises on MCP servers`.

### Task 9: MCP rule

**Files:**
- Modify: `internal/rules/rules.go` (`Context`, `Evaluate`)
- Create: `internal/rules/mcp.go`, `internal/rules/mcp_test.go`

**Interfaces:**
- Consumes: `usage.MCPCall`, `usage.Usage.MCP`, `agentIn`, `run`, `hist`.
- Produces: `rules.Context.MCP []usage.MCPCall` (doc comment: the agent's MCP calls, read only by the MCP rule), set in `Evaluate` from `a.Usage.MCP`. `rules.MCPRule{}`: `Tool() "mcp"`; `Attribute(c, _, x)` returns every `x.MCP` call with `Server == c.ID` as `usage.Call{At: m.At, Invocation: shellparse.Invocation{Tool: "mcp", Sub: m.Tool, Target: m.Server}}`, 0 unattributed; `Risks` returns nil; `DeveloperUse` returns `DevUnknown`; `Revoke` returns `""`.

- [ ] **Step 1: Write the failing tests.** `TestMCPAttribute`: `x.MCP` has 3 calls to `filesystem` (tool `read`) and 1 to `other`; credential `{Tool: "mcp", ID: "filesystem"}` gets 3 calls, first has `Tool "mcp"`, `Sub "read"`, `Target "filesystem"`. `TestMCPEvaluate` through `run(...)` with `agentIn(u)` where `u.MCP` is set: 0 calls and 45 days of history gives `SevMed`, `Rules == [usage.unused]`; 1 call gives `SevLow`; 212 calls gives `SevOK`, `Used "212"`, `Headline == "used 212 times by claude-code in the last 30 days"`; 0 calls and 10 days of history gives `Used "0?"` and no `usage.unused` (spec: no "unused" on short history); calls to a different server give the credential 0 calls.
- [ ] **Step 2: Run** `go test ./internal/rules -run MCP -count=1` → FAIL.
- [ ] **Step 3: Implement** the field, the `Evaluate` line and `MCPRule`.
- [ ] **Step 4: Run** the standing verification.
- [ ] **Step 5: Commit** `feat: MCP rule counts the agent's MCP calls per server`.

### Task 10: MCP scanner

**Files:**
- Create: `internal/scan/mcp/mcp.go`
- Test: `internal/scan/mcp/mcp_test.go`

**Interfaces:**
- Consumes: `scan.Scanner`, `scan.LocalOnly`, `model.ReadRegularFile`, `model.Sanitize`.
- Produces: `mcp.New() *Scanner`; `Name() "mcp"`, `Provider() "MCP"`, `LocalOnly()`, `Resolve` returning a `SkipError`. `Discover` reads `<CLAUDE_CONFIG_DIR>/.claude.json` when that variable is set (it must be absolute, else error `configuration directory is not an absolute path`), else `<Home>/.claude.json` (nothing when `Home == ""`). Top level uses exact key lookup (`map[string]json.RawMessage`, as `claude/settings.go` does), then `mcpServers` and `projects.<path>.mcpServers` (projects in sorted path order, user scope first). Each server value is decoded only for `type`. One credential per normalized name: `Tool "mcp"`, `ID` the name with every character outside `[A-Za-z0-9_-]` replaced by `_`, `Label` the sanitized original name, `Kind` `stdio` (also when `type` is absent), `http` or `sse`, else `unknown`, `Source "file"`, no `Files`, first definition wins, sorted by `ID`. Missing file, empty file, `mcpServers: null` or `{}` give nil, nil. Unreadable, unparsable, non-regular or over-1-MiB file gives nil and the error `could not read or parse Claude Code configuration` (no content, no path from the file). Doc comment lists what is not covered (see Decisions).

- [ ] **Step 1: Write the failing tests** (the config is written by a helper into `t.TempDir()`):
  - `TestDiscoverServers`: user-scope `filesystem` (no type), `remote` (`"type":"http"`), project-scope `filesystem` again plus `local-only` (`"type":"sse"`) under `projects./p/a`: three credentials `filesystem` (`stdio`), `local-only` (`sse`), `remote` (`http`), sorted.
  - `TestDiscoverNames` (Review Focus 5 and 2): `my server.v2` gives `ID "my_server_v2"`, `Label "my server.v2"`; a name with `\x1b[31m` has a sanitized label; an empty name is skipped; two names normalizing to the same ID give one credential.
  - `TestDiscoverConfigDirWins`: both `<cfgdir>/.claude.json` and `<home>/.claude.json` exist with different servers: only `<cfgdir>`'s are returned; with `CLAUDE_CONFIG_DIR` unset the home file is read; relative `CLAUDE_CONFIG_DIR` gives the error.
  - `TestDiscoverNeverReturnsSecrets` (Review Focus 3): servers with `env`, `headers`, `url`, `args`, `command` holding `CANARY-...` values plus a top-level `oauthAccount` with a canary: marshalled credentials contain no canary.
  - `TestDiscoverBadFiles` (Review Focus 2): invalid JSON containing a canary, a JSON array, a file over 1 MiB, a directory at the path: each gives nil credentials and the fixed error text without the canary; empty file, missing file, `{"mcpServers":null}`, `{"mcpServers":{},"projects":{"/p":{"mcpServers":null}}}`, and `Home == ""` with no config dir give nil, nil; a server whose `type` is a number gives `Kind "unknown"`, not an error.
  - `TestResolveSkips`.

- [ ] **Step 2: Run** `go test ./internal/scan/mcp -count=1` → FAIL (does not compile).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/scan/mcp -count=1 -race` → PASS.
- [ ] **Step 5: Commit** `feat: MCP server scanner for Claude Code configuration`.

### Task 11: MCP registry line, end to end, README

**Files:**
- Modify: `internal/registry/registry.go`, `internal/run/e2e_local_test.go`, `README.md`

**Interfaces:**
- Consumes: Tasks 8 to 10, `runLocal` from Task 4.
- Produces: `registry.Scanners` ends `..., docker.New(), kubectl.New(), mcp.New()`; `registry.ToolRules` ends `..., rules.DockerRule{}, rules.KubectlRule{}, rules.MCPRule{}`.

- [ ] **Step 1: Write the failing end-to-end test** `TestE2EMCPServers`: `<dir>/.claude/.claude.json` with servers `filesystem`, `idle` (env canary) and `blocked`; `settings.json` denying `mcp__blocked`; a session file with a first line dated 40 days ago and three `tool_use` records named `mcp__filesystem__read_file` (ids `m1` to `m3`); `doctor --offline --json`, exit 0: `claude-code:mcp:filesystem` has `severity` `OK` and `used` `3`; `claude-code:mcp:idle` has rules `[usage.unused]` and `advice` containing `deny "mcp__idle" in ~/.claude/settings.json`; `claude-code:mcp:blocked` has `access` `denied`; no canary in stdout or stderr; `inventory --offline` text lists `MCP` and `filesystem`. A second case with only a 5-day history shows `used` `0?` for `idle`.
- [ ] **Step 2: Run** `go test ./internal/run -run TestE2EMCPServers -count=1` → FAIL.
- [ ] **Step 3: Implement**: add the two registry entries. In `README.md` change the line "Supported today: one agent (Claude Code) and two tools (AWS, and GitHub through `gh`)..." to also name the Docker socket, kubectl contexts and Claude Code MCP servers (offline checks only; MCP covers user and per-project servers in `.claude.json`). Change nothing else in the README.
- [ ] **Step 4: Run** the standing verification, then the final verification below.
- [ ] **Step 5: Commit** `feat: report MCP servers; document the new tools`.

---

## Final verification

Automated (a `verifier` can run these):

- `cd /Users/sang/Projects/individual-projects/agentctl && gofmt -l . ; go vet ./... && go test ./... -count=1 -race` → no gofmt output; every package `ok`.
- `go test ./internal/run -run 'TestSourcesHaveNoPerToolLiterals|TestRegistry' -count=1` and `go test ./internal/registry -count=1` → `ok` (no tool names in `run` or `render`; every scanner has a rule).
- `go build -o "$TMPDIR/agentctl-bin" ./cmd/agentctl`, then, never against the real home: `D=$(mktemp -d) && HOME=$D CLAUDE_CONFIG_DIR=$D/.claude AWS_CONFIG_FILE=$D/a AWS_SHARED_CREDENTIALS_FILE=$D/b GH_CONFIG_DIR=$D/gh XDG_CONFIG_HOME=$D/x HISTFILE=$D/h ZDOTDIR=$D KUBECONFIG=$D/kube DOCKER_HOST=unix://$D/none.sock "$TMPDIR/agentctl-bin" inventory --offline` → prints `No credentials found.`, exit 0.

Manual (owner, on a real machine; the planner and implementers do not do this):

- `agentctl inventory --offline` on a machine with Docker and a kubeconfig lists a `Docker` group and a `kubectl` group, and `doctor` shows `HIGH` for a reachable Docker socket and `MED` for a production context.
- A `doctor` run with only these tools present and no `--yes` does not stop asking for `--yes`.
- Contexts the owner knows are production show `production-context`; a context named like `nonprod` does not, but `product-x` does (substring rule): confirm that is acceptable.

## Self-review notes

- Spec coverage: scanners list (Tasks 3, 6, 10); usage rules and kubectl attribution rule (Tasks 5, 7, 9); developer-use handling (rule `DeveloperUse` in 4 and 7, MCP unknown in 9); three risk rules (4, 7, 9); safety requirements (global constraints, canary tests in 3, 6, 10 and end to end in 4, 7, 11); testing section (fixtures built in tests, rules as pure functions); service-account line from "Running on servers" (Task 6). Left out on purpose: `fix`, advice wording per tool, `.mcp.json` and plugin servers.
- Type consistency: `LocalOnly()` (Task 1) is implemented by Tasks 3, 6, 10; `Kind` strings `socket`, `socket-unreachable`, `context`, `production-context`, `serviceaccount` match between scanner and rule tasks; `BlockAdvice(c model.Credential)` is introduced in Task 8 and used only afterwards; `Context.MCP` (Task 9) is read only by `MCPRule`.
- Proportion: three interface edits (one marker interface, one struct field, one signature), no new dependency, three scanner packages and three rule files.
