# agentctl — design

Date: 2026-11-20
Status: approved by owner, 2026-11-20

Items marked **(call)** were decided by the design author, not by the project owner, and are open to correction.

## Intent

AI coding agents (Claude Code, Codex, Cursor) run on developer machines that hold authenticated CLIs and long-lived credentials. The developer rarely knows what the agent can actually reach, and access the agent never uses stays available to be leaked or misused.

`agentctl` is an open-source command-line tool that shows a developer what their agent can reach, flags the risky and the unused, and helps take the unused access away.

Why this shape: research (see `docs/agent-work/research/2026-11-20-*.md`) found the enforcement layers crowded (nono, Keycard, OneCLI, native agent permission rules, MCP gateways) and the visibility layer empty. Nothing found resolves reachable credentials to effective permissions, and nothing recommends removal based on what the agent actually used.

## Goals

1. One command shows every tool and credential the agent can reach on this machine and what each can do.
2. Flag high-risk access (for example an AWS credential with AdministratorAccess, an exposed Docker socket, a production Kubernetes context).
3. Flag access the agent has not used, or has rarely used, and recommend removing it.
4. Apply the agent-side removal for the user, after confirmation.
5. Run entirely on the developer's machine with no AI model and no third-party service.

## Non-goals (v1)

- No runtime proxy, gateway, or credential broker.
- No sandbox. `agentctl` relies on the agent's own permission rules and says so.
- No minting of short-lived credentials.
- No background daemon or scheduled notifications. Findings appear when a command is run.
- No automatic revocation at the provider. `agentctl` prints the command or link; the user does it.
- No team or central policy.
- No nono profile output. **(call)** Deferred until the Claude Code path is proven.

## Future goals (owner's direction, not built in v1)

- **A user interface.** Its form (terminal, local web page, desktop) is not decided. To keep that door open, v1 must:
  - produce the inventory and findings as data first, with printing as a separate step, so a UI can call the same code the commands do;
  - treat `--json` output, with its schema version, as a stable contract a UI or another program can read.
- A UI must still honour "everything runs locally" and every anti-goal below.

## Anti-goals

These would make the project a failure even if it works:

- Printing, logging, or transmitting a secret value.
- Sending anything anywhere other than the provider a credential belongs to.
- Any provider call that is not read-only.
- Changing a file without showing the change and getting a yes.
- Recommending revocation of a credential the developer still uses themselves.
- Presenting agent deny rules as a hard security boundary. Without a sandbox they are advisory, and the output must say so.

## Constraints

- Local only. No AI model, no telemetry, no update check.
- Online by default (owner's decision): `agentctl` uses the credentials already on the machine to ask each provider, read-only, what that credential can do. `--offline` disables all network access and reports only what the files show.
- macOS and Linux, on laptops and on servers (owner's requirement). See "Running on servers".
- Single binary, no runtime dependencies. Written in Go (owner's decision).
- License MIT (owner's choice: the GitHub repository was created with an MIT licence).

## Approaches considered

**A. Scan and report only.** `doctor` and `inventory`, nothing is changed. Smallest and safest, but the user must act on every finding by hand, and reports that require manual follow-up tend to be read and dropped.

**B. Scan, report, and apply (chosen).** As A, plus `agentctl fix`, which writes deny rules into the agent's own configuration after confirmation. Completes the loop the owner described (detect unused access, notify, remove) without a daemon or proxy. Cost: must track each agent's configuration format, and deny rules are advisory without a sandbox.

**C. Full gateway.** CLI and MCP proxy, credential broker, approval, audit. Gives runtime control and short-lived credentials, but is several times larger, duplicates nono, OneCLI and Keycard, and is still advisory without a sandbox.

B was chosen because it delivers what the owner asked for without rebuilding what already exists. The scan is built before `fix` so the value of the findings can be tested early. C can be revisited later.

## Decisions made by the owner

- Build it, as open source.
- Unused or rarely used access triggers a recommendation to remove it.
- Two levels of removal:
  - **Agent does not use it, developer does:** recommend blocking only the agent. The credential is untouched.
  - **Nobody uses it:** recommend revoking the credential at the provider.
- Everything runs locally; no AI agent is needed to run any command.
- Online is the default; offline is the opt-out.

## Commands

### `agentctl inventory`

Lists what the agent can reach, grouped by tool: provider, credential type, identity, effective permissions (when online), and whether the agent's current configuration allows or denies it.

### `agentctl doctor`

Runs the inventory, reads the agent's usage, applies the rules below, and prints findings ordered by severity.

```text
$ agentctl doctor
About to ask AWS and GitHub what your credentials can do.
Read-only, but the requests appear in their audit logs.
Continue? [y/N] (--yes to skip this question, --offline to stay local) y

HIGH  AWS · profile prod
      AdministratorAccess. Agent can reach it.
      Agent use, last 30 days: none. Your use: 4 days ago.
      → Block the agent:  agentctl fix aws-prod

HIGH  Docker
      Docker socket is reachable by the agent (equivalent to root on this machine).

MED   kubectl · context production
      Agent use, last 30 days: none (kubectl not run). Your use: unknown.
      → Block the agent:  agentctl fix kube-production
      If you do not use it either, remove the context.

MED   GitHub · token (gh)
      Scopes: repo, workflow, admin:org. Agent's commands needed: repo.
      → Unused scopes: workflow, admin:org. Replace the token: https://github.com/settings/tokens

OK    MCP · filesystem — used 212 times

Note: agent deny rules are advisory unless the agent runs in a sandbox.
```

### `agentctl fix [finding-id]`

For each fixable finding (all, or the one named): shows the exact change to the agent's configuration file, asks for confirmation, backs up the file, writes the change. Provider-side revocation is never performed; the command or URL is printed.

### Flags

- `--offline`: no network access.
- `--since <duration>`: usage window. Default 30 days. **(call)**
- `--json`: machine-readable output for `inventory` and `doctor`. **(call)**
- `--yes`: answers yes to every confirmation: the online prompt in `inventory` and `doctor`, and the apply prompt in `fix`. Needed where there is no terminal to answer on. Changes made by `fix` are still printed and backed up. **(call)**

### Running on servers

The owner requires that `agentctl` works on servers as well as laptops. How that is met is the design author's reading. **(call)**

- **Two kinds of server (owner's decision):** a remote development machine the developer reaches over SSH and runs an agent on, and a machine where an agent runs unattended.
- **No screen, no keyboard needed.** Every command runs over SSH, in a container, or in a scheduled job. Nothing opens a browser. The two confirmations (going online, applying a fix) are answered with `--yes` on unattended machines; without a terminal and without `--yes` the command stops with a clear message instead of hanging.
- **Plain output when not attached to a terminal:** no colour, no symbols that need a special font.
- **Exit status for automation:** `doctor` exits 0 when there are no HIGH findings, 1 when there are, and 2 on an error, so a job can fail on a risky machine.
- **Linux builds for x86-64 and arm64**, statically linked, so the binary runs on minimal server images without installing anything.
- **Server credential sources are scanned too.** On servers, credentials usually come from environment variables and from the machine's own identity rather than from files in a home directory. `agentctl` reports credentials present in its environment (by variable name, never value), and online it resolves AWS through the standard credential chain, which picks up an instance or container role. A server with no `~/.aws` must not be reported as having no AWS access.
- **Whose access is checked:** the account `agentctl` runs as. To check the account an agent runs under (a service user, a container), run `agentctl` as that account or inside that container.
- Kubernetes service-account tokens mounted inside a pod are reported as present; resolving what they can do is out of v1, like the rest of Kubernetes permission resolution.

### What a run covers **(call)**

- A run covers the whole machine, not one project. Credentials are machine-wide, so agent usage is added up across every project's session history.
- `fix` writes to the user-level Claude Code settings file, so a block applies in every project. Project-level and managed settings are read (to know what is already allowed or denied) but never written.

### What "the agent can reach it" means **(call)**

A credential is reachable when it exists on the machine and the agent's configuration does not deny the tool. Denying only the credential file is not enough to count as denied, because the tool can still pick the credential up from the environment or another source; that case is shown as "credential file blocked, tool still allowed" and the risk finding stands. The inventory shows one of three states per tool: denied, asks first, or allowed without asking. Risk findings are raised for anything not denied; "asks first" is shown on the finding because it lowers the risk. Flags given when the agent is launched (such as skipping all permission prompts) are not visible in configuration files and are not detected; the output says so.

## Scope of v1

| Area | Covered |
|---|---|
| Agents | Claude Code. Codex follows. **(call)** |
| Tools | `gh`, `aws`, `kubectl`, `docker`, configured MCP servers. **(call)** |
| `fix` target | Claude Code permission settings. **(call)** |

## How it works

Four kinds of component. The first two are the axes the project grows along, so each is behind a small interface; nothing else is abstracted.

1. **Scanners, one per tool.** Each does two things: *discover* from local files (always), and *resolve* effective permissions by asking the provider (online only).
   - `aws`: profiles from `~/.aws`; online, identity and attached policies.
   - `gh`: authenticated hosts from gh's configuration; online, token scopes.
   - `kubectl`: contexts from kubeconfig; a context is treated as production when its name or cluster matches `prod`. **(call)** Online resolution of Kubernetes permissions is out of v1. **(call)**
   - `docker`: whether the socket exists and is accessible to the user.
   - MCP: servers listed in the agent's configuration.
2. **Usage readers, one per agent.** Reads the session history the agent already writes to disk and extracts shell commands and MCP tool calls with timestamps. Commands are attributed to a tool by the first word (`aws`, `gh`, `kubectl`, `docker`) and, where it can be read from the arguments, to a profile or context.
3. **Rules.** Fixed checks in code that turn inventory plus usage into findings. No model, no scoring service.
4. **Fixers, one per agent.** Turn a finding into a concrete change to that agent's configuration.

### Usage rules

- **Unused:** no agent use in the window.
- **Rarely used:** fewer than 3 agent uses in the window. Reported at lower severity as "consider removing". **(call)**
- If session history covers less than the window, the finding says how many days of history were available instead of claiming "unused".

### Commands that do not name a profile or context **(call)**

- `aws` with no profile in the command or its inline environment counts as use of the default profile.
- `kubectl` with no context in the command cannot be attributed, because the current context at that moment is not recorded. If the agent never ran `kubectl` in the window, every context is unused. If it ran `kubectl` without naming a context, no context is called unused; the finding says "agent ran kubectl N times without naming a context" and the production-context risk finding still stands.
- The same principle applies everywhere: when use cannot be attributed, `agentctl` says so and does not claim "unused".

### Telling the developer's use from the agent's

The two-level removal depends on this, and it cannot always be known. **(call)**

- Shell history (zsh, bash) can only prove the developer **does** use a tool. It never proves absence: it often has no timestamps and misses consoles, SDKs, Terraform and IDEs.
- Only provider last-used data proves absence. In v1 that means AWS access keys, online.
- When developer use is **known recent** (dated shell history or provider data): recommend blocking the agent only. Shell history without timestamps counts as unknown.
- When provider data shows **no use by anyone** in the window: recommend revoking the credential.
- Otherwise developer use is **unknown**: recommend blocking the agent only, and add one line saying to revoke the credential if the developer does not use it either. Revocation is never recommended on a guess.

Consequence: in v1 the "nobody uses it, revoke" recommendation appears only for AWS access keys. For every other tool the result is "block the agent" plus the reminder line.

### Risk rules in v1

- AWS identity with AdministratorAccess or equivalent wildcard policy (online).
- AWS long-lived access key present on disk or in the environment.
- Docker socket reachable.
- Kubernetes production context reachable.
- GitHub token with scopes the agent's commands never needed (online). **(call)** Covers classic and OAuth tokens, which report scopes. Fine-grained and GitHub App tokens do not report scopes; they are listed with "permissions cannot be read" and no scope finding. Agent use is mapped to scopes coarsely, by `gh` command group (for example `gh pr`, `gh issue`, `gh repo` need `repo`; `gh workflow`, `gh run` need `workflow`).
- MCP server configured and never called.
- Agent permission configuration that allows unrestricted shell.

### Known limits

- Deny rules that target one profile or one context match on command text and can be sidestepped (for example by changing the default context first). `fix` prefers robust rules (block the tool, block reading the credential file) and labels narrower ones as best-effort.
- Offline mode cannot say what a credential can do, only that it exists and whether the agent used the tool.
- Mapping agent commands to provider permissions is coarse in v1: tool level for all, scope level for GitHub. Fine-grained AWS action analysis is not attempted.

## Safety requirements

- Secret values are never read into output, logs, or errors. Tokens are passed to provider calls only, by the provider's own SDK or CLI.
- Every provider call is read-only and has a timeout. The providers to be contacted are printed before any call is made.
- Online checks are never interactive. **(call)** A profile that would need a browser login, an MFA code, or an expired session to be renewed is skipped with a note and reported from files only.
- Read-only calls still appear in the provider's audit log (AWS CloudTrail, GitHub audit log). On a company account, permission queries from an admin credential can trigger security alerts. For that reason `agentctl` asks for confirmation before contacting any provider (owner's decision).
  - One prompt per run, listing every provider about to be contacted and noting the audit-log effect. Answering no continues offline. **(call)** The answer is not remembered between runs, so there is no state file. **(call)**
  - `--yes` skips the prompt; `--offline` makes it unnecessary.
  - With no terminal and neither flag, the command exits with status 2 and a message naming the two flags. It does not guess. **(call)**
- A failed or unauthorized provider call degrades that finding to the offline result with a note; it does not fail the run.
- `fix` shows the diff, requires an explicit yes, writes a backup beside the file, and never touches provider-side state.

## Testing

- Scanners and usage readers run against fixture home directories containing fake configuration and session files.
- Provider calls sit behind an interface with fakes; tests make no network calls.
- Rules are tested as pure functions from inventory plus usage to findings.
- `fix` is tested by comparing the resulting configuration file with an expected file, including the backup.

## Order of work

1. `inventory` and `doctor` for Claude Code with `aws` and `gh`, ending in a build other people can install. Try it on real machines; this is the test of whether the findings matter to people. There is no formal pass mark: the owner decides whether to continue to step 2. **(call)**
2. `kubectl`, `docker`, MCP scanners and their rules.
3. `fix` for Claude Code.
4. Codex usage reader and fixer.

## Left to the builder

- The exact location and format of Claude Code and Codex session history, and of Claude Code permission rules. These were not verified during design and must be checked against current documentation before coding.
- Which read-only AWS and GitHub calls to use, and whether to call the SDK or shell out to the installed CLI.
- Package layout, command-line library, output styling.
- The stable form of finding IDs.
