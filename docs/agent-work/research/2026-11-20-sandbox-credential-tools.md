---
date: 2026-11-20
topic: What nono, AgentVault and s-gw do and where each stops (gap check for agentctl)
git_commit: n/a
status: complete
---
## Answer
No single project unifies CLI + MCP + API + credentials with inventory/doctor/permission graph. nono is the closest and is the real threat to the hypothesis: it has per-command argv rules, credential proxy with phantom tokens, approval backends, signed audit, team profiles, no root. It stops at enforcement: it has no discovery/inventory, no risk scan, no permission graph, no usage-based least-privilege suggestions, and no managed credential lifecycle (it brokers existing secrets). AgentVault is a 3-star, 6-commit prototype (secret store + MCP/HTTP proxy), not a permission layer. s-gw is a credential-redemption/approval broker (handles, approve-then-run, output scrubbing) with a credential inventory UI, but no sandbox.

## Key findings
- nono repo moved: always-further/nono redirects to nolabs-ai/nono. 5,054 stars, 338 forks, Apache-2.0, created 2026-01-31, last push 2026-11-20, releases v0.80.0 (10-13), v0.81.0 (10-29), v0.82.0 (11-14), i.e. ~2-week cadence. Backed by nolabs-ai, "built by the team behind Sigstore"; funding not found. — https://api.github.com/repos/nolabs-ai/nono ; README https://github.com/nolabs-ai/nono
- nono enforcement: kernel sandbox; Landlock on Linux, Seatbelt on macOS (verified in tool-sandbox doc); Windows only via WSL2. No root, single binary, no container/daemon. — https://nono.sh/docs/cli/features/tool-sandbox ; https://localhosted.com/nono
- nono per-command control: `command_policies` with `intercept` rules matching argv (exact/prefix/contains), actions passthrough/respond/capture/capture_credential/approve/exec; `invocation_policy` allow/approve/deny. Commands reached via PATH shims; absolute-path calls denied unless allowed. Matching is literal (no `-f` vs `--force` normalization). The doc has no gh example; per-subcommand allow/deny is feasible by writing rules (inferred for gh). — tool-sandbox doc
- nono credentials: types local-socket, raw-file, proxy (aws_auth signs on host; sandbox sees placeholders), ambient (phantom token resolved at egress). Secrets stay in supervisor. Network: domain filtering and HTTP method/path rules. — tool-sandbox doc; README
- nono approval: terminal, webhook, chain backends (600s default). Audit: tamper-evident, verifiable, optional signing. Team: signed registry profiles and JSON policies in VCS. Sigstore verification of skills/hooks. Rust/Python/TS/Go bindings. — tool-sandbox doc; https://localhosted.com/nono
- nono limits: macOS Seatbelt cannot enforce per-port rules for command sandboxes; Linux daemonized callers need a writable cgroup base or are denied; bypass by absolute path is allowed if explicitly configured. I found no mention of MCP-server policy as a first-class tool, inventory, doctor or graph (absence in the pages I read; inferred, not exhaustively checked in source). — tool-sandbox doc
- AgentVault: 3 stars, 0 forks, 6 commits, created 2026-02-21, last push 2026-02-24, no releases. README says MIT but GitHub API reports no detected license and /LICENSE returns 404. Single author. — https://api.github.com/repos/DanielOu1208/agent_vault ; README
- AgentVault mechanism: Node 20+ app; AES-256-GCM per-secret DEK, DEK wrapped with PBKDF2 key from "machine identity" and stored in a file (keychain.ts is an encrypted file, not OS keychain). Proxy mode injects HTTP auth headers to a remote MCP server; serve mode exposes vault_* tools (git push, create issue) that run the action and return results. Policy: host allowlist, private-IP block, method/path. Lease approval via CLI/TUI/web. Hash-chained audit. Targets Cursor and Claude Code. OSes unstated (paths suggest macOS/Linux). No arbitrary CLI wrapping: only a fixed set of built-in vault tools. — README https://github.com/DanielOu1208/agent_vault
- AgentVault bypass (inferred): any same-user process can read vault.json and dek.enc and derive the key from machine identity; no sandbox stops the agent from other routes.
- s-gw: repo sgateway/s-gw, 16 stars, 1 fork, Apache-2.0 for TS broker/clients/docs, but distributed packages include a proprietary compiled Rust execution core. Created 2026-07-04, last push 2026-11-13, releases v0.1.20-0.1.22 (Aug-Oct 2026). Self-described "early preview", no independent audit. Company/funding/pricing not stated. — https://github.com/sgateway/s-gw ; https://s-gw.com/
- s-gw mechanism: agent sees typed handles (`s-gw:credential:prod-readonly`); local approval of agent+handle+command+env binding+cwd+target; runs approved command as child process with cleared env and the credential injected; output sanitized; local audit. Secrets in macOS Keychain, Linux Secret Service, Windows Credential Manager, 1Password or encrypted ledger. MCP stdio server for handle discovery. Guard mode swaps credential-like env values for handles. Secret detection scanner. Grants can be time-windowed. macOS, Linux, Windows (preview, experimental). Node 20+. Console shows credential inventory, policies, usage flow. — README, threat-model.md, detection.md in the repo
- s-gw limits (its own threat model): trusts the local OS account and approved executable; does not inspect commands spawned later by an approved interpreter/wrapper; it is not a sandbox, so an agent with its own shell can read env/files/dotfiles directly unless guard mode or an external sandbox is used (inferred; repo has docs/anthropic-sandbox.md suggesting pairing with Anthropic's sandbox, not read). — threat-model.md
- Root: none required for nono (stated). s-gw/AgentVault: none stated; Linux s-gw install needs `secret-tool` package (apt) and a user systemd service. — READMEs

## Feature matrix (Y yes, P partial, N no, ? not evidenced)
| Capability | nono | AgentVault | s-gw |
|---|---|---|---|
| Arbitrary CLI per-subcommand control | Y (argv rules, literal match) tool-sandbox doc | N (fixed vault_* tools) README | P (grant bound to exact command+args; allow/ask/deny rules) threat-model |
| CLI credential lifecycle (store, inject, rotate) | P (brokers/injects; no rotation evidenced) | P (store, inject; no rotation) | P (store, inject, time windows; no rotation evidenced) |
| MCP + CLI one abstraction | P (policy on commands/network; MCP not first-class) | P (MCP proxy + vault tools) | P (CLI exec + MCP handle server) |
| Tool inventory/discovery of installed+authenticated | N | N | P (credential inventory of enrolled handles; secret scanner; not tool discovery) |
| Permission graph | P (explicit can_use caller/callee edges, config only) | N | N |
| Credential-to-tool mapping | Y (per-command credentials) | P (per-profile) | Y (handle policy binds command) |
| Centralized/team policy | P (signed registry profiles, VCS JSON) | N | N (local) |
| Ephemeral/scoped credentials | P (phantom tokens, per-call sandbox; no cloud STS minting evidenced) | N | P (action-scoped grants, time window) |
| Human approval | Y | Y (lease) | Y |
| Audit | Y (tamper-evident, signable) | Y (hash chain) | Y (local log) |
| Sandbox of agent itself | Y | N | N |
| Needs root | N | not stated | not stated |

## Where each stops
- nono: policy is hand-written; it does not tell you what exists on the machine, what is over-privileged (e.g. AdministratorAccess), or learn least-privilege from usage. Not seen: doctor, inventory, graph visualisation, STS-style credential minting. This is the gap, but it is an add-on to an existing enforcement engine, not a new category.
- AgentVault: a prototype secret vault and proxy. Could become a permission layer only by rewriting most of it; low momentum.
- s-gw vs nono vs AgentVault: s-gw is a credential-redemption broker with a polished approval/inventory UI and no sandbox; nono is a sandbox with a credential proxy built in; AgentVault is a simpler, abandoned-looking variant of s-gw's idea (vault + proxy).

## Recommendation
Do not build another enforcement engine. If proceeding, position agentctl as the discovery/risk/least-privilege layer (inventory, doctor, usage-derived policy) that generates and audits nono-style policies, with s-gw/nono as possible backends. One-line reason: enforcement is covered by nono (active, 5k stars); the unserved piece is visibility and recommendation.

## Open questions
- Does nono have any discovery or "learn mode"/profile generation from observed access? (Not seen; check nono docs for profile learning and MCP handling.)
- nolabs-ai funding and whether it plans inventory features; s-gw company and the proprietary Rust core terms.
- Verified source reading was limited to READMEs/docs, not code; bypass analysis for nono (e.g. unsandboxed same-user processes) not done.

## Sources
- https://github.com/nolabs-ai/nono (README, fetched 2026-11-20); GitHub API repo/releases
- https://nono.sh/docs/cli/features/tool-sandbox
- https://localhosted.com/nono
- https://github.com/DanielOu1208/agent_vault (README, API)
- https://s-gw.com/ ; https://github.com/sgateway/s-gw (README, docs/threat-model.md, docs/detection.md, SECURITY.md)
