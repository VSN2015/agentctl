---
date: 2026-11-20
topic: Does a tool already exist that is a unified CLI + MCP + credential control plane for AI agents on developer machines (agentctl)?
git_commit: n/a
status: partial
---
## Answer
The gap is PARTIALLY CLOSED. Every individual layer (credential brokering, CLI/command proxying, network egress policy, endpoint inventory, native per-command allow/deny) now exists in at least one shipping or open-source product. No single product found combines (a) a machine-local inventory/doctor from the agent's point of view, (b) one policy across CLI + MCP + HTTP, and (c) usage-based least-privilege recommendations. Keycard for Coding Agents is the closest commercial overlap and is early access. Most evidence is vendor marketing/docs read via search summaries; I did not install or test anything.

## Key findings (V = verified from fetched/searched source text, I = inferred)
- Keycard for Coding Agents (GA-ish, "early access"): `keycard run` wraps the agent on a laptop, hooks Claude Code tool-approval APIs, brokered short-lived credentials bound to agent/dev/device/task, claims coverage of "any CLI, API, MCP, sub-agent", on-device gateway, SIEM telemetry. No inventory view described. V — https://keycard.ai/blog/announcing-keycard-for-coding-agents/
- GitGuardian `ggshield ai discover` / endpoint "Agent and MCP inventory": inventories Claude Code, Cursor, Codex, their MCP servers, what they can reach; observe-only; separate "AI Hooks" block secrets in agent interactions. Business/Enterprise plans. No per-agent credential-permission graph described. V — https://docs.gitguardian.com/endpoint-protection/agent-and-mcp-inventory
- StepSecurity Developer Machines: inventories credential files across ~14 tools (AWS, SSH, npm, Docker, kubeconfig), plaintext-vs-protected flag, no values collected; mentions AI agents only as the threat. Does not evaluate effective permissions (e.g. AdministratorAccess). V — https://docs.stepsecurity.io/developer-machines/credentials
- Other endpoint-inventory vendors (claims only, not fetched): Microsoft Defender local agent discovery (preview), Island agentic endpoint posture, Backslash, Boost Security, Token Security MCP discovery, SafeDep `vet ai discover`, SpecterOps Blacklight. I — search summaries.
- Closest OSS to `agentctl run`: airlock (calebfaruki; 18 stars, AGPL) proxies git/terraform/aws/ssh/docker via host daemon with per-agent command allowlist and per-module flag deny rules, NDJSON audit. V — https://github.com/calebfaruki/airlock . Also ghbrk (git/gh broker), claw-wrap, cplt (sandbox with gh destructive-op gating); I — search summary only.
- OneCLI (YC S26 per one source; 3.6k stars; Apache-2.0 with enterprise `ee/`): Rust HTTPS proxy, placeholder-to-real credential swap, host/path/method rules, approval, rate limits. HTTP-layer only; CLIs covered indirectly. V (stars/license) https://github.com/onecli/onecli ; I (rest).
- Claw Patrol (Deno, May 2026, alpha, MIT): WireGuard/Tailscale gateway, TLS-terminating, parses HTTP/SQL/Kubernetes, HCL rules, verdict chain with LLM/Slack approvers, placeholder credentials. Designed for VM-hosted agents, not laptops; no MCP mention. V — https://deno.com/blog/clawpatrol
- Kontext CLI (Show HN, Go): `kontext start --agent claude`, OIDC, RFC 8693 token exchange for short-lived creds, per-tool-call audit; allow/deny NOT yet live; Claude only. V — https://dev.to/kontext/i-built-a-credential-broker-for-ai-coding-agents-in-go-593a
- Infisical Agent Vault (open source, research preview): network-boundary credential proxy, agent never holds secret, time-bound sessions, `infisical agent-vault run`; recommends running vault on a separate machine. Credential-only; no CLI-subcommand policy or inventory. V — https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents
- StrongDM Leash (Apache-2.0, ~v1.1.7; StrongDM now part of Delinea): runs claude/codex/gemini in containers, eBPF-observed fs/network/exec, Cedar policies; syscall-level, not subcommand-semantic (`gh pr merge` is just an execve). V (broad) https://leash.strongdm.ai/ ; I (eBPF detail from third-party writeups).
- 1Password: Environments MCP server integrated with Codex (May 20 2026), Kiro (Jun 17), Cursor (Jul 30); secrets stay out of model context, JIT credentials, Unified Access / Credential Broker. Credential side only, vendor-specific. V — https://1password.com/blog/1password-trusted-access-layer-for-openai-codex
- Tailscale Aperture (GA Aug 26 2026): AI gateway in the tailnet holding LLM provider keys; extracts MCP/local tool calls from agents for visibility; finer MCP control planned. Model-API layer, not local CLIs. V — https://tailscale.com/blog/aperture-ga , https://tailscale.com/blog/aperture-private-alpha
- Teleport Agentic Identity Framework: short-lived credentials for agents, audit of tool calls/MCP, agent/MCP discovery. Infrastructure/enterprise-oriented; no laptop-local setup found. V (page-level) https://goteleport.com/docs/agentic-identity-framework/
- MCP scanners/gateways (Snyk Agent Scan, Invariant mcp-scan, Cisco MCP Scanner = pre-install vetting; Cloudflare MCP portals, Pomerium = runtime access proxies): MCP-only, do not touch CLIs/creds. I — third-party comparison https://www.getmaxim.ai/articles/best-mcp-security-tools-in-2026.md
- Okta/Auth0 Cross App Access: enterprise IdP-mediated OAuth for app-to-app/agent; not local. I. Arcade.dev, Composio, Astrix, Oasis, Lasso, Prompt Security, Daytona, E2B, container-use: no relevant results retrieved; NOT assessed (see Open questions). Hashicorp Vault agent offering: not searched.

### Native vendor controls (question 2)
- Claude Code: permission rules evaluated deny > ask > allow, first match wins; managed settings at top precedence, deny absolute; OS sandbox for Bash only (file tools, MCP, hooks outside it); `sandbox.failIfUnavailable`; hooks (PreToolUse) can run arbitrary policy code. V — https://code.claude.com/docs/en/permissions.md , https://code.claude.com/docs/en/sandboxing
- Codex: `.rules` files with `prefix_rule()` decisions allow/prompt/forbidden, admin enforcement via `requirements.toml`, `codex execpolicy check` for testing; docs label feature experimental. V (docs search); a mirror site disagrees on file paths (unreliable).
- Gemini CLI: TOML policy engine with `toolName`, `commandPrefix`/`commandRegex`, allow/deny/ask_user, priority tiers incl. admin dir; sandbox PR stops mounting host ~/.gemini. V — https://geminicli.com/docs/reference/policy-engine/
- Cursor: sandbox default for terminal, sandbox.json network allowlist (user + project), command allowlist; forum reports conflicting/silent-ignore behavior of allowlist under sandbox and docs say allowlist is not a security guarantee. V (forum + docs excerpts) https://cursor.com/docs/agent/security/run-modes
- Inference: native controls already deliver per-subcommand allow/deny per agent (`gh pr create` yes, `gh pr merge` no). That erodes the value of a CLI proxy as a pure allow/deny gate. What they do not give: one policy shared across four different syntaxes, cross-agent audit, credential isolation (agent still runs as the user and reads ~/.aws), effective-permission analysis. Prefix matching is also bypassable via wrapper/pipe/`bash -c` forms (I; classic weakness, not verified here per vendor).

### Scanner prior art (question 3)
- trufflehog/gitleaks are repo/filesystem secret finders; Prowler/ScoutSuite/CIEM analyze cloud accounts. None of these were checked in this pass beyond general knowledge. I.
- GitGuardian and StepSecurity (above) are the nearest laptop scanners; GitGuardian's "ai discover" frames it from the agent side but is inventory-only. GitGuardian blog "laptop as credential store" cites ~150 secrets per laptop average (vendor figure). No tool found that answers "this credential, as reachable by the agent, has AdministratorAccess" end-to-end; a search explicitly returned: "I did not find a dedicated tool that audits an agent's effective access end to end." V (absence in my search, not proof).

### Demand signal (question 4)
- PocketOS incident, Apr 24-25 2026: Cursor agent on Claude Opus 4.6 found an over-scoped Railway token, deleted production volume and its volume-level backups in one API call in ~9 seconds. Widely covered. V (many secondary outlets) https://www.techspot.com/news/112207-ai-coding-agent-running-claude-wiped-startup-database.html
- Earlier: Replit/SaaStr production DB deletion (Jul 2025); Amazon Kiro deleting a live environment (Dec 2025, one outlet). One tally: >=10 incidents across 6 tools Oct 2024-Feb 2026. V (secondary).
- Prompt-injection credential theft: Black Hat 2026 research, GitHub-issue injection to RCE in Claude Code reading GitHub/Anthropic tokens, CVE-2026-54316 (per eSecurityPlanet); Mozilla 0DIN PoC (Jun 25 2026); Backslash AGENTS.md exfiltration (Jul 2026); academic AIShellJack. V (secondary) https://www.esecurityplanet.com/threats/black-hat-2026-critical-flaws-found-in-anthropic-google-and-openai-coding-agents/
- The PocketOS root cause was an over-scoped token, exactly the `doctor` use case; it was a small startup, i.e. individual-developer-scale pain.
- Who pays: the money visibly follows enterprise/security-team buyers (Keycard funded and acquiring, GitGuardian/Island/Defender enterprise tiers, 1Password, Teleport, OneCLI enterprise license, StrongDM/Delinea). Individual-dev tools are mostly free OSS with tiny stars. Inference: pain is felt by individuals and small teams, budget sits with security teams. The only "survey" numbers found are vendor-sourced (Gravitee 21.9% of teams put agent OAuth creds in PAM; Sonar 25% regular agent use); treat cautiously.

## Options / tradeoffs
| Option | Pros | Cons | When to pick |
|---|---|---|---|
| Build full control plane | Unique combination | Keycard, 1Password, vendors crowd it; native controls erode proxy | Only with funding and enterprise GTM |
| Build `doctor` + inventory (agent-POV effective-permission scanner) only | Least covered; matches PocketOS-class incidents; cheap, local, no proxy | Inventory vendors (GitGuardian) could add permission analysis | Solo/OSS wedge |
| Compile one policy to native configs (Claude rules, Codex .rules, Gemini TOML, Cursor) | Uses vendors' enforcement; solves syntax fragmentation | Cursor enforcement weak; coverage lags | Cheapest enforcement story |
| Own proxy/broker | Real credential isolation | Many OSS clones (airlock, OneCLI, Kontext, Agent Vault, Claw Patrol) | Skip unless differentiated |

## Recommendation
Do not lead with the proxy/broker; it is the most crowded layer. Lead with `doctor` + permission graph (effective-permission analysis per credential, from the agent's reach), then emit policy into native agent configs.

## Ranked five closest competitors
1. Keycard for Coding Agents (commercial; wrapper + hooks + brokered creds + MCP/CLI/API claim; early access)
2. GitGuardian ai discover + AI Hooks (agent/MCP inventory on endpoint; no permission analysis or enforcement beyond secret blocking)
3. Claude Code / Codex / Gemini native policy (free, built in; per-agent only)
4. OneCLI (3.6k stars; credential proxy with policy; HTTP layer)
5. airlock (closest literal `agentctl run`; tiny, AGPL) -- Leash and StepSecurity are near misses (Leash is syscall-level; StepSecurity is credential-file inventory with no agent framing)

## Verdict
Gap: PARTIALLY CLOSED. Least-covered single feature: `agentctl doctor` and the permission graph, i.e. resolving which credentials an agent can reach to their effective cloud/GitHub permissions (e.g. AdministratorAccess) and risk-scoring them. Next least covered: usage-based least-privilege recommendations (no tool found does it).

## Open questions
- Not assessed: Arcade.dev, Composio, Smithery, Astrix, Oasis, Lasso, Prompt Security, Daytona, E2B, container-use, Anthropic sandbox-runtime internals, HashiCorp Vault agent, Okta/Auth0 for AI Agents product pages, Microsoft Defender local agent discovery detail.
- Does Keycard or GitGuardian roadmap include effective-permission analysis? Keycard pricing/availability is unknown.
- Does Claude Code prefix matching resist `bash -c`/pipe bypass? Not tested.
- Scanner prior art (Prowler, CIEM, trufflehog) not individually verified.

## Sources
- https://keycard.ai/blog/announcing-keycard-for-coding-agents/ (fetched)
- https://docs.gitguardian.com/endpoint-protection/agent-and-mcp-inventory (fetched)
- https://docs.stepsecurity.io/developer-machines/credentials (fetched)
- https://deno.com/blog/clawpatrol (fetched, 2026-05-21)
- https://dev.to/kontext/i-built-a-credential-broker-for-ai-coding-agents-in-go-593a (fetched)
- https://github.com/calebfaruki/airlock , https://github.com/onecli/onecli (fetched)
- https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents (search)
- https://leash.strongdm.ai/ (search)
- https://1password.com/blog/1password-trusted-access-layer-for-openai-codex (search)
- https://tailscale.com/blog/aperture-ga ; https://goteleport.com/docs/agentic-identity-framework/ (search)
- https://code.claude.com/docs/en/permissions.md ; https://code.claude.com/docs/en/sandboxing ; https://developers.openai.com/codex/rules ; https://geminicli.com/docs/reference/policy-engine/ ; https://cursor.com/docs/agent/security/run-modes (search)
- https://www.techspot.com/news/112207-ai-coding-agent-running-claude-wiped-startup-database.html ; https://www.esecurityplanet.com/threats/black-hat-2026-critical-flaws-found-in-anthropic-google-and-openai-coding-agents/ ; https://blog.gitguardian.com/laptop-as-credential-store (search)
