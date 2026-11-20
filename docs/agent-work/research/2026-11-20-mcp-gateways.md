---
date: 2026-11-20
topic: Do ToolHive, Docker MCP Gateway, ContextForge, agentgateway, MS Agent Governance Toolkit treat CLI + MCP as one governed tool model on a dev laptop?
git_commit: n/a
status: partial
---
## Answer
No. None of the five treats CLI tools and MCP servers as one "Tool" with one policy/credential/audit model on a developer laptop. Four are MCP-centric gateways (ToolHive, Docker, ContextForge, agentgateway). Microsoft AGT is the closest: it hooks Claude Code's PreToolUse, so it can see non-MCP tool calls, but it has no tool registry, credential broker, or backend-independent Tool abstraction (verified only at the page-summary level; see caveats). The hypothesis (MCP gateways govern only MCP traffic) is confirmed for Docker and ToolHive from vendor docs; for ContextForge and agentgateway the CLI path exists only as "wrap a stdio MCP server", not "govern a CLI".

## Key findings
- ToolHive: runs MCP servers in isolated containers on desktop (Docker/Podman) or via a K8s operator; OIDC/OAuth; OTel + Prometheus; encrypted secrets. Cedar policy, verified MCP-only: governs call_tool / get_prompt / read_resource, tool args visible as `arg_*`; docs describe no non-MCP governance. — https://docs.stacklok.com/toolhive/concepts/cedar-policies , https://github.com/stacklok/toolhive
- ToolHive "no local credentials" is a design stance (servers get none), not inventory of host creds. Page does not mention scanning ~/.aws etc. — https://github.com/stacklok/toolhive
- Docker MCP Gateway: `docker mcp` CLI plugin; one endpoint (stdio default, sse/streaming); each server in a container; secrets in Docker Desktop secrets store; per-profile tool allowlists; no policy engine described in repo README. — https://github.com/docker/mcp-gateway
- Docker org governance: Cedar policies, explicitly "MCP activity only"; direct in-sandbox MCP connections are governed by network policy instead; no shell/CLI policy described; without org policy the gateway permits everything; requires paid subscription. — https://docs.docker.com/ai/sandboxes/governance/access-controls/mcp/ , https://docs.docker.com/ai/sandboxes/
- Docker Sandboxes (`sbx` CLI): each agent in its own microVM with private Docker engine; a host-side credential proxy injects secrets into outbound API requests so the VM sees placeholder values; network proxy policy; free local, paid governance/cloud. Vendor-stated claims, via search summaries of docs.docker.com (not independently verified). — https://docs.docker.com/ai/sandboxes/security/workspace/ , https://www.docker.com/blog/why-microvms-the-architecture-behind-docker-sandboxes/
- ContextForge: gateway/registry over MCP, A2A, REST, gRPC; REST->MCP and gRPC->MCP adapters; `mcpgateway.translate` wraps a stdio command (e.g. `uvx mcp-server-git`, `docker run`) to SSE/streamable HTTP; JWT/Basic/OAuth, RBAC, SSO; 40+ plugins; OTel, SIEM compose; Postgres/Redis/Helm. README names no OPA/Cedar. translate wraps MCP servers speaking stdio, not arbitrary CLIs (inferred from README; not tested). — https://github.com/IBM/mcp-context-forge
- agentgateway: Linux Foundation proxy for LLM, MCP, A2A traffic; JWT/API key/OAuth; CEL RBAC; MCP targets include stdio (cmd+args, e.g. npx/docker), and OpenAPI targets via MCP target type; standalone YAML or K8s Gateway API. Not CLI wrapping beyond stdio MCP. OpenAPI->MCP detail not verified. — https://github.com/agentgateway/agentgateway , https://agentgateway.dev/docs/standalone/latest/integrations/mcp/servers/stdio/
- Microsoft AGT: MIT, in-process SDKs (Py/TS/.NET/Rust/Go) intercepting tool calls; YAML rules with deny/require_approval, OPA and Cedar listed as options; MCP Security Gateway spec (tool poisoning, drift, typosquat, hidden-instruction scanning; 127 conformance tests); command denylist and "pre-dispatch command policy" in runtime/K8s sandbox example; first-party Claude Code plugin with PreToolUse allow/deny/review, policy at ~/.claude/agt/policy.json, audit at ~/.claude/agt/audit-log.json. — https://github.com/microsoft/agent-governance-toolkit , https://microsoft.github.io/agent-governance-toolkit/packages/claude-code-governance/
- AGT unverified: whether the Claude Code plugin matches Bash command strings, per-subcommand granularity, default rules, credential brokering (README describes identity via SPIFFE/DIDs, not secret injection). The README claims "10/10 OWASP" while its own badge says "7 Full, 3 Partial". — same sources
- Maturity (GitHub API, 2026-11-20): ToolHive 2.3k stars, Apache-2.0, v0.66.0 (2026-11-16), Stacklok; Docker mcp-gateway 1.6k, MIT, v0.44.3 (2026-10-26), Docker; ContextForge 4.9k, Apache-2.0, v1.1.1 (2026-11-10), IBM; agentgateway 6.3k, Apache-2.0, v1.7.0 (2026-10-27), Linux Foundation (solo.io origin: inferred); AGT 6.6k, MIT, v4.1.0 (2026-06-09), Microsoft, last push 2026-11-20.

## Feature matrix (yes / partial / no)
| Capability | ToolHive | Docker (gateway+sandboxes) | ContextForge | agentgateway | MS AGT |
|---|---|---|---|---|---|
| Local developer-machine deploy | yes (desktop/CLI) [repo] | yes (Desktop/sbx) [repo] | partial (pip/docker, server-oriented) [repo] | partial (single binary, YAML; inferred) | yes (pip, Claude plugin) [pkg page] |
| K8s / enterprise deploy | yes [repo] | partial (org policy, paid) [docs] | yes [repo] | yes [repo] | partial (guides) [repo] |
| MCP governance | yes | yes | yes | yes | yes (MCP gateway spec) |
| Policy language | Cedar [docs] | Cedar (org, MCP only) [docs] | none named [repo] | CEL [repo] | YAML; OPA/Cedar listed [repo] |
| Per-argument policy | yes (arg_*) [docs] | unverified | unverified | unverified | unverified |
| Wrap arbitrary CLI as tool | no (containers/pkg-managers) [repo] | no [repo] | partial (stdio MCP via translate) [repo] | partial (stdio cmd, MCP only) [docs] | partial (Bash hook; depth unverified) |
| REST/OpenAPI -> MCP | no found | no found | yes [repo] | partial (OpenAPI target) [docs] | no found |
| CLI and MCP as one Tool model | no | no | no | no | no (no registry; hooks only) |
| Knows host creds (~/.aws, ~/.kube, gh) | no [repo] | no (proxy injects API creds in sandbox; no inventory) | no | no | no evidence |
| Credential broker/injection | partial (secrets store) | yes for sandbox API keys; partial for MCP [docs] | partial (token store) | partial (auth passthrough; unverified) | no evidence |
| Approval flow | no evidence | no evidence | no evidence | no evidence | yes (require_approval / review) |
| Audit / observability | yes OTel/Prom | partial (logs/tracing) | yes OTel/log viewer | yes (observability, per README) | yes (audit-log.json) |
| Inventory / risk scan / permission graph | no | no | no | no | partial (MCP tool scanning, red-team scan) |
| Isolation primitive | yes (containers) | yes (microVM) | no | no | partial (recommends containers) |

## Direct answers to specific questions
- ToolHive generalized to CLI? Inferred: plausible but nontrivial. Its pieces (container isolation, secrets, Cedar authz, OTel) are reusable, but Cedar entities/actions are MCP-method-specific and enforcement is an HTTP proxy in front of MCP. A CLI would need an MCP shim or a new interception layer.
- Docker direction: yes, MCP is a first-class managed layer (catalog, gateway, profiles, Cedar org policy). Useful primitives for agentctl: microVM sandbox, host-side credential proxy, network policy, ephemeral containers. Governance stops at MCP/network/filesystem; CLI-level policy not described. Org governance is paid.
- ContextForge: MCP-centric registry that is broader on protocols (REST/gRPC/A2A), enterprise/server oriented; not a laptop control plane.
- agentgateway: generic data-plane proxy for LLM/MCP/A2A; broad but traffic-based; no concept of local shell tools.
- Microsoft vs local gateway: AGT is a library/policy engine embedded in agents with hook plugins; a gateway intercepts traffic. AGT is the only one reaching non-MCP tool calls, but is not a registry/broker.

## Recommendation
A gap appears to exist: a unified Tool abstraction (CLI + MCP + HTTP) with credential brokering and local-credential inventory is not shipped by any of the five. Closest threat is AGT's Claude Code plugin; inspect its source before committing. Reasoning is inferred from docs, not hands-on testing.

## Open questions
- Does AGT's Claude plugin parse Bash commands per subcommand/argument, and what does default-policy.json contain?
- Docker docs: any CLI/exec policy in sbx beyond network/filesystem/MCP? Does sbx support Codex/Cursor?
- agentgateway OpenAPI-to-MCP config and per-tool CEL specifics.
- Docker mcp-gateway interceptors (not in README; not checked).

## Sources
- https://github.com/stacklok/toolhive , https://docs.stacklok.com/toolhive/concepts/cedar-policies (read 2026-11-20)
- https://github.com/docker/mcp-gateway , https://docs.docker.com/ai/sandboxes/ , https://docs.docker.com/ai/sandboxes/governance/access-controls/mcp/ , Docker sandbox security pages via search summary
- https://github.com/IBM/mcp-context-forge
- https://github.com/agentgateway/agentgateway , https://agentgateway.dev/docs/standalone/latest/integrations/mcp/servers/stdio/
- https://github.com/microsoft/agent-governance-toolkit , https://microsoft.github.io/agent-governance-toolkit/packages/claude-code-governance/
- GitHub REST API repo/releases metadata, 2026-11-20
Note: WebFetch results are small-model summaries of pages; treat details as unverified against raw source.
