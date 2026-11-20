---
date: 2026-11-20
topic: Aembit, and feasibility of identity, short-lived creds, approval and bypass resistance for a local AI-agent tool gateway (macOS/Linux)
git_commit: n/a
status: partial
---
Legend: [V] verified from a source fetched/searched this session (URL given). [I] inferred or from my background knowledge, NOT verified this session. Provider limits as of 2026-11-20.

## Answer
Sound without a sandbox: credential brokering via credential helpers (aws credential_process, git, kubectl exec, docker) and a header-injecting proxy, short-lived down-scoped tokens for AWS/GitHub App/K8s, audit, and approval UX. NOT enforceable without a sandbox: anything that depends on the agent not calling the real binary, reading ~/.aws / keychain / env, or using curl directly. Same-OS-user identity checks (peer creds, code signing) tell you which process connected but not that it is "the agent"; the agent's shell can run anything the user can. Aembit is a server-side workload-IAM product whose MCP Identity Gateway pattern (agent holds only a gateway-scoped token; gateway injects the real credential) is the closest analogue, but it targets MCP over HTTP and cloud workloads, not local CLIs.

## Part 1 - Aembit
- MCP Identity Gateway sits between agents and MCP servers; agent connects to it as if it were an MCP server, gateway relays with credentials Aembit manages, held in memory and injected per request. [V] https://docs.aembit.io/get-started/use-cases/mcp-server-access (via search summary)
- Agent identity: user authenticates via an IdP (Google/Okta/Entra); Aembit Authorization Server issues a JWT access token (RS256/ES256) the agent presents; audience must match the gateway /mcp URL; 3s grace after expiry. Docs reviewed do NOT describe device/process/workload attestation for the agent beyond this token flow. [V] https://docs.aembit.io/user-guide/deploy-install/mcp-identity-gateway/reference-mcp-gateway
- Broader Aembit product: "attestation methods" (trust providers) exist for workloads, and the agent page says these extend to agentic AI but gives no specifics. [V] https://docs.aembit.io/get-started/use-cases/ai-agents/ . Detail of the workload attestation (cloud metadata, k8s, etc.) not verified.
- Credential injection: gateway adds credentials as header/query param per request; Credential Providers hold API keys, OAuth tokens, or temporary cloud creds; per-user creds via OAuth auth-code providers. Injection fails if a credential cannot go in a header/query param. [V] same pages.
- Deployment: Aembit-managed (`<tenant>.mcpgateway.aembit.io`, recommended, reaches only publicly reachable MCP servers) or self-hosted (own infra, Prometheus metrics). Policy evaluated by Aembit Cloud on every request (SaaS dependency). Aembit itself says the model adds latency and a single point of failure. [V] reference page above.
- Limits: no redirects, tool names prefixed per server, some MCP methods unsupported, no event if token rejected pre-trust. [V]
- Pricing: Agentic plans Starter free (3 agents, 1 gateway, 5 policies); Teams $20/agent/month (10-500 agents); Enterprise custom. Workload plans similar ($20/workload/month). Target: teams/orgs running agents or services in production, enterprise IAM buyers. [V] https://aembit.io/pricing/
- Listed supported clients: Claude Desktop, Gemini CLI, custom MCP clients. No mention of laptop/device requirements. [V] https://docs.aembit.io/get-started/use-cases/ai-agents/
- Applicability to local CLI tooling: [I] low. It covers MCP-over-HTTP and server workloads; I found nothing about intercepting gh/aws/kubectl on a laptop, nor any local sandbox or process attestation. The transferable idea is the pattern: agent token valid only at the gateway, gateway exchanges it per request for a short-lived, audience-scoped credential. Aembit's own Edge/Agent Proxy for workloads was not documented on pages read; not verified.

## Part 2 - Key findings per question

### Q1 Per-provider short-lived / down-scoped credentials
| Provider | Mechanism | Min TTL | Scoping granularity | Solo dev? |
|---|---|---|---|---|
| GitHub (App) | Installation access token; request `repositories`/`repository_ids` and `permissions` subset | fixed 1 h max (cannot be shorter) [V]; enterprise-scoped tokens cannot be scoped down [V] | per repo + per permission subset, per mint [V] | Yes, but needs the dev to create and install their own GitHub App (private key held by broker). Org-owned repos need app install approval [I] |
| GitHub (fine-grained PAT) | Manual creation in UI; options 7/30/60/90 d, custom up to 1 y, or none [V] (community discussion lists no 1-day option) | 7 days via UI presets [V]; no API to mint [I] | per repo + permission, fixed at creation, not per request | Yes but not ephemeral; cannot be minted by a broker |
| GitHub (OAuth device flow / GitHub App user token) | User token; GitHub App user tokens expire after 8 h by default [V, search snippet] | 8 h default | limited by app permissions and user access; not narrowable per request [I] | Yes |
| AWS STS AssumeRole | Session policy + DurationSeconds | 900 s; role chaining capped at 1 h [V] | inline policy + managed ARNs combined <=2,048 chars and packed-size limit [V]; session policy only narrows role | Yes (needs a base credential for the broker; IAM Identity Center or IAM user) |
| AWS IAM Roles Anywhere | cert-based CreateSession; `credential_process` helper | 900 s to 43200 s [V] | profile session policy; role scope | Yes with own CA + trust anchor (setup heavy). Private key can sit in macOS Keychain, PKCS#11/YubiKey or TPM [V]. Helper `serve` mode warns any local process can fetch creds; `update` writes ~/.aws/credentials to disk [V] |
| AWS IAM Identity Center | SSO login, `aws sso` cache, role creds | role session duration (typically 1 h) [I] | permission set; no per-request narrowing except via second AssumeRole+session policy [I] | Yes (if org uses it) |
| Kubernetes | TokenRequest (`kubectl create token --duration`) and exec credential plugin returning `expirationTimestamp` | requested via expirationSeconds; issuer may grant different value [V]; 10 min floor [I, unverified here] | ServiceAccount + RBAC; audience-bound; narrowing needs a pre-created least-priv SA/Role per scope | Yes on own clusters; managed clusters (EKS/GKE) use cloud IAM tokens instead (EKS presigned STS token ~15 min [I]) |
| Docker registries | Credential helpers; ECR `get-login-password` tokens 12 h [I]; GHCR uses GitHub tokens | provider dependent; ECR 12 h fixed [I] | ECR: IAM; Docker Hub: PAT with scope read/write/delete, no per-request [I] | Partly; Docker Hub PATs not short-lived |
| Cloudflare | API tokens created via API with `expires_on`/`not_before` [V] | arbitrary timestamp [V] | permission groups + resource scope per token [I] | Yes, but minting needs a long-lived parent token that can create tokens (a high-value secret held by broker) [I] |
| Vercel | Integration tokens expire, no refresh [V]; account tokens have dashboard expiry or never [V] | no documented per-request minting for individuals | team scope only [I] | Mostly no (static tokens); third-party Vault plugin mints with TTL [V, 3rd party] |
| Fly.io | `fly tokens create deploy --expiry` (default 20 years) [V]; macaroon-attenuated tokens, community mentions ~10.5 min practical validity [V, forum title] | short, user-set [V] | per-app deploy / per-org tokens [V] | Yes |
| Railway | Project token scoped to one environment, `Project-Access-Token` header [V] | no expiry setting found [V negative] | project+environment | Static only; cannot mint short-lived (not verified exhaustively) |

Providers that make ephemeral + per-request scoping impossible for an individual: Railway, Vercel (account tokens), Docker Hub, GitHub fine-grained PATs (no mint API [I]). Workaround: broker holds the long-lived secret and the gateway enforces scope by request filtering (proxy), which is policy-level, not credential-level, scoping.
Key point [I]: "down-scoped per request" is credential-enforced only for AWS (session policy), GitHub App (repo/permission subset), K8s (via pre-made SAs). Elsewhere it is gateway policy enforcement, and the real secret is in the broker.

### Q2 Injecting credentials into unmodified CLIs
| Mechanism | Pros | Cons |
|---|---|---|
| Env vars into child process | Universal, simple | Visible via /proc/<pid>/environ (same user) and `ps eww` on macOS [I]; child can print them; agent that spawns the process sees them if it controls the spawn |
| Credential helper hooks (aws `credential_process`, git credential helper, kubectl exec plugin, docker credential helper) | Native, short-lived creds returned on demand with Expiration [V for aws/k8s shapes]; no secret on disk | Helper runs as the same user, so anything that can run `aws` (or the helper itself) gets creds; helper must authenticate the caller, which it cannot reliably do (see Q3). Config files (~/.aws/config) are writable by the agent unless sandboxed [I] |
| Local HTTP(S) proxy with header injection / TLS termination | Real secret never enters the CLI process; one mechanism for curl/gh/terraform; per-request policy and audit; Claude Code's sandbox already does this: masks env var with sentinel, proxy substitutes only for allowed hosts, needs `tlsTerminate` [V https://code.claude.com/docs/en/sandboxing] | Needs custom CA trust per tool (Go, Java, Node, Python certifi differ) [I]; cert pinning and non-HTTP protocols (ssh, gRPC with pinned certs) fail; SigV4 signs the body/headers so AWS needs re-signing (proxy must hold creds and re-sign, not just inject a header) [I]; tools ignoring HTTP_PROXY bypass it [V for ssh/db drivers in sandbox docs] |
| Per-process filesystem view (mount namespace/bwrap, Seatbelt) | Gives the child only a synthetic ~/.aws etc. | Linux: bubblewrap [V]; macOS: Seatbelt (deprecated-but-working `sandbox-exec`) [V that Claude Code uses it]; requires the agent's commands to be launched inside it |
Verified helper facts: AWS credential_process JSON {Version, AccessKeyId, SecretAccessKey, SessionToken, Expiration} [V https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html]; K8s ExecCredential with expirationTimestamp caching [I/partly, fetched page truncated before section; general knowledge].

### Q3 Local agent identity
All [I] unless noted; none fetched this session except where stated.
- Unix socket peer creds: Linux SO_PEERCRED (pid, uid, gid); macOS LOCAL_PEERCRED (uid/gid), LOCAL_PEERPID (pid), LOCAL_PEERTOKEN (audit token, newer macOS). PID reuse races exist on pid-only checks; audit token is more robust.
- Code-signing checks: macOS can validate the peer's code signature via audit token (SecCode). Works for signed apps (Claude Desktop), weak for Node/Python/script-based agents (the binary is `node`, identity = interpreter, not the agent) and for any process that injects into/hosts the signed binary unless Hardened Runtime blocks it.
- Endpoint Security / audit: requires an ES system extension and Apple entitlement (com.apple.developer.endpoint-security.client), user approval + Full Disk Access; observes exec/open events but is detection not isolation (AUTH events can deny). Heavy for a solo project.
- Linux cgroups/namespaces: put the agent in its own cgroup/user namespace/ systemd scope and identify by cgroup path from SO_PEERCRED pid; meaningful only if the agent is launched into that scope by something the agent cannot bypass.
- SPIFFE/SPIRE: workload attestor uses kernel facts (uid, path, cgroup/k8s labels). On a laptop it reduces to the same peer-cred checks; adds SVID issuance, not stronger attestation.
- Same OS user: peer creds and code signing identify the connecting process, not intent. An agent with a shell can launch any binary as the same user, ptrace-less impersonation still works by simply running the allowed client binary or using its socket. macOS blocks cross-process injection for hardened/signed processes, and Linux Yama ptrace_scope=1 restricts ptrace to descendants, but neither stops "run the trusted client as a subprocess". Meaningful identity needs a different uid, a sandbox the agent starts in, or capability-bearing handles (inherited fd / per-session token injected only into the agent's process, which the agent can leak, but a sandbox can contain).

### Q4 Bypass
Verified from sandbox docs [V https://code.claude.com/docs/en/sandboxing]:
- Claude Code's sandbox: Seatbelt (macOS) / bubblewrap + netns + socat (Linux); network only through a hostname-allowlist proxy; writes limited to cwd/tmp; BUT reads allowed machine-wide by default incl. ~/.ssh and ~/.aws/credentials unless denyRead; sandbox covers only Bash and its children, not Read/Edit/Write/WebFetch, hooks, local MCP servers; model can retry with `dangerouslyDisableSandbox` unless `allowUnsandboxedCommands:false`; `excludedCommands` matching is textual.
Bypass paths if the agent has an unsandboxed shell [I, standard]: call real binary by absolute path; `curl` with token read from ~/.aws, ~/.config/gh/hosts.yml, ~/.kube/config, ~/.docker/config.json; `security find-generic-password` (macOS keychain; ACL prompt appears unless the calling app is trusted [V partly: security tool, partition list docs]); edit PATH, shell rc, ~/.aws/config to remove the helper; read env of sibling processes; `ssh-agent` socket use; browser cookie stores.
What closes holes (ranked) [I]:
1. Remove standing secrets from disk and env (no ~/.aws/credentials, no gh token in hosts.yml; use helpers returning short-lived creds from the broker).
2. Filesystem deny (Seatbelt/bwrap) for credential paths plus protected rc/config paths.
3. Network deny with only the broker proxy reachable (netns on Linux; Seatbelt "block all but proxy" on macOS [V]).
4. Separate OS user or container/VM: strongest; agent cannot read the user's home/keychain at all. Needs root to create the user (both OSes) and, for VMs, Virtualization.framework (macOS, no root) or KVM/Docker (Linux).
Requires root/system extension: separate user (root to create); macOS network filter by process (Network Extension / pf rules need root and entitlements); ES-based enforcement (system extension + entitlement); Linux: unprivileged userns+bwrap works without root on most distros but is disabled by default on Ubuntu 24.04+ via AppArmor restriction [I] and Claude docs mention `allowNestedUserNamespaces` weakening [V]. Seatbelt via sandbox-exec needs no root [I].
Conclusion: a CLI shim/proxy alone is advisory; enforcement exists only where the agent process tree is launched inside a confinement that the agent cannot modify, with credentials not reachable from inside it.

### Q5 Human approval the agent cannot forge
All [I]; no source fetched.
- Out-of-band channel the agent cannot write to: native macOS notification/dialog from the gateway daemon (a separate process), push to phone (ntfy/Pushover/Telegram), or a separate TTY the agent has no handle to. In-band prompts via the agent's own UI (MCP elicitation, Claude Code permission prompt) are controlled by the agent harness and can be auto-approved by it if misconfigured.
- Forgery vectors: agent synthesizes keystrokes (macOS CGEvent/AppleScript if it has Accessibility/Automation; `osascript` click; Linux xdotool/uinput on X11; Wayland blocks this), writes to the approval TTY (`/dev/pts/*` same user can write/TIOCSTI on older kernels), or reads a file-based approval token. Sandbox flag `allowAppleEvents` is documented as widening reach [V].
- Strongest: Touch ID/LAContext prompt or WebAuthn/FIDO2 key touch bound to the specific action hash (user presence cannot be synthesized by software), with the approval summary rendered by the trusted daemon, not the agent (avoid TOCTOU: sign the canonical request, bind to approval).
- Failure modes: approval fatigue (users click through after many prompts; mitigations: allowlist/classify low-risk, batch, time-boxed grants, show diffs and blast radius, rate-limit prompts); prompt injection that makes a risky action look routine; misleading summaries when the agent supplies the description; approving a command string whose effect differs (aliases, scripts invoking subcommands).

### Q6 Keychain / Secure Enclave / TPM
Partly [V] from Apple Dev Forums via search: keychain items have ACLs and a partition list; both must pass; `security find-generic-password -g/-w` can print secrets and is flagged by detection rules (Elastic) [V search summary].
- [I] File-based login keychain, unlocked at login: any same-user process in the ACL's trusted-app list or partition (e.g. same team ID / "apple:" partition, which includes Apple binaries like `security`) can read; otherwise a user prompt appears. An agent running Terminal-spawned shells runs under Terminal's/shell's context and can trigger prompts or invoke `security`. Items created with `-T` for a specific binary protect against other apps only until the user clicks "Always allow".
- [I] Secure Enclave: keys are non-exportable; protects key extraction, not use. Any process that may invoke the key (subject to ACL/biometric flags like `.userPresence`) can request signatures. With `biometryCurrentSet` + per-use Touch ID, use requires the human, which is meaningful against the same-user agent. Needs a signed app with keychain-access-groups entitlement; Secure Enclave is unavailable on Intel Macs without T2 [I].
- [I] TPM on Linux: keys sealed to TPM (tpm2-tools; AWS Roles Anywhere helper supports TSS2 key files and handles [V]) prevent exfiltration of the key file, but any process that can access /dev/tpmrm0 (typically `tss` group or user with ACL) and knows the auth value can use it. AWS doc itself warns: a TPM key with no password is usable by anyone with machine access [V].
- Net: hardware keys stop theft/copy of key material (e.g. to another machine) and survive disk reads, but not use-by-same-user-process unless each use needs a human factor or the key is only reachable from outside the agent's confinement.

### Q7 Least-privilege from usage
- iamlive: generates IAM policy from AWS CLI/SDK calls using client-side monitoring or embedded MITM proxy (needs CA trust); output typically uses Resource:"*" and needs manual narrowing [V search summary, https://github.com/iann0036/iamlive].
- IAM Access Analyzer policy generation: builds policy from CloudTrail; AWS says do not use for auditing; supports not Control Tower trails [V https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html]. Also AWS "IAM Policy Autopilot" open-source tool aimed at AI coding assistants exists [V title only: https://aws.amazon.com/blogs/security/iam-policy-autopilot-an-open-source-tool-that-brings-iam-policy-expertise-to-builders-and-ai-coding-assistants; content not read].
- audit2rbac: search returned nothing; from memory it builds RBAC roles from Kubernetes audit logs [I, unverified].
- Can CLI/MCP calls map to minimal permissions automatically? [I] For AWS yes at action level (API call to IAM action mapping is well defined, resource ARNs partly). For GitHub, calls map to REST endpoints whose required fine-grained permission is documented per endpoint; mapping is feasible but not shipped as a tool I verified. For MCP, tool name to downstream API is opaque. CLI string to provider API call needs interception at the HTTP layer (proxy) rather than argv parsing. Observed-usage policies are a floor from past behavior, over-fit to what was exercised, and miss rare-but-legit paths; recommend as suggestion generator reviewed by a human, not auto-applied.

### Q8 Vocabulary (one line each; usage in this space, [I] synthesis)
- Sandbox: OS-enforced confinement of a process (fs/net/syscalls) that the confined process cannot lift; the only component that actually prevents bypass.
- Proxy: an intermediary that forwards traffic (HTTP, CLI shim, MCP) and may inspect or rewrite it; enforces nothing if the client can route around it.
- Gateway: a proxy that is the single mandated ingress to a set of backends, adding authN/Z, policy and audit (Aembit's MCP Identity Gateway is this).
- Broker: a component that holds or mints credentials and issues scoped, short-lived ones to callers on request (credential brokering), separate from where the request is forwarded.
- Control plane: the policy/config/identity/audit layer that decides and records, as opposed to the data plane (proxies/sandboxes) that carries and enforces; "agentctl" as described = control plane + local gateway + broker, with enforcement dependent on a sandbox.

## Options / tradeoffs (enforcement posture)
| Option | Pros | Cons | When to pick |
|---|---|---|---|
| Advisory shim + credential helpers only | Easy, no root, great UX, real audit of cooperative paths | Trivially bypassed by a shell agent; false sense of safety | Detect/audit mode, trusted-agent workflows |
| Sandbox (Seatbelt/bwrap) + broker proxy | No root; closes env/file/network bypass for sandboxed shell; credentials masked [V pattern exists in Claude Code] | Agent harness tools outside the sandbox (Read/WebFetch/MCP stdio) remain; per-agent integration; Ubuntu userns limits | Default target |
| Separate OS user or VM/container | Strongest isolation, keychain unreachable | Root/admin setup, friction, file sharing, perf | High-risk agents, untrusted repos |
| ES/Network Extension system extension | Process-level visibility/denies | Apple entitlement, notarization, user approval; heavy | Probably not for a solo/OSS MVP |

## Recommendation
Position agentctl as broker + audit + approval daemon whose enforcement claim is conditional on running agents inside a sandbox it launches (Seatbelt/bwrap) with credentials removed from disk/env; run unsandboxed only in "advisory" mode and label it so. Reuse (do not rebuild) the Claude Code sandbox-runtime pattern of proxy masking if it fits. Use GitHub App tokens, AWS STS/Roles Anywhere, K8s exec plugins as first-class providers; treat Railway/Vercel/Docker Hub as proxy-enforced-only. Approval via Touch ID/phone push bound to a hash of the canonical request, rendered by the daemon.

## Open questions
- Aembit: how its workload trust providers/attestation and Edge/Agent Proxy work; whether any laptop deployment exists (not documented in pages read).
- K8s TokenRequest 10-minute floor and ExecCredential caching: confirm against official docs (not verified).
- GitHub fine-grained PAT 1-day option and OAuth device-flow token TTL: unverified.
- macOS: LOCAL_PEERTOKEN availability, current status of sandbox-exec deprecation, Keychain partition-list behavior for CLI-spawned processes: unverified; test on target macOS.
- Ubuntu userns restriction for bwrap: unverified.
- Cloudflare/Vercel/Railway scoping granularity beyond what was in search snippets.
- audit2rbac and IAM Policy Autopilot content not read.

## Sources
- https://aembit.io/pricing/ - pricing (fetched 2026-11-20)
- https://docs.aembit.io/get-started/use-cases/mcp-server-access and /ai-guide/mcp/identity-gateway/ - search summaries
- https://docs.aembit.io/user-guide/deploy-install/mcp-identity-gateway/reference-mcp-gateway - gateway reference (first 100k of 120k chars read)
- https://docs.aembit.io/get-started/use-cases/ai-agents/ - agent use case
- https://code.claude.com/docs/en/sandboxing - Claude Code sandbox docs (first 100k chars read)
- https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html - Roles Anywhere helper v1.8.6 (changelog dated 2026-11-04)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html ; https://github.com/iann0036/iamlive - policy generation (via search)
- GitHub docs: "Authenticating as a GitHub App installation" (docs.github.com), GitHub PAT docs/changelog, https://github.com/orgs/community/discussions/184161 - via search summaries
- AWS STS AssumeRole API reference and IAM quotas (docs.aws.amazon.com) - via search summaries
- https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_token/ and TokenRequest v1 API ref - via search summaries
- https://fly.io/docs/flyctl/tokens-create-deploy ; Cloudflare API tokens docs; Vercel short-lived tokens docs; Railway docs - via search summaries
- Apple Developer Forums threads on keychain ACL/partition list - via search summaries
