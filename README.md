# agentctl

`agentctl` shows, read-only and on your own machine, what an AI coding agent can reach: which cloud and code-hosting credentials exist, whether the agent is allowed to use them, how much it actually does, and what to tighten.

Supported today: one agent (Claude Code) and two tools (AWS and GitHub through `gh`). It runs on macOS and Linux, on laptops and on servers. It is a single static binary with no runtime dependencies, no telemetry, and no update check.

## Install

From source:

    go install github.com/VSN2015/agentctl/cmd/agentctl@latest

Or download an archive for your OS and CPU, check it, and unpack it:

    shasum -a 256 -c SHA256SUMS --ignore-missing
    tar -xzf agentctl_<version>_<os>_<arch>.tar.gz

(On Linux, `sha256sum -c SHA256SUMS --ignore-missing` does the same.) Each archive holds `agentctl`, `LICENSE`, and `README.md`.

## Use

    agentctl inventory    # what credentials exist and what the agent may do with them
    agentctl doctor       # the same, plus findings: what is risky and what to change

Flags for both commands:

| Flag | Meaning |
| --- | --- |
| `--offline` | make no network request; report only what files and environment show |
| `--yes` | answer yes to the online question |
| `--since <duration>` | how far back to count agent use (default `30d`; `12h`, `1d12h`) |
| `--json` | write one JSON document with `schema_version` instead of text |

`agentctl --version` prints the version.

## What it reads

It reads the files and environment where credentials are configured (for example `~/.aws`, the `gh` hosts file, environment variables), Claude Code settings and session history under every project, and your shell history. It reports names only (profile names, variable names, tool names, counts), never secret values: a value is not copied into output, logs, or error messages. Access key IDs are masked. It writes nothing to disk and keeps no state between runs.

## What it contacts, and when

By default it is online: it asks AWS (identity, attached policies, access key last-used) and GitHub (`gh api user`) what a credential can do. Every call is read-only and has a timeout. Before any call it lists the providers and notes that the requests appear in their audit logs, then asks once.

- Answer `n`, or pass `--offline`: nothing leaves the machine.
- `--yes`: skip the question.
- No terminal and neither flag: it exits with status 2 and names `--yes` and `--offline`.

A profile that would need a browser login, an MFA code, or a renewed session is skipped with a note and reported from files only. A failed or unauthorized call falls back to the file-only result with a note.

## Exit statuses

| Status | Meaning |
| --- | --- |
| 0 | success (`doctor`: no HIGH findings) |
| 1 | `doctor` found at least one HIGH finding |
| 2 | error, usage mistake, or no terminal without `--yes`/`--offline` |

The report goes to standard output; the prompt, notes about errors, and usage errors go to standard error. With `--json`, standard output carries only the JSON document.

## Output

On a terminal the output is coloured with symbols. When piped or redirected (for example over `ssh ... | cat`) it is plain ASCII.

## Running on servers

Credentials in the environment are reported by variable name. Online, AWS is resolved through the standard credential chain, so an instance or container role is reported even when there is no `~/.aws`. The answer is for the account `agentctl` runs as.

## Limits

- Deny rules in agent settings are advisory. Without a sandbox, an agent can usually reach a credential some other way; do not treat them as a security boundary.
- Launch flags (such as skipping all permission prompts) are not visible in configuration files and are not detected.
- Shell history can only show that you use a tool, never that you do not. Revoking a credential is recommended only when the provider itself shows no use in the window.
- Offline output cannot say what a credential can do. Mapping of agent commands to permissions is coarse (tool level; scope level for GitHub).
- `agentctl fix` is not available. These commands change no file.

## License

MIT. See `LICENSE`.
