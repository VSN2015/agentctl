---
date: 2026-11-20
topic: Verify file-format and API facts for a read-only Go scanner (AWS CLI, gh, Claude Code)
git_commit: n/a
status: complete
---
Claude Code docs read 2026-11-20 (pages quote versions up to v2.1.319). Base URL: https://code.claude.com/docs/en/ (append `.md` for raw markdown).

## 1. Claude Code settings locations and precedence: CORRECTED (user-local file does not exist)
- User `~/.claude/settings.json`; shared project `<proj>/.claude/settings.json`; project local `<proj>/.claude/settings.local.json`. `~/.claude/settings.local.json` is NOT an official file (docs list four scopes: user, shared project, project local, managed). Scanning it is harmless but unofficial.
- Managed file paths CONFIRMED: macOS `/Library/Application Support/ClaudeCode/managed-settings.json`; Linux and WSL `/etc/claude-code/managed-settings.json`; Windows `C:\Program Files\ClaudeCode\managed-settings.json` (legacy `C:\ProgramData\ClaudeCode\` no longer read).
- NEW: drop-in dir `managed-settings.d/*.json` next to that file (merged after managed-settings.json, alphabetical; hidden and non-.json ignored). Also `managed-mcp.json` there. Other managed sources (not files): macOS configuration profile domain `com.anthropic.claudecode`; Windows registry `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings` (also HKCU); server-managed (claude.ai console), cached at `~/.claude/remote-settings.json`.
- Project-local file location: since v2.1.211 it lives at the git repository root (not the start dir) when inside a git repo; older location (start dir) still read too. Shared `.claude/settings.json` is read from the session primary working directory.
- Also `~/.claude.json` (global config: MCP servers, per-project state, account); `CLAUDE_CONFIG_DIR` relocates the `~/.claude` folder.
- Precedence high to low: managed > `--settings` CLI > project local > shared project > user. List keys (e.g. `permissions.allow`) MERGE across files. A few security keys have exceptions.
- Settings files are strict JSON (no comments, no trailing commas).
- Source: https://code.claude.com/docs/en/settings.md , https://code.claude.com/docs/en/managed-settings.md

## 2. permissions object: CONFIRMED (with additions)
- Keys: `allow`, `ask`, `deny`, `additionalDirectories`, `blockReadsOutsideWorkingDirectories`, `blockWritesOutsideWorkingDirectories`, `defaultMode`, `denyInsteadOfPrompting`, `disableBypassPermissionsMode`, `disableAutoMode`.
- `defaultMode` values: `"default"` (alias `"manual"`), `"acceptEdits"`, `"plan"`, `"auto"`, `"dontAsk"`, `"bypassPermissions"`. `bypassPermissions` is valid. Since v2.1.257, `auto` and `bypassPermissions` do NOT take effect from project/local settings (user or managed only); before that, bypass worked from any file. A scanner should still flag them in any file but note effectiveness.
- Precedence: "Rules are evaluated in order: deny, then ask, then allow. The first match in that order determines the outcome, and rule specificity doesn't change the order." A deny `Bash(aws *)` beats allow `Bash(aws s3 ls)`.
- Source: https://code.claude.com/docs/en/settings-reference.md#permissions-defaultmode , https://code.claude.com/docs/en/permissions.md

## 3. Rule grammar: CONFIRMED / CORRECTED on deprecation
- `Tool` and `Tool(specifier)`. Bash forms: `Bash` and `Bash(*)` are equivalent, match all Bash. `Bash(aws)` = exact command `aws` only. `Bash(aws *)` = prefix with word boundary; matches `aws` and `aws s3 ls`, not `awsx` (a trailing ` *` also matches the bare command). `Bash(aws*)` (no space) also matches `awsx`. `Bash(aws:*)` is "an equivalent way to write a trailing wildcard" to `Bash(aws *)`; recognized only at the end of a pattern. NOT marked deprecated in current docs (CORRECTED: assumption that `:*` is deprecated is unsupported; the dialog now writes the space form). `*` may appear mid-pattern (`Bash(* --version)`).
- Bash matching strips wrappers `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`; allow rules split compound commands.
- Read/Edit path syntax: `//path` absolute from filesystem root (`Read(//Users/alice/secrets/**)`); `~/path` home; `/path` relative to settings source (project settings: primary working dir), NOT absolute; `path` or `./path` relative to cwd; `*`, `**` globs.
- MCP: `mcp__puppeteer` (whole server), `mcp__puppeteer__*` (wildcard, same), `mcp__puppeteer__puppeteer_navigate` (one tool). Rules with parentheses on `mcp__` are skipped as invalid. Deny/ask accept tool-name globs (`"*"`, `"mcp__*"`); allow only after literal `mcp__<server>__` prefix.
- Source: https://code.claude.com/docs/en/permissions.md

## 4. Transcripts: CONFIRMED
- `~/.claude/projects/<project>/<session>.jsonl`; `<project>` = working dir path with every non-letter/digit char replaced by `-` (e.g. `-Users-you-my-project`; Windows: 16-char hash). Subagent transcripts: `projects/<project>/<session>/subagents/` (same format). Also `<session>/tool-results/`, `<session>/mcp-tasks/`, `*.orphaned-<ts>-<suffix>.jsonl`, `*.jsonl.superseded-<ts>`.
- `CLAUDE_CONFIG_DIR` replaces `~/.claude` (settings, history, plugins, projects). `CLAUDE_CODE_PROJECT_DIR_NAME` (with CONFIG_DIR) overrides the `<project>` dir name. Project/local settings cannot set CLAUDE_CONFIG_DIR via `env`.
- `cleanupPeriodDays`: days to keep transcripts before a background sweep (after session start) deletes them; whole number, min 1, DEFAULT 30. `history.jsonl` (typed prompts) exists in `~/.claude`.
- Source: https://code.claude.com/docs/en/claude-directory.md , https://code.claude.com/docs/en/settings-reference.md#cleanupperioddays

## 5. Launch flags recorded on disk: UNVERIFIED
- No docs page found that says `--dangerously-skip-permissions`/`--permission-mode` are persisted. Docs say flags are "for one session" and "don't write to any file". `~/.claude/sessions/` holds one small file per running session (concurrency/crash detection); its content is undocumented. Treat flags as not reliably on disk; do not read them from there without inspecting a real file (out of scope here).
- Source: https://code.claude.com/docs/en/settings.md ; claude-directory.md

## 6. gh hosts.yml: CONFIRMED (structure) / CORRECTED (no macOS difference; refreshable tokens new)
- Config dir order (go-gh `ConfigDir`): `GH_CONFIG_DIR`, then `$XDG_CONFIG_HOME/gh`, then Windows only `%AppData%\GitHub CLI`, else `$HOME/.config/gh`. macOS uses `~/.config/gh` (no Library path). File: `<dir>/hosts.yml` (also `config.yml`).
- Structure (multi-account, gh >= 2.40):
```
github.com:
  git_protocol: https
  user: alice            # active user (legacy single-user key, still written)
  users:
    alice:
      oauth_token: gho_x # only if stored insecurely (no keyring)
    bob:
  oauth_token: gho_x     # host-level, mirrors active user's insecure token
```
  Top-level keys are hostnames. `users` map keys are accounts; value empty when token is in the system keyring. `oauth_token` present only when token not in keyring (plain text). Newer gh has "refreshable" credentials (extra per-user record) beyond this layout; exact keys UNVERIFIED (source references a "refreshable slot" but I did not extract key names).
- Source: https://github.com/cli/go-gh/blob/trunk/pkg/config/config.go , https://github.com/cli/cli/blob/trunk/internal/config/migration/multi_account.go , https://github.com/cli/cli/blob/trunk/internal/config/config.go

## 7. gh env tokens: CONFIRMED
- github.com (also `*.ghe.com`, `github.localhost`): `GH_TOKEN`, then `GITHUB_TOKEN`. Any other host (GHES): `GH_ENTERPRISE_TOKEN`, then `GITHUB_ENTERPRISE_TOKEN`. Env beats stored config. Then falls back to `hosts.yml` host-level `oauth_token`, then keyring.
- `GH_HOST`: default host for commands without a hostname; stored creds used if present else needs GH_TOKEN/GH_ENTERPRISE_TOKEN.
- Source: https://cli.github.com/manual/gh_help_environment , https://github.com/cli/go-gh/blob/trunk/pkg/auth/auth.go

## 8. gh api -i output: CONFIRMED layout; scopes header PARTLY UNVERIFIED
- Code: `fmt.Fprintln(w, resp.Proto, resp.Status)` then headers as `Name: v1, v2\r\n` (sorted, "Status" skipped), then `"\r\n"`, then body. So first line is like `HTTP/2.0 200 OK` (Proto is "HTTP/2.0" for h2, "HTTP/1.1" otherwise; split on first space, do not assume "HTTP/2"). Header lines end `\r\n`; a blank `\r\n` line ends them; body follows. 204 has no body. Non-2xx makes gh exit non-zero (still prints headers/body).
- `--hostname H` and `-i/--include` flags exist.
- X-OAuth-Scopes: GitHub docs say "`X-OAuth-Scopes` lists the scopes your token has authorized" (classic/OAuth). Docs say fine-grained PAT and GitHub App tokens use permissions, shown via `X-Accepted-GitHub-Permissions` (endpoint requirement). No official page states explicitly that X-OAuth-Scopes is absent for fine-grained/App tokens: UNVERIFIED as a documented guarantee; treat missing header as "not classic/OAuth or no scopes", and handle an empty value (classic with no scopes sends empty header).
- Env: `GH_PROMPT_DISABLED` "set to any value to disable interactive prompting"; `GH_NO_UPDATE_NOTIFIER` "set to any value to disable GitHub CLI update notifications" (checks every 24h, notice on stderr): CONFIRMED.
- Source: https://github.com/cli/cli/blob/trunk/pkg/cmd/api/api.go , https://cli.github.com/manual/gh_help_environment , https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps , https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api

## 9. AWS shared files: CONFIRMED
- config file: `[default]`, `[profile x]`, `[sso-session x]`, `[services x]`. credentials file: `[default]`, `[x]` (no `profile` word). Credentials file officially holds only `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token` (others there may be tolerated; do not rely on it). `[default]` does not inherit into other profiles.
- Keys: `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`, `role_arn`, `source_profile`, `credential_source` (Environment | Ec2InstanceMetadata | EcsContainer), `sso_session`, `sso_start_url`, `sso_region`, `sso_account_id`, `sso_role_name`, `web_identity_token_file`, `credential_process`, `mfa_serial`. `sso_session`, `sso_start_url` etc. confirmed as Go SDK constants (shared_config.go); the others are standard documented settings.
- Overrides: `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` (SDK env_config.go). Defaults `~/.aws/config`, `~/.aws/credentials`.
- Prefixes: `AKIA` = access key (long-lived); `ASIA` = temporary STS key ID. Also `ABIA` STS bearer token, `ACCA` context-specific credential.
- Source: https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html , https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html , https://github.com/aws/aws-sdk-go-v2/blob/main/config/shared_config.go

## 10. aws-sdk-go-v2 profile vs env creds: CONFIRMED
- `resolveCredentialChain` (config/resolve_credentials.go): `case sharedProfileSet:` (profile set via programmatic option such as `config.WithSharedConfigProfile`, checked among non-env "other" sources) is evaluated BEFORE `case envConfig.Credentials.HasKeys()`. So a programmatic profile wins over `AWS_ACCESS_KEY_ID`. But `AWS_PROFILE` in env alone does NOT count as "set": env keys win then.
- Recommended pattern for one named profile only: `config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(name), config.WithSharedConfigFiles(...)/WithSharedCredentialsFiles(...) if needed)`. Extra hardening (inference): to ignore env creds entirely, unset `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN`/`AWS_WEB_IDENTITY_TOKEN_FILE` in the process before load. No separate documented "profile only" option beyond that.
- Source: https://github.com/aws/aws-sdk-go-v2/blob/main/config/resolve_credentials.go , config/load_options.go

## 11. DMI sys_vendor: UNVERIFIED (official docs)
- AWS "Detect whether a host is an EC2 instance" page covers instance identity doc, system UUID, VM generation ID, not `sys_vendor`. Commonly known (not verified here): Nitro `sys_vendor` = `Amazon EC2`; older Xen reports `Xen` (and `/sys/hypervisor/uuid` starts `ec2`). Treat `Amazon EC2` as sufficient-but-not-necessary, and also check `board_vendor`/`bios_vendor`.
- Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html

## 12. YAML module: CONFIRMED
- `go.yaml.in/yaml/v3` latest `v3.0.6` (2026-10-13), origin github.com/yaml/go-yaml. `gopkg.in/yaml.v3` latest `v3.0.1` (2022-05-27); upstream github.com/go-yaml/yaml is archived with a "THIS PROJECT IS UNMAINTAINED" README. Use `go.yaml.in/yaml/v3` (drop-in API).
- Source: https://proxy.golang.org/go.yaml.in/yaml/v3/@latest , https://api.github.com/repos/go-yaml/yaml

## 13. cobra: CONFIRMED
- `github.com/spf13/cobra` latest `v1.10.2` (2025-12-03). v1.10.2 has: `Command.SilenceUsage`, `Command.SilenceErrors` (bool fields), `(*Command).ExecuteC() (*Command, error)`, `SetFlagErrorFunc(func(*Command, error) error)`, `SetVersionTemplate(string)`, `CompletionOptions.DisableDefaultCmd`.
- Source: https://github.com/spf13/cobra/blob/v1.10.2/command.go , completions.go , https://proxy.golang.org/github.com/spf13/cobra/@latest
