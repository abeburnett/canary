# Codex gate facts — 2026-09-26

## Status: stop before implementation

Rebased `program/2026-09-26-canary-codex` onto `f8c5b87`. The content of facts
commit `a8c6b88` is preserved as rebased commit `9e081b4`. All five original
requests are settled by the new baseline; the old manifest reproduction is
superseded by the successful checks below.

**The complete classifier isolation requirement is not proven.** A custom
model catalog can produce a tool-free request in the local experiment, but
the tested instruction-suppression settings still load global `AGENTS.md`.
An empty temporary home avoids that file; that is a fixture condition, not
proof of suppression. Enforced administrator configuration and approved-login
operation remain unverified. This is not a claim that every possible Codex
configuration is impossible to isolate. It is a refusal to certify an
unproven one or implement the classifier on that assumption.

**A newly demonstrated interface mismatch also requires Claude's decision:**
Codex accepts deny JSON on stdout with exit **0**. JSON on stdout with exit
**2**, without a stderr reason, **fails open**. Architecture lines 105–109
currently say to print host deny JSON and exit 2. The existing
`deny(reason) -> (stdout, exit_code)` interface can express the working JSON /
exit-0 protocol without expansion, but the blanket exit-2 instruction must
be corrected before implementing against it.

No host adapter, classifier backend, or plugin was added. No real hooks,
settings, credentials, system policy, other worktrees, or published state
were changed.

## Evidence and reproducibility

Installed native binary:

```text
/Users/abrahamburnett/.local/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex
codex-cli 0.157.1
```

Official source inspected at tag `rust-v0.157.1`, commit
`36650394c5b38c2990ccf2a3457165ca3e9d9726`, from
[openai/codex](https://github.com/openai/codex/tree/36650394c5b38c2990ccf2a3457165ca3e9d9726).
Source observations below are distinguished from executed binary evidence;
upstream tests were read, not represented as tests executed here.

Temporary evidence directory: `/private/tmp/canary-codex-probes/`.
`probe.py` launches the installed binary; `mcp.py` is a harmless stdio MCP
server; `verify.py` checks captures and marker files. Each case has its own
`home`, `home/.codex`, `workspace`, and `tmp`. The child receives an explicit
minimal environment, including fake HOME, CODEX_HOME, XDG paths and TMPDIR,
not the coordinator's environment or credentials. Login shells and shell
snapshots are disabled. No API key or auth file was copied.

A loopback HTTP server returns deterministic Responses API messages and tool
calls, captures actual outgoing request bodies, and never contacts a model
service. These are **real installed CLI / hook / tool executions with a fake
model endpoint**, not a live model or paid-login acceptance test. Request
bodies are captured without HTTP headers. Tools are inspected in both the
ordinary top-level `tools` array and `input[].type == "additional_tools"`;
code-mode tools nested in descriptions also count.

Representative command shape:

```text
<installed native binary> --no-daemon --dangerously-bypass-hook-trust exec \
  --strict-config --skip-git-repo-check --ephemeral --json --color never \
  'Return PROBE_DONE without using tools.'
```

The hook-trust flag is deliberately used **only for synthetic hooks in fake
homes**. It does not prove managed installation or ordinary trust enrollment.
The server deliberately emits calls despite that inert prompt, so prompt
obedience cannot substitute for tool exclusion. Hook cases use
`workspace-write`; classifier cases use `read-only`.

The initial shell allow control hit nested macOS sandbox denial. It is not
counted as a successful allow. The shell/patch allow and failure matrix was
then executed outside the coordinator's outer sandbox, retaining the child
Codex workspace sandbox and temporary-only fixtures. The allow controls
created their markers. No sudo or machine configuration changes were used.

Executed verification:

```text
python3 /private/tmp/canary-codex-probes/verify.py
44 evidence assertions passed
```

Final harness SHA-256 values (earlier captures were made while extending the
harness; the final version retains their cases):

```text
probe.py          de75a35060f06254ba4fab56ad7503e1165b417a45c61930cdb057aff0fc9560
mcp.py            8a571272a1090447b685788c1e5dccd9bc66e616da0e7a54289d734151888d8a
verify.py         2cddd9916702f2839c2ac8c7db0eef83b3cc9cba826e9795b00f9f0969f5fce0
zero-catalog.json e6a9f130bbfbd615da466509b9f52ae8916ecadebca94dc957aa75932ebf103c
isolated.toml     0490a2079cbd393af3aa556169657ddcea439fc2575bbb5ad6d2710dd656dfee
```

Raw evidence is local temporary data, not a committed fixture suite. The
important observed payloads, results, and limitations are recorded below.

## 1. Discovery and initial context

Official guide: [Build skills](https://learn.chatgpt.com/docs/build-skills).
Short quote: “Codex supports symlinked skill folders”.

Installed-version source:
[host_roots.rs](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/ext/skills/src/host_roots.rs),
[host skill loader](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/ext/skills/src/loader/host.rs),
[bundled skills](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/skills/src/lib.rs),
[plugin store](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/core-plugins/src/store.rs).

| Channel | Verified source behavior | Executed capture |
|---|---|---|
| User skills | `$HOME/.agents/skills` and legacy `$CODEX_HOME/skills` | Both synthetic descriptions entered first request |
| Bundled skills | `$CODEX_HOME/skills/.system`, extracted embedded assets | Fresh-home baseline contains bundled skill instructions |
| Repository skills | `.agents/skills` from project root through cwd; project config-folder `skills` roots also supported | Root, child, and cwd `.agents/skills` metadata captured |
| System skills | Skills under the system configuration folder, normally `/etc/codex/skills` | Source verified; no system fixture installed |
| Plugin skills | Enabled plugin roots plus manifest-derived roots; cache `$CODEX_HOME/plugins/cache/<marketplace>/<plugin>/<version>` | Source verified; plugin installation not exercised |
| Additional roots | Host-supplied extra roots and selected executor capability roots exist | Source verified; not exercised |
| Resource skills | Host extension supports cloud/resource-backed skills, not just local paths | Source verified; remote/orchestrator integration unverified |

`discovery-fixtures/request-01.json` contains HOME, legacy, repository, and
symlink-target description sentinels before any tool call. The full body
sentinel is absent. Thus description exposure precedes file-read hooks.
User/repo/admin directory symlinks are followed by the source loader;
bundled-system directory symlinks are ignored. The user symlink case was
also observed at runtime. A filesystem-only fixed list cannot claim coverage
of arbitrary resource-backed skills.

Source supports skill cache invalidation and refresh; official docs describe
automatic reload. **[UNVERIFIED runtime]** Mid-session file mutation/reload
was not tested. Do not translate startup captures into that stronger claim.

### Agent instructions

[agents_md.rs](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/core/src/agents_md.rs)
walks project root to cwd, preferring `AGENTS.override.md`, then `AGENTS.md`,
then configured fallback names. Default root marker is `.git`; no root marker
means cwd only. Explicit empty root-marker configuration stops ancestor
traversal. Untrusted projects are skipped.

`hierarchy-fixtures/request-01.json` verifies trusted repository root
instructions, child override instructions, and a leaf `GUIDE.md` fallback;
the instruction outside the repository is absent. The fake CODEX_HOME's
`AGENTS.md` is separately loaded as global instructions. Project byte budget
zero suppresses project instructions but **does not suppress that global
file**, including with `--ignore-user-config --ignore-rules`.

**[UNVERIFIED]** Exhaustive runtime coverage of plugin manifests, configured
extra roots, remote/executor/orchestrator sources, global override precedence,
and all fallback/root-marker combinations. Source-backed paths above are
facts; they are not a completed exhaustive discovery acceptance test.

## 2. Hook payloads, denial and failures

Official guide: [Hooks](https://learn.chatgpt.com/docs/hooks).
Short quote: “not a complete enforcement boundary”.

### Actual captured input

This shell payload is copied from `shell-deny/hook-input.json`; only random
session/turn/tool IDs are shortened here. `transcript_path` really is null
under this ephemeral run, and `permission_mode` really is
`bypassPermissions` with approval policy `never`. That string does not mean
the filesystem sandbox was disabled.

```json
{
  "session_id": "<session UUID>",
  "turn_id": "<turn UUID>",
  "transcript_path": null,
  "cwd": "/private/tmp/canary-codex-probes/shell-deny/workspace",
  "hook_event_name": "PreToolUse",
  "model": "gpt-6-astra",
  "permission_mode": "bypassPermissions",
  "tool_name": "Bash",
  "tool_input": {
    "command": "/usr/bin/touch /private/tmp/canary-codex-probes/shell-deny/workspace/marker"
  },
  "tool_use_id": "exec-<UUID>"
}
```

`patch-deny/hook-input.json` has the same common envelope, with:

```json
{
  "tool_name": "apply_patch",
  "tool_input": {
    "command": "*** Begin Patch\n*** Add File: /private/tmp/canary-codex-probes/patch-deny/workspace/marker\n+probe\n*** End Patch"
  }
}
```

`mcp-deny-approved/hook-input.json` has the common envelope, with:

```json
{
  "tool_name": "mcp__probe__echo",
  "tool_input": {"message": "MCP_SENTINEL"}
}
```

The MCP control explicitly approves only this synthetic echo tool using
`[mcp_servers.probe.tools.echo] approval_mode = "approve"`. Without that
setting, policy `never` separately rejected the call; that earlier attempt
is not counted as an allow control. With it, allow writes the MCP call log
and deny does not. Nested `functions.exec` calls reach these canonical hooks.
Do not parse the outer JavaScript wrapper as the hook's shell command.

### Executed decision matrix

Each case receives a real call from the deterministic endpoint. All CLI
sessions finish normally; session exit status is not the hook decision.

| Hook behavior | Case | Tool executed? |
|---|---|---|
| Empty stdout, exit 0 | `shell-allow-real` | Yes: marker exists |
| Valid deny JSON, exit 0 | `shell-deny` | No; model receives blocking reason |
| Nonempty stderr reason, exit 2 | `shell-stderr-deny` | No; model receives blocking reason |
| Valid deny JSON, exit 2, empty stderr | `shell-json-exit2` | **Yes** |
| Missing hook executable | `shell-missing` | **Yes** |
| Python exception, exit 1 | `shell-crash` | **Yes** |
| Malformed JSON `{broken`, exit 0 | `shell-malformed` | **Yes** |
| Empty stdout, exit 0 | `patch-allow` | Yes: patched file exists |
| Valid deny JSON, exit 0 | `patch-deny` | No: patched file absent |
| Empty stdout, exit 0 | `mcp-allow-approved` | Yes: MCP call log exists |
| Valid deny JSON, exit 0 | `mcp-deny-approved` | No: MCP call log absent |

Working stdout protocol, with **exit 0**:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"CANARY_PROBE_DENY"}}
```

The exact-version
[PreToolUse parser](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/hooks/src/events/pre_tool_use.rs#L197)
corroborates the experiment: exit 0 parses JSON; exit 2 checks stderr;
missing reason, other exit codes and execution errors produce failures,
not denial. Required managed declaration load failures have a separate
startup error path. Do not generalize optional-hook runtime tests into proof
of all managed failure behavior.

### Configuration and enforcement limits

[Hook discovery source](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/hooks/src/engine/discovery.rs)
first appends managed requirements, then visits configuration layers low to
high, loading adjacent `hooks.json` followed by inline TOML hooks, then
plugin hooks. Matching hooks accumulate; they do not simply replace previous
ones. User hooks have trust/state controls; managed hooks have separate
mandatory policy handling. This ordering is source evidence, not a runtime
multi-layer precedence experiment.

Shell/unified execution uses `Bash`; patches use `apply_patch`, with Edit/Write
matcher aliases documented. MCP names are server-qualified, with argument
objects directly in `tool_input`. Shell redirects are still shell commands,
not a separate universal Write event. Documented `write_stdin` continuation,
hosted-tool and specialized-tool exclusions remain. Concurrent hooks cannot
prevent another matching hook from starting.

**[UNVERIFIED runtime]** Managed-versus-user precedence, trust enrollment,
matcher alias behavior, hook-disable attempts under required policy, hosted
exclusions and process-continuation coverage. No admin installation was made.

## 3. Administrator enforcement

Official guide:
[Managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration).
Short quote: “users can't override”.

The exact-version
[configuration loader](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/config/src/loader/mod.rs#L107)
loads Unix `/etc/codex/requirements.toml`, enterprise/cloud requirements,
legacy `/etc/codex/managed_config.toml`, and macOS managed preferences.
Requirements constrain supported settings; ordinary `/etc/codex/config.toml`
is a defaults layer, not an equivalent enforcement mechanism. Runtime
`--config` and `--ignore-user-config` do not mean “ignore system requirements”.

Managed hook declarations support `managed_dir` and pinning
`[features].hooks = true`. `allow_managed_hooks_only` would suppress user hooks
and must not be silently enabled. The configuration source has internal test
path overrides; no supported CLI remapping of `/etc/codex/requirements.toml`
was established. Fake HOME does not relocate that absolute path or macOS MDM.

The **installation interface is settled**, not unverified: return
`PlannedFile(..., action="create")` only for an absent administrator file;
otherwise return `action="manual"` with the exact additive block. Never
rewrite the existing file. This is the agreed contract at `f8c5b87`, not a
verified installed policy. No requirements drop-in directory is claimed.

**[UNVERIFIED runtime]** The proposed root-owned installation's resistance to
user/project overrides, crash behavior under managed policy, and interaction
with an isolated classifier. Establishing that needs a disposable managed
host or an agreed equivalent test boundary; writing `/etc`, using sudo, or
claiming a fake-home test relocated MDM would violate this task's conditions.
In particular, a deployment that pins hooks on needs a demonstrated answer
to the classifier's zero-loaded-hooks requirement.

## 4. Capability channels and settled scanner behavior

The exact-version
[metadata parser](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/ext/skills/src/loader/metadata.rs)
reads `agents/openai.yaml` interface, dependencies and policy. Dependency
entries include `type`, `value`, `description`, `transport`, `command`, `url`
and OAuth metadata. Policy includes implicit invocation and product filters.
This does not establish that arbitrary Claude-style permission fields grant
Codex permissions.

The installed feature list reports `skill_mcp_dependency_install` stable and
enabled. The
[dependency installer](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/core/src/mcp_skill_dependencies.rs#L40)
checks first-party origin, mentioned skills and the feature flag, filters
missing dependencies through policy, then requests installation consent.
Disabling this flag is not equivalent to disabling already configured MCP.
**[UNVERIFIED runtime]** No dependency install was attempted.

Portable `plugin.json`, compatibility `.codex-plugin/plugin.json`, hooks,
MCP configuration and executable scripts are distinct capability channels.
Plugin entry points can refer to paths outside the ordinary skills tree;
protecting only `SKILL.md` does not cover them.

Two scanner checks were rerun against **this rebased worktree**, with
`python3 -B bin/canary scan <temporary directory> --json`:

```text
Descriptive-only plugin.json:
  exit 0; LIKELY_SAFE; capability plugin_manifest
agents/openai.yaml with dependencies.tools:
  exit 10; NEEDS_REVIEW; capability skill_dependencies
```

These verify the two previously blocking scanner examples are resolved.
They are not a full scanner regression run or a plugin implementation test.

## 5. Classifier isolation experiments

All candidates use separate fake HOME and CODEX_HOME, `--no-daemon`,
`--ephemeral`, no inherited credentials, strict config validation, disabled
web search, and the loopback endpoint. The fixture cases plant unique skill,
AGENTS and hook sentinels. The fixture's hook only captures input; shell/patch
attempts can at most create a temporary marker.

| Case | Actual outgoing tools/context | Result |
|---|---|---|
| `baseline` | Bundled skills, coding instructions, code-mode shell/patch and collaboration tools | Fails isolation |
| `isolated` / Astra | Feature exclusions still leave code-mode, async input, collaboration tools and multi-agent instructions | Fails isolation |
| `isolated-gpt55` | Only requested system text and user prompt, but top-level `apply_patch` remains | Fails zero-tools |
| `isolated-catalog-gpt55` | Custom catalog: `tools: []`; requested system text and user prompt only | Passes captured empty-home request, not full deployment proof |
| `isolated-catalog-fixtures-gpt55` | No tools or skill sentinels; global AGENTS sentinel remains | Fails instruction exclusion |
| `isolated-catalog-ignore-fixtures-gpt55` | Adding ignore-user-config/ignore-rules does not remove global AGENTS | Still fails |

The isolation feature exclusions are captured in `isolated.toml`: shell,
unified execution, hooks, plugins, memories, multi-agent, image, browser,
computer, goals, skill dependency installation/search, and code-mode controls
are disabled; host skill discovery is skipped; bundled skills and skill
instructions are disabled. Request-user-input and update-plan are disabled
through their `enabled` tables. Initial invalid flag/schema spellings were
rejected by `--strict-config` and corrected; rejected configurations are not
passing experiments.

Top-level settings replace base instructions with a known classifier
sentinel, set project document bytes to zero, and exclude environment,
permission, app and collaboration instruction blocks. The custom catalog
explicitly specifies disabled shell, null apply-patch type, disabled
multi-agent version, and no experimental tools for `gpt-5.5`. Source
[tool registration](https://github.com/openai/codex/blob/36650394c5b38c2990ccf2a3457165ca3e9d9726/codex-rs/core/src/tools/spec_plan.rs)
explains why the normal catalog still registers apply_patch when a working
environment exists despite shell being disabled.

Both custom-catalog fixture cases reject an injected apply_patch response as
`unsupported custom tool call: apply_patch`, leave the marker absent, and
never run the synthetic hook. The baseline fixture does run the hook and
includes skill metadata. This is stronger evidence than asking a model not
to use tools, but **absence of hook execution is not proof that no hook
configuration was loaded**, and absence of metadata is not proof of no disk
reads during discovery.

**[UNVERIFIED]** A complete configuration satisfying zero loaded tools,
skills, hooks and incidental instructions with the approved login, including
managed-policy and resource-backed sources. No live authenticated request
was made. No classifier backend will be implemented on the strength of the
partial local success alone.

## Required handoff decisions

1. **Correct the Codex denial contract.** Recommend host-specific JSON /
   exit 0, which fits the existing tuple interface and has an executed deny
   control. Reject blanket JSON / exit 2 because it demonstrably executes the
   supposedly denied call. The alternative, stderr / exit 2, works but needs
   an interface or emission change to carry stderr.
2. **Keep the classifier stopped pending a complete isolation proof.** The
   custom-catalog experiment is a useful candidate, not certification.
   Evidence that would change this is a demonstrated clean request and
   absence of discovery/hook loading under the intended authentication and
   managed installation. Reject treating read-only sandboxing, fresh
   CODEX_HOME alone, or an empty advertised tool list as the whole guarantee.
3. **Retain the runtime-unverified labels above.** Managed installation and
   exhaustive discovery have not passed their acceptance boundary. Do not
   replace them with assumed facts to unblock coding.

No implementation suite or counterfactual mutation was run: there is no
adapter implementation yet. The 44 assertions check executed experiment
artifacts; they are not the future adapter's acceptance suite.

## Deviations

None from this continuation's agreed scope. The rebase changes the facts
commit ID while preserving its change. Source inspection and experimental
writes stayed in temporary directories; the only worktree content change is
this owned facts document. Routine Git metadata changed for the requested
rebase/commit. No sudo, publishing, privileged installation, credential copy,
or adapter code.
