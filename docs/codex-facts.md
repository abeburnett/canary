# Codex gate facts — 2026-09-26

## Direct OpenAI API backend — current continuation

Rebased `program/2026-09-26-canary-codex` onto `b8eb66e`, which already
contains the host adapter and retained facts history. The following API
backend is explicitly owner-authorized; `codex exec` remains excluded.

`canary/classifiers/openai_api.py` exports
`classify(system_prompt, fenced_skill_text, timeout_s, *, model, transport=None)`.
The caller binds its chosen model (and a transport for tests). It reads
`OPENAI_API_KEY` only at invocation. The default transport makes one HTTPS
POST to `api.openai.com/v1/responses`, without redirects or retries. The
request contains exactly `model`, `instructions`, `input`, and `store: false`;
there is no `tools` field or local context collection. `timeout_s` is the
standard-library socket I/O timeout, not a total wall-clock deadline.

The response must be HTTP 200 and completed, without API error or incomplete
metadata. All output is checked before returning concatenated output-text
parts, preserving whitespace and leaving verdict parsing to the shared caller.
Refusals, tool calls, partial messages, malformed bodies and transport errors
raise generic RuntimeError messages. No response body, key or underlying
exception message is logged or included in the displayed exception chain.
Reasoning output items are ignored; they are not returned as answer text.

Source for the Responses request and output structure:
[OpenAI text generation guide](https://developers.openai.com/api/docs/guides/text).
This documents the protocol, not execution evidence for the live service.

Acceptance evidence (Python 3.10.3):

- Test-first scaffold returned an empty string; the tests failed on raw-text
  equality and missing RuntimeError assertions, rather than import errors.
- `python3 -B -m unittest discover -s tests -p test_classifier_openai_api.py -v`:
  **3 tests passed**, covering the exact single request/raw text, failure and
  key-diagnostic cases, and default HTTPS transport with no redirect handling.
  Tests replace the environment with a fake key and forbid socket creation.
- Counterfactual: adding `tools: []` made
  `test_exact_single_request_and_unmodified_raw_text` fail while the other two
  tests passed. Original bytes restored; capture at
  `/private/tmp/canary-openai-counterfactual.txt`.
- `python3 -B -m unittest discover -s tests -v`: **24 tests passed**.
- No real credential was read and no real API call was made.
- **[UNVERIFIED]** Live authentication, model availability, service behavior,
  latency and real network timeout behavior. Caller integration is owned by
  the shared core and is not included in this backend slice.

Deviations: none.

## Previous adapter handoff

The owner corrected the deny contract and removed `codex exec` as a classifier
backend in `3a9febd`. This branch is rebased onto that commit. Original facts
commit `a8c6b88` is now `65f1954`; the experiment commit is now `5dadc42`.
The historical classifier experiments below remain evidence, not pending
classifier work. No `codex exec` classifier code is being added.

Built the five functions in `canary/hosts/codex.py`, captured-payload tests in
`tests/test_host_codex.py`, and a descriptive plugin in `plugins/codex/`.
`canary.gate` is not on this base: the tests supply temporary dataclass
stand-ins through the module boundary. The adapter imports the shared types
only when parsing or planning; `deny()` has no shared-core dependency.

Owner-approved scope decision: **implement verified local roots and document
exclusions**. Configured external paths, nondefault project markers and
instruction fallback filenames, extra executor roots, and remote/resource
skills remain outside discovery coverage. No partial TOML parser or new
library was introduced. Shared integration must not claim exhaustive roots.

Local discovery includes default skill roots, CODEX_HOME, plugin caches,
repository `.agents`/`.codex` ancestors through `.git` (cwd only without a
root marker), global/repository AGENTS files, and nested symlink targets.
Individual instruction and project policy files are protected paths in the
root list; protecting their parent directory would block unrelated repo work.
The configuration directory itself is protected so a newly created named
profile cannot escape an inventory of existing profile files. Existing
profile files are also resolved individually to include symlink destinations.
Paths are absolute, resolved and deduplicated; platform case folding remains
the shared gate's responsibility, as specified in architecture.

`parse_pre_tool_use` handles captured `Bash` and `apply_patch` shapes. Shell
paths are hints from common file commands, redirects and explicit path
operands; the full command is preserved for the shared decision logic.
Expansion, multiline/compound shell commands and indirect shell builtins
raise `ValueError` for review. Opaque MCP calls and unknown tools also raise
`ValueError`, rather than inventing read/write semantics. These conservative
refusals may block benign calls. This is not universal shell enforcement.

`deny()` returns the verified JSON / exit-0 pair. A constant valid denial is
the fallback for invalid reasons or any exception, including serializer
failure. Its module needs only the standard library. This does not protect
against the hook executable being missing, import-time interpreter failure,
process termination, or an error in the shared CLI before/after calling it.

`managed_install_plan()` reads only metadata at
`/etc/codex/requirements.toml`. Absent means `create`; any existing entry,
including a symlink, means `manual`. It returns one root-owned-mode (0644)
requirements block with a feature pin and PreToolUse command. It never writes
files or disables the user's hooks. `manual` means the administrator merges
the block into existing TOML tables, not that setup blindly appends duplicate
table headers. Real managed installation remains unverified and unperformed.

### Acceptance evidence for this continuation

- Initial denial scaffold: named test failed `2 != 0` at the exit-code
  assertion. Parser and discovery/plan scaffolds then failed missing-path
  assertions. No import failure was counted as red evidence.
- Focused command: `python3 -B -m unittest discover -s tests -p
  test_host_codex.py -v`; three public-boundary risk groups pass.
- Counterfactual: changed only the successful `deny()` result from exit 0 to
  exit 2. `test_deny_stays_valid_even_when_reason_or_serializer_fails` failed
  `2 != 0`; the two neighboring tests passed. Original bytes were restored.
  Artifact: `/private/tmp/canary-codex-probes/adapter-counterfactual.txt`.
- Real installed Codex demo: `adapter_probe.py adapter-deny-v2 deny` imports
  the actual worktree adapter and emits its `deny()` result. A requested
  `/usr/bin/touch` inside fake HOME's `.agents/skills` is blocked, with the
  adapter reason returned to the model endpoint and the marker absent.
  `adapter-allow-v2 allow` creates the corresponding marker. Both temporary
  skill directories are included by the actual `discovery_roots()` function.
  Captures and harness: `/private/tmp/canary-codex-probes/`.
- Plugin scan: `python3 -B bin/canary scan plugins/codex --json` exits 0,
  `LIKELY_SAFE`, score 0, complete coverage of two files, only the nonblocking
  `plugin_manifest` capability. No hooks, scripts, MCP or dependency metadata.
- Profile regression: adding the expected protected CODEX_HOME directory to
  the existing root/plan test failed its missing-path assertion. Including
  that directory in `config_files()` restored all three focused tests.
- Final aggregate on Python 3.10.3:
  `/Users/abrahamburnett/.pyenv/versions/3.10.3/bin/python3 -B -m unittest discover -s tests -v`
  — **21 tests passed**. Plugin scan was repeated with the same interpreter:
  exit 0, `LIKELY_SAFE`, complete coverage. `git diff --check` passed.
- Fresh-context implementation review (Terra/high, same family) found no
  remaining must-fix issue and approved the targeted profile-directory fix.
  This is not cross-family certification. No rendered UI is part of this slice.

### Review reconciliation and delegation record

- **Must fix, resolved:** protect future named profile files, not only an
  existing-files inventory. The minimal directory-protection correction has
  a red/green assertion and passed targeted review; the aggregate ran after it.
- **Accepted known risk:** a literal command inside `/bin/sh -c` can hide its
  target from path hints; the complete command is preserved. This is within
  the frozen architecture's hidden-shell-target exclusion. Shared gate
  integration must not equate empty path hints with permission.
- **Rejected reproduction:** the review's exact `$HOME` shell-wrapper example
  raises `ValueError` in the actual adapter. A literal absolute-path variant
  does reproduce the documented shell limitation; both were executed through
  the public parser without executing their shell commands.
- **Integration evidence gap:** future-profile protection needs the shared
  gate's directory-prefix matching test after `canary.gate` lands.

2026-09-26 delegation outcomes, recorded here because writes outside the
worktree/temp directories are forbidden: Claude Opus 5/high through the
isolated CLI, outcome 1/5 (not logged in; zero API tokens, no review obtained);
Terra `gpt-5.6-terra`/high through the native read-only implementation reviewer,
outcome 5/5 (fresh-context review plus targeted correction review; 3 adapter
tests and plugin scan independently passed; no boundary incident). Adapter
SHA-256 after correction:
`7951987955be7f1d6bc6a1d02536e45b8e4a9956798815d2fcf32b761831f109`.


The real deny demo uses the same credential-free loopback protocol fixture
and temporary-only subprocess environment described below. It proves the
adapter's denial protocol in Codex, not a complete `canary hook` integration:
the shared gate and CLI hook dispatch are not on this branch.

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

## Integration boundaries still unverified

- Shared `canary.gate` dataclasses and `canary hook` dispatch must be connected
  and tested by their owner. The command must honor the adapter's exit 0 and
  catch parser/decision errors before emitting the adapter's deny response.
- Root-owned requirements installation, managed precedence/trust and hook
  crash behavior under enforced policy were not exercised on a disposable
  managed host. No sudo or system-policy write was authorized here.
- Exhaustive remote/external discovery and mid-session reload are excluded
  or unverified as individually marked in the historical evidence above.
- The planned Homebrew distribution and shared setup/add workflows are not
  established by this adapter/plugin slice. Plugin copy states this limit.
- Fresh isolated Claude/Opus review was attempted with no tools, temporary
  HOME and CLAUDE_CONFIG_DIR, no credential copying and no persistence. It
  returned `Not logged in` before a model call. No cross-family certification
  is claimed. The owner integrating in Claude must retain that review gap.

## Deviations

Owner-approved narrowing: discovery covers verified default local roots;
configured external and resource-backed roots are explicitly excluded pending
integration. The attempted cross-family review could not authenticate in the
required isolated environment; no credentials were copied to work around it.
No classifier, paid-launch edits, publishing, sudo, real configuration writes,
or writes outside this worktree and temporary directories were performed.
