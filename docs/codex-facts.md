# Codex gate facts — 2026-09-26

Status: **implementation stopped at the brief's fact/interface gate**. No host
adapter, classifier, or plugin has been implemented. No real Codex settings,
hooks, credentials, protected directories, or other agents' work were changed.

## Baseline and evidence levels

Installed executable: `/Users/abrahamburnett/.local/bin/codex`; its own
`--version` reports `codex-cli 0.157.1`. Its `--help` exposes `exec`,
`--sandbox read-only`, `--config`, `--no-daemon`, and a hook-trust bypass flag.
The bypass flag was observed only, not used.

This branch, `program/2026-09-26-canary-codex`, was created from the latest
committed gate revision available at start: `eca766b`. In Claude's gate
worktree, the architecture and scanner are staged/uncommitted and
`docs/codex-brief.md` is untracked. Consequently they are not yet inherited by
this branch. They were read in place; no copying, committing, or modification
of Claude's files occurred. Claude must commit its intended baseline before
implementation integration.

Evidence labels below distinguish current official documentation from actual
0.157.1 runtime experiments. Documentation alone does not satisfy the brief's
required captured-hook and classifier-isolation experiments.

## 1. Discovery and initial context

Official source: [Build skills](https://learn.chatgpt.com/docs/build-skills).
Short quote: “Codex supports symlinked skill folders”.

Documented roots are `.agents/skills` at the working directory and each
ancestor through the repository root; user `$HOME/.agents/skills`; admin
`/etc/codex/skills`; and OpenAI-bundled system skills. Discovery follows
symlink targets. Skill changes are detected automatically, with restart as a
fallback. Names, descriptions, and paths enter initial context before the
full skill body is explicitly read. The metadata list has a bounded prompt
budget. This means a later file-read hook alone cannot establish the brief's
promise that no unvetted skill text has reached a working model.

[UNVERIFIED] Complete installed-version discovery behavior for legacy
`$CODEX_HOME/skills`, exact plugin cache roots, bundled-skill physical paths,
`AGENTS.md` and override/fallback ancestor discovery, additional configured
roots, and remote/orchestrator resource skills. These must be established
from the installed binary/source or isolated capture before implementing
`discovery_roots`. Do not treat the short documented list as exhaustive.

## 2. Hooks

Official source: [Hooks](https://learn.chatgpt.com/docs/hooks).
Short quote: “not a complete enforcement boundary”.

Hooks load from `hooks.json` adjacent to active configuration layers or inline
`[hooks]` tables, including user, trusted project, and enabled-plugin sources.
Matching sources accumulate rather than replacing lower layers. Non-managed
hooks require hash-specific trust. Managed hooks cannot be disabled through
the user hook browser; managed requirements can pin the hooks feature on.

The documented input has session/cwd/event fields plus `tool_name`,
`tool_use_id`, `turn_id`, and `tool_input`. Shell and unified execution map to
`Bash`; patches to `apply_patch` (also matchable as Edit/Write). Both use
`tool_input.command`. MCP/local functions use their argument objects.

The documented deny shape is `hookSpecificOutput` with
`hookEventName: PreToolUse`, `permissionDecision: deny`, and
`permissionDecisionReason`. Exit 2 with a stderr reason also blocks.
Unsupported output fields can cause a failed hook while execution continues.

Documented exclusions matter: hosted tools lack this local hook path; some
specialized tools can opt out; `write_stdin` does not rerun PreToolUse when
sending subsequent input to an already-approved process. Hooks also run
concurrently, so one cannot prevent another matching hook from starting.
A root-owned hook therefore cannot, by itself, prove comprehensive enforcement.

[UNVERIFIED] Actual captured 0.157.1 shell/patch/MCP payloads, missing-command,
crash and malformed-output behavior, and real harmless deny demonstration.
No model session was started merely to fabricate this evidence.

## 3. Administrator enforcement

Official source: [Managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration).
Short quote: “users can't override”.

Enforced requirements exist at `/etc/codex/requirements.toml` on macOS/Unix,
with additional cloud and macOS MDM delivery. They constrain supported
security-related configuration, including permission profiles, hooks,
features, MCP identities, and plugin marketplace sources. Ordinary system
config defaults and most legacy managed defaults are not equivalent to
requirements.

The Hooks guide documents managed `[hooks]`, `managed_dir`, and
`[features].hooks = true`. It also offers `allow_managed_hooks_only`, which
would exclude the user's hooks; do not enable that silently. The shared
architecture deliberately preserves existing user hooks.

[UNVERIFIED] Safe additive installation when a machine already has a
requirements file, actual runtime precedence on this machine, and an isolated
proof that user overrides cannot disable the proposed configuration. No
verified drop-in directory is established here. `managed_install_plan` must
not blindly overwrite an existing administrator policy.

Strongest supported direction to investigate: combine enforced managed hooks
with managed filesystem restrictions and controlled package installation.
That is a proposed architecture change, not a claim of implemented or proven
coverage. It needs a defined threat model and a way to preserve existing
administrator requirements. A user-editable hooks.json is rejected as an
alternative because it cannot meet the immutability requirement.

## 4. Capability channels and the plugin conflict

Official sources: [Build skills](https://learn.chatgpt.com/docs/build-skills)
and [Plugin structure](https://developers.openai.com/plugins/build/plugins#plugin-structure).
Short plugin quote: “A portable plugin has a `plugin.json` manifest”.

Current portable plugins use root `plugin.json`, `skills/`, and optional
`mcp.json`; OpenAI-specific settings live in `extensions.com.openai`.
`.codex-plugin/plugin.json` is a compatibility overlay. The Hooks guide also
documents default `hooks/hooks.json` and manifest-specified hook paths or
inline hook objects. Skill `agents/openai.yaml` can declare MCP dependencies;
these are capability-bearing metadata and not equivalent to presentation
fields. Optional skill scripts can execute code when invoked.

The current gate scanner detects script files/shebangs/executable bits,
plugin/marketplace manifests, hooks.json, mcp.json/.mcp.json, bin directories,
and selected Markdown frontmatter capabilities. It does not inspect
`agents/openai.yaml` for dependency declarations. [UNVERIFIED] The complete
permission-granting YAML field set and installed-version dependency-install
flag behavior. Do not infer Claude frontmatter execution semantics for Codex.

### Executed manifest-only reproduction

Against Claude's working scanner (read-only execution, Python bytecode writes
disabled), created one temporary file containing only a minimal portable
plugin manifest: name, version, description. No hooks, scripts, or MCP server.

Command boundary:

```text
python3 -B bin/canary scan <temporary manifest-only package> --json
exit: 10
verdict: NEEDS_REVIEW
threat_verdict: LIKELY_SAFE
score: 0
coverage.complete: true
capabilities: [{kind: plugin_manifest, path: plugin.json, line: 0}]
```

Scanner source SHA-256 at the reproduction:
`cfd69ace48150583e77648a3787a67d66019979fd4580b9be42f6966dd874245`.

This contradicts Part 4's required `LIKELY_SAFE` result for the onboarding
plugin. Removing hooks and scripts is insufficient. Recommendation: Claude
should explicitly decide whether a verified declarative manifest is a listed
but non-blocking capability, with hook/MCP declarations still blocking, or
change the plugin acceptance criterion to a deliberate reviewed package.
Do not special-case the Canary plugin's name. Omitting the manifest would
avoid the score but would fail the plugin packaging requirement.

## 5. Isolated classifier

[UNVERIFIED] A supported `codex exec` configuration that guarantees zero model
tools, zero skill metadata (including bundled/admin sources), zero hooks,
plugins, memories and project instructions, while using approved login.
Read-only sandboxing does not mean no tools or no reads. Fresh CODEX_HOME
alone cannot prove absence of the separately documented HOME/admin/bundled
skill sources. No real credential was copied, and no classifier experiment
was run. The required fake-home canary-skill/hook demonstration remains a
prerequisite, not an omitted passing check.

## Requested changes in Claude-owned files

1. Commit the architecture, brief, and intended scanner baseline on the gate
   branch; provide the commit before this branch advances onto it.
2. Clarify the enforced threat model in `docs/architecture.md`: managed hooks
   protect supported calls, but the official exclusions and early metadata
   loading prevent a universal claim based only on PreToolUse. Define how the
   installer and OS restrictions close those gaps before calling it enforced.
3. Resolve the manifest-only plugin contradiction in the scanner/brief.
4. Establish additive administrator-policy installation semantics; the
   adapter cannot safely return an unconditional replacement for existing
   `/etc/codex/requirements.toml`.
5. Add capability handling for skill MCP dependency metadata or explicitly
   assign that scanner change to its owner.

No implementation tests were added/run because the brief forbids code until
these facts and interfaces are settled. No counterfactual mutation was run:
there is no implemented Codex behavior to mutate yet. The temporary scanner
reproduction above is executed evidence of the contract mismatch, not a
passing acceptance suite.

## Deviations

The managed worktree tool returned “Not a git repository” for this chat, so
an isolated shell-created worktree was used with approval. Only this owned
facts document was written on the requested branch. No implementation,
publication, push, merge, privileged installation, or real-machine config
change occurred.
