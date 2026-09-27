# Canary architecture and interface contract

Status: frozen interfaces for the 2026-09-26 gate program. Change them only by
editing this file first, so every host adapter (Claude Code, Codex) builds
against the same seam.

## Goal

A skill, plugin or agent package is vetted before it reaches any directory an
agent discovers skills from, and before any working agent reads its text.
Both hosts load skill names and descriptions into context at session start and
reload skills mid-session, so vetting has to happen before files land, not
when an agent reads them. The limits of each enforcement layer are stated in
"Enforcement layers and their limits"; Canary never claims more than that.

## Pieces

| Piece | What it is | Who can change it |
|---|---|---|
| `canary` CLI | One Python 3 program, standard library only. Scans, classifies, installs, answers hooks. | Installed root-owned by `canary setup` |
| Layer 1 | Deterministic scanner (`canary scan`). No model; reads every file in the package. | — |
| Layer 2 | Isolated classifier, launched by the CLI, never by an agent. | — |
| Combiner | Deterministic code that turns layer 1, layer 2 and coverage into one verdict. | — |
| Quarantine | `~/Library/Application Support/Canary/quarantine/<package-digest>/` | Outside every discovery root |
| Lockfile | `~/.agents/.canary-lock.json`, a sibling of `npx skills`' `~/.agents/.skill-lock.json` | Written by the CLI only |
| Host adapters | A managed hook per host that calls `canary hook`. | Root-owned managed settings |

The Claude Code and Codex plugins in each marketplace are front doors: they
explain Canary and run `canary setup`. They are not the enforcement.

## `canary scan <path> [--json | --text] [--excerpts]`

Scans a file or a package directory. Never executes, imports or installs
anything it scans.

Exit codes (every Canary command uses these):

| Code | Meaning |
|---|---|
| 0 | `LIKELY_SAFE` |
| 10 | `NEEDS_REVIEW` |
| 20 | `UNSAFE` |
| 2 | Usage or path error |
| 3 | Internal error. Callers treat it as `NEEDS_REVIEW`, never as safe. |

`--json` output (schema `canary.scan/1`):

```json
{
  "schema": "canary.scan/1",
  "target": "/abs/path",
  "package_digest": "sha256:…",
  "verdict": "LIKELY_SAFE | NEEDS_REVIEW | UNSAFE",
  "threat_verdict": "LIKELY_SAFE | NEEDS_REVIEW | UNSAFE",
  "score": 0,
  "coverage": {
    "complete": true,
    "files_total": 3,
    "files_scanned": 3,
    "skipped": [{"path": "rel/path", "reason": "binary | too_large | unreadable | special_file | symlink_escape"}]
  },
  "capabilities": [{"kind": "…", "path": "rel/path", "line": 12}],
  "findings": [{"check_id": "…", "category": "…", "severity": "high|medium|low|info",
                "path": "rel/path", "line": 5, "excerpt_sha256": "…"}],
  "reasons": ["plain-language reason for the verdict"]
}
```

Rules the verdict follows:

- `threat_verdict` comes from the finding score, where each distinct check
  counts once at its strictest severity (high 3, medium 2, low 1, info 0):
  6 or more is `UNSAFE`, 3 to 5 is `NEEDS_REVIEW`, otherwise `LIKELY_SAFE`.
- `verdict` is the strictest of: `threat_verdict`; `NEEDS_REVIEW` when
  coverage is incomplete (including an empty package); `NEEDS_REVIEW` when any
  capability that runs code is present.
- Skip reasons: `binary`, `too_large`, `unreadable`, `special_file`,
  `symlink_escape`, `symlink_dir`, `too_many_entries`, and `media`. Every reason
  except `media` makes coverage incomplete. `media` needs both an image or font
  extension and matching first bytes.
- Findings carry no attacker text by default. Excerpts appear only with
  `--excerpts`, which is for a human's terminal, never for an agent.

Capability kinds that block auto-approval: `shell_injection` (a `` !`cmd` ``
line or a ```` ```! ```` block in a skill), `allowed_tools`, `skill_hooks`
(frontmatter `hooks:`), `plugin_power` (a `plugin.json` using any key beyond
the declarative set below, one that is not valid JSON, or any
`marketplace.json`), `plugin_hooks` (any `hooks.json`), `mcp_config`
(`.mcp.json`, `mcp.json`), `skill_dependencies` (an `agents/*.yaml` that
declares dependencies, MCP servers, tools, permissions or install steps),
`bin_dir`, `script` (a script extension or a shebang), `executable_bit`.

Listed but not blocking: `plugin_manifest` (a `plugin.json` using only
`$schema`, `name`, `version`, `description`, `author`, `homepage`,
`repository`, `license`, `keywords`, `skills` as paths, `displayName`,
`category`, `tags`) and `context_fork`. Hook, MCP and command declarations
elsewhere in the package are still found by their own kinds.

## `canary hook --host claude|codex`

Reads the host's pre-tool-use JSON on stdin (the shape both hosts share:
`hook_event_name`, `tool_name`, `tool_input`, `cwd`). Decides whether the tool
call installs, writes into, or reads from a protected location.

- Allow: exit 0 with no output. The host's normal permission flow continues.
- Deny: print the host's deny JSON and exit 2. For Claude Code:
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision":
  "deny", "permissionDecisionReason": "<reason pointing at canary add>"}}`.
- Any internal error: deny. The hook fails closed, because a hook that fails
  to start fails open in the host.

Protected: every discovery root of every supported host (resolved, case-folded
on macOS), the quarantine directory, the lockfile, and Canary's own install.

## Host adapters (`canary/hosts/<host>.py`)

The gate's decision logic lives in `canary/gate.py` and knows nothing about
any host. Each host adapter is one module that exposes exactly these
functions, so Claude Code (`canary/hosts/claude.py`) and Codex
(`canary/hosts/codex.py`) can be built by different people without touching
each other's files:

```python
def discovery_roots(home: str, cwd: str) -> list[str]:
    """Every directory this host loads skills, plugins, hooks or agent
    instructions from, for this user and this working directory, including
    ancestor walks. Absolute, resolved, de-duplicated."""

def config_files(home: str) -> list[str]:
    """Host configuration an agent could edit to weaken the gate
    (settings, hook and plugin config). Protected like discovery roots."""

def parse_pre_tool_use(payload: dict) -> "ToolCall":
    """Map the host's pre-tool-use JSON to canary.gate.ToolCall(tool_name,
    command, paths_read, paths_written, cwd). Unknown shapes raise ValueError;
    the gate then denies."""

def deny(reason: str) -> tuple[str, int]:
    """The exact stdout text and exit code that make this host block the call."""

def managed_install_plan(canary_bin: str) -> list["PlannedFile"]:
    """Root-owned files `canary setup` needs for this host:
    PlannedFile(path, content, mode, action). action is "create" when the
    path does not exist, or "manual" when an administrator file already exists
    there: setup then never rewrites it, prints the exact block to add, and
    `canary doctor` verifies it afterwards. Never touches the user's own
    config. Pure: reads the filesystem, writes nothing."""
```

`canary.gate.ToolCall` and `PlannedFile` are plain dataclasses defined in
`canary/gate.py`. `canary hook --host <name>` loads the adapter, calls
`parse_pre_tool_use`, asks `gate.decide(call, roots, protected)`, and prints
`deny(...)` or nothing.

Layer-2 backends follow the same pattern in `canary/classifiers/<backend>.py`:
`classify(system_prompt: str, fenced_skill_text: str, timeout_s: int) -> str`
returns the model's raw text; `canary/classify.py` owns fencing, schema
validation and the fail-closed rules, so a backend never decides a verdict.

## `canary add <source>` and `canary setup`

Specified when their slices land (slices 3 and 4). Fixed now: `add` fetches
into quarantine, scans an immutable snapshot, and installs that exact snapshot
as one unit; `setup` asks for the user's password once, installs the CLI
root-owned, and writes one drop-in per host (Claude Code:
`/Library/Application Support/ClaudeCode/managed-settings.d/canary.json`). It
does not set `allowManagedHooksOnly`, because that would disable the user's own
hooks; a managed hook cannot be disabled from user settings anyway.

## How people get Canary and use it

Canary itself is the one install that happens without Canary, so it only
arrives through channels that check integrity, and no agent ever reads a web
page to install it.

1. **Install:** `brew install skillcanary/tap/canary` (signed GitHub release
   behind a Homebrew tap), or a signed, notarized macOS `.pkg`. An agent may
   run that exact command when asked; it never fetches instructions from a page.
2. **Setup:** `canary setup` detects Claude Code and Codex, shows the three
   protection levels (Scan, Guard, Lockdown) with their trade-offs, recommends
   one, and asks for the password once for Guard or Lockdown. It then scans the
   existing library in report-only mode and prints the counts.
3. **Every install:** the person says "use Canary to install <link>" in chat,
   or runs `canary add <link>`. The agent only passes the link. Canary fetches
   into quarantine, scans, classifies, and asks the person in a native macOS
   dialog that summarizes publisher, version and capabilities in plain words.
   At Lockdown the dialog requires Touch ID or the password. The agent receives
   only the outcome.
4. **Redirects:** at Guard and above, `npx skills add`, plugin installs and
   writes into skill folders are denied with the message "use `canary add
   <source>`", so the insecure path points to the secure one.
5. **Updates:** `canary update` fetches, shows what changed in plain words
   (for example "now adds a shell script"), and installs only after approval.

The Claude Code and Codex marketplace plugins are front doors: a descriptive
skill that teaches the agent to use `canary add` and, when `canary` is
missing, to tell the person the install command. Each plugin must scan
`LIKELY_SAFE` under Canary itself.

## Enforcement layers and their limits

No single mechanism enforces the goal, so Canary stacks four layers and
states what each one covers.

1. **Install path.** `canary add` is the supported way in: fetch to quarantine,
   scan an immutable snapshot, install that exact snapshot. It is only as
   strong as the layers that stop other ways in.
2. **Managed hooks.** Claude Code: a drop-in under
   `/Library/Application Support/ClaudeCode/managed-settings.d/` with a
   `PreToolUse` hook and managed `permissions.deny` rules on protected paths.
   Codex: `[hooks]` in `/etc/codex/requirements.toml`, which users cannot
   override. Both deny agent tool calls that write into, read from, or install
   into protected locations. Known gaps, from each host's documentation:
   Codex hosted tools and tools that opt out of hooks never reach the hook;
   input sent with `write_stdin` to an already-approved process does not
   re-run the hook; hooks run concurrently; and a shell command can hide its
   target from any parser. Hooks are a guard, not proof.
3. **Filesystem ownership.** *Proposed; needs an owner decision.* Setup makes
   the user-level discovery roots root-owned, so no user-level process (an
   agent, `npx skills`, a script inside an approved skill) can add or change a
   skill there; `canary add` writes through a root-owned helper after the
   person approves. This is the layer that closes the hook gaps for
   user-level roots. Cost: plugin managers' own installs and auto-updates into
   those roots stop working and go through `canary update` instead.
   Repository-local roots (`.agents/skills`, `.claude/skills` in any repo)
   cannot be root-owned; layer 2 guards them, and `canary scan` runs on them
   when a session starts in a new repo.
4. **Detection.** `canary doctor` and an alert-only watcher report packages and
   configuration that changed without passing through Canary.

Public claims follow the layers actually installed:

| Installed | What Canary may say |
|---|---|
| 1 and 2 | "Guards installs by agents in Claude Code and Codex." |
| 1, 2 and 3 | "Enforces vetting for user-level skill directories on this Mac, and guards repository skills." |
| any | Cursor, opencode and Gemini: "scanned and monitored, not enforced." |

`canary doctor` prints which row applies to the machine it runs on.

Policy files are added, never replaced. Claude Code reads a drop-in
directory, so Canary owns one file there. Codex reads a single
`requirements.toml`: setup creates it only when absent; otherwise it prints
the exact block for the administrator to add and verifies it afterwards.
