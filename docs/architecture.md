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

## `canary scan <path> [--json | --text] [--excerpts] [--exclude <relative-path>]...`

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
  "target_id": "f:…",
  "package_digest": "sha256:…",
  "verdict": "LIKELY_SAFE | NEEDS_REVIEW | UNSAFE",
  "threat_verdict": "LIKELY_SAFE | NEEDS_REVIEW | UNSAFE",
  "score": 0,
  "coverage": {
    "complete": true,
    "files_total": 3,
    "files_scanned": 3,
    "skipped": [{"path_id": "f:…", "reason": "…"}]
  },
  "capabilities": [{"kind": "…", "path_id": "f:…", "line": 12}],
  "findings": [{"check_id": "…", "category": "…", "severity": "high|medium|low|info",
                "path_id": "f:…", "line": 5, "excerpt_sha256": "…"}],
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
  `symlink` (links inside a package are never followed), `symlink_loop`,
  `too_deep` (over 64 levels), `too_many_entries` (over 5,000 files and
  directories), and `media`. Every reason except `media` makes coverage
  incomplete. `media` is a PNG, JPEG, GIF, WebP or WOFF file whose structure
  parses (PNG chunk CRCs, JPEG segments, GIF blocks, WebP and WOFF lengths);
  anything that decodes as text is scanned as text, and PDFs and other
  binaries are incomplete coverage.
- Attacker-controlled text stays out of default output: no excerpts, and file
  names and the target path appear only as opaque `path_id` / `target_id`
  values. `--excerpts` adds `path`, `excerpt` and `target` fields and is for a
  person's terminal, never an agent.
- `--exclude` names paths, relative to a directory target, that are scanned as
  separate packages (the Action uses it to scan files outside skill folders).

Capability kinds that block auto-approval: `shell_injection` (a `` !`cmd` ``
line or a ```` ```! ```` block in a skill), `allowed_tools`, `skill_hooks`
(frontmatter `hooks:`), `plugin_power` (a `plugin.json` using any key beyond
the declarative set below, one that is not valid JSON, or any
`marketplace.json`), `plugin_hooks` (any `hooks.json`), `mcp_config`
(`.mcp.json`, `mcp.json`), `skill_dependencies` (an `agents/*.yaml` that
declares dependencies, MCP servers, tools, permissions or install steps),
`unparsed_frontmatter` (frontmatter this parser cannot read line by line:
flow style, escaped or unusual keys, an unclosed block, a continuation that
looks like a key), `instructs_execution` (Markdown telling the agent to run an
interpreter on a file, such as `python3 helper.txt` or `awk -f x.awk`),
`bin_dir` (any path segment named `bin`, any case), `script` (a script
extension or a shebang), `executable_bit`, `package_manifest`
(`package.json`, `pyproject.toml`, `requirements.txt` and similar), and
`unrecognized_file` (a text file whose type is not on the inert-document
allowlist in `canary/scan.py`; unknown means possibly runnable).

Listed but not blocking: `unknown_frontmatter_key` (hosts ignore keys they do
not define), `plugin_manifest` (a `plugin.json` using only
`$schema`, `name`, `version`, `description`, `author`, `homepage`,
`repository`, `license`, `keywords`, `skills` as paths, `displayName`,
`category`, `tags`) and `context_fork`. Hook, MCP and command declarations
elsewhere in the package are still found by their own kinds.

## `canary hook --host claude|codex`

Reads the host's pre-tool-use JSON on stdin (the shape both hosts share:
`hook_event_name`, `tool_name`, `tool_input`, `cwd`). Decides whether the tool
call installs, writes into, or reads from a protected location.

- Allow: exit 0 with no output. The host's normal permission flow continues.
- Deny: print exactly what the adapter's `deny(reason)` returns, write the
  reason to stderr, and exit with the adapter's code. The hosts differ, and a
  wrong pairing fails open:
  - Claude Code: deny JSON on stdout, reason on stderr, exit 2. Verified
    2026-09-26 on the installed Claude Code: stderr with exit 2, deny JSON
    with exit 0, and deny JSON with exit 2 each block; a hook that exits 1
    lets the call run.
  - Codex: deny JSON on stdout with **exit 0**, or a reason on stderr with
    exit 2. Deny JSON with exit 2 and empty stderr **runs the command**
    (verified on Codex 0.157.1, `docs/codex-facts.md`).
  Both shapes: `{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "deny", "permissionDecisionReason": "<reason pointing
  at canary add>"}}`.
- Any internal error: the hook still prints its host's deny. In both hosts a
  missing hook command, a crash or malformed output lets the call run, so the
  hook catches every exception, and `canary` is installed root-owned where an
  agent cannot remove it. Setup also checks that the Python the hook runs on
  works, because macOS's `/usr/bin/python3` stub fails when the command-line
  tools are missing, and a failing hook fails open.

Protected: every discovery root and configuration file of every supported
host (resolved, case-folded on macOS), the quarantine directory, the
lockfile, Canary's own install and the managed policy files.

Decision rules (`canary/gate.py`, `decide`), in order:

1. The payload is not a pre-tool-use event with a tool name, a tool input
   object and an absolute `cwd`: deny.
2. A command that runs a skill or plugin installer (`npx`, `pnpm dlx`,
   `bunx` or `yarn dlx` with `skills add|install|update`;
   `claude plugin install|marketplace add|update`; `codex plugin` installs;
   `git clone` or `curl`/`wget` output into a protected folder): deny, "use
   `canary add <source>`".
3. `canary` itself is allowed when the command's first word is exactly
   `canary`, it has no other shell syntax, and the `canary` on `PATH` is the
   root-owned install (so an agent cannot put its own `canary` first).
4. The adapter mapped the call (a file tool, a tool that only carries text,
   or a shell command `canary/shellparse.py` can lex): deny when a written
   path is inside a protected location or inside any repository's
   `.claude/skills`, `.claude/commands`, `.claude/agents`, `.agents/skills`
   or `.codex/skills`; when a read path is inside the quarantine; or when a
   recursive read (`grep -r`, `find`, `rg`, a glob, Claude Code's Grep and
   Glob) covers it. Writing to a folder that contains a protected location
   (`rm -rf ~/.claude`) counts as writing into it.
   - Shell: `canary/shellparse.py` lexes quotes itself, so a quoted `;` is an
     argument and `2>` is a file descriptor. It maps pipelines and `&&`/`;`
     chains, follows a plain `cd dir &&`, and models read-only commands
     (`ls`, `cat`, `grep`, `find` without actions, `sed -n 'N,Mp'`, …), the
     writers `touch`, `mkdir`, `rm`, `rmdir`, `tee`, `cp`, `mv`, and
     redirection. A glob stands for its fixed folder. Backslashes, `$`,
     backticks, newlines, subshells and heredocs cannot be mapped (rule 5).
   - `git`: subcommands that touch only the index and history (`status`,
     `log`, `diff`, `show`, `add`, `commit`, `fetch`, `push`, …) are reads;
     `--output=<file>` is a write. Every other subcommand, and any alias,
     rewrites the repository at `-C` or the working folder, walked up to its
     root: deny when that repository holds a protected location that exists
     on disk. (A skills folder that does not exist yet is not protected
     against a checkout that creates it; see "Enforcement layers".)
   - Any other command is unknown: every argument, including option values
     such as `--out=<path>`, counts as a path it reads and writes, resolved
     against the tracked working folder (so `cd ~/.claude && tool
     skills/x.md` writes into a skills folder). An option with its value
     attached (`-oskills/x.md`) counts every suffix up to its first `/` as a
     candidate. A bare `.` or `..` may only be read (`prettier --check .`),
     so it counts as written only when it is the home folder or above, a host
     folder (`.claude`, `.agents`, `.codex`) or inside a protected location;
     a whole-repository run in a repository is allowed. Its text is also
     screened as in rule 5.
   - Tools that only carry text to a person or another agent
     (AskUserQuestion, TodoWrite, Agent, SendMessage, plan-mode tools,
     spawn_task) touch no files; whatever they start is checked in turn.
5. The adapter could not map it exactly (variables, escapes, heredocs,
   unknown tools such as MCP calls): the call's text is screened. Deny when
   it names a protected location (the resolved paths, their `~` and `$HOME`
   spellings, and the fragments `.claude/skills`, `.agents/skills`,
   `.claude/plugins`, `.codex/skills`, `.claude/commands`, `.claude/agents`,
   `.claude/settings`, `.claude.json`, `.mcp.json`, `AGENTS.md`,
   `.codex/config`, `.codex/hooks`, `.codex/rules`, `.canary-lock`,
   `Application Support/Canary`, `Application Support/SkillCanary`,
   `managed-settings`, `/etc/codex`). A call the adapter could not map at
   all is also denied when it names a bare `.claude`, `.agents` or `.codex`
   folder, because relative writes after `cd` into one cannot be seen.
   Allow otherwise, so ordinary compound commands keep working.
6. Otherwise allow.

Notes: an adapter may name protected folders whose top-level notes agents
may write (`note_folders(home)`; Codex returns its home folder, which is
protected whole so that a profile created later is covered). A note is a
`.md`, `.txt` or `.log` file directly in that folder, judged on its resolved
path, that is a regular file with one name and is not `AGENTS.md`,
`AGENTS.override.md` or `instructions.md`. Writing one is checked against
every other protected location, so a note that is really a skills file, or a
note folder inside another protected folder, is still denied. A note folder
that is the home folder or above it, or overlaps another host's protected
locations (`CODEX_HOME` pointed at `~/.claude`), grants no notes. This lets an
agent keep a delegation log in `~/.codex`; everything else there stays
protected. The exception rests on one fact, that `AGENTS.md`,
`AGENTS.override.md` and the legacy `instructions.md` are the only such files
a host loads from its home folder; a test ties the exclusion list to the
Codex adapter's own list of loaded files.

In the text screen (rule 5, commands that cannot be mapped: `printf` with
escapes, heredocs), a note folder's name is fine when each mention is
followed by one plain note file name that passes the same on-disk checks
(regular, one name, resolved directly in the folder), and no quote sits
directly before the mention or after the name. A quote glued to the name can
change the file the shell means (`x.md'.config.toml'`, `''$HOME/.codex/x.md'
  .config.toml'`, `x.md'/../config.toml'`), and telling a closing quote from a
glued one needs the whole command's quote state, so a quoted note path is
denied there: write the path without quotes, or use the Write or Edit tool.
The name must end at white space, `;`, `&`, `|`, `<`, `>`, `)`, the end of
the text, or (in JSON text) an escaped newline, return or tab or the string's
closing quote. Any other mention of the folder, and every other protected
location, still denies.

Deny messages name the way forward: a write into a skills folder names
`canary edit start` and `canary edit apply`; a write to settings says no
SkillCanary command allows it and tells the agent to give the person a
command to paste into their own terminal; a text-screen deny says to read with plain commands and to
write a file that mentions a protected folder with the Write tool.

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

def note_folders(home: str) -> list[str]:   # optional
    """Protected folders whose top-level notes agents may write (see
    "Notes" under the decision rules). Codex: its home folder."""

def install_root(home: str) -> str:
    """The user-level folder `canary add` installs skills into for this
    host (Claude Code `~/.claude/skills`, Codex `~/.agents/skills`)."""

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
`classify(system_prompt: str, fenced_skill_text: str, timeout_s: int, *,
model: str) -> str` returns the model's raw text or raises `RuntimeError`
with no diagnostics; `canary/classify.py` owns fencing, schema validation and
the fail-closed rules, so a backend never decides a verdict.

A backend ships only when its isolation is demonstrated: the model receives
the system prompt and the fenced text and nothing else, and has no tools.
- `claude`: `claude -p` from a fresh empty temporary directory with
  `--disable-slash-commands --tools "" --strict-mcp-config --setting-sources ""
  --no-session-persistence --max-turns 1 --output-format json
  --system-prompt-file`, skill text on stdin, and an environment reduced to
  `HOME`, `USER`, `LOGNAME`, `PATH`, `LANG`, `LC_ALL` and `TMPDIR` (an
  exported `ANTHROPIC_API_KEY` would otherwise switch billing to that key;
  subscription login still works without it). Verified 2026-09-26 on the
  user's subscription login, with a positive control: no tools, MCP servers,
  skills, hooks, advisor or `CLAUDE.md` (the same question without
  `--setting-sources ""` found the global `CLAUDE.md`). The model still sees
  Claude Code's environment block (working directory, date) and the account's
  email address. With no tools it cannot send either anywhere; the output
  validator keeps model text out of agent-facing output. Default model
  `sonnet`: Opus costs several times more per scan for a classification task.
  (`--bare` is not usable: it drops subscription login.)
- `openai_api` and `anthropic_api`: a direct API request with the user's own
  key. No agent harness, so nothing else can load.
- `codex exec` is **not** a backend: it still loads the global `AGENTS.md`
  under every suppression setting tried (`docs/codex-facts.md`). A person who
  has only a Codex subscription and no API key therefore has no layer 2; their
  checks top out at `NEEDS_REVIEW`, and onboarding must say so.

## `canary check <path> [--json | --text] [--excerpts] [--backend <name>] [--model <id>] [--timeout <seconds>]`

Layer 1, then layer 2, then the combiner. Same exit codes as `canary scan`.
`canary add` runs exactly this on its quarantined snapshot.

Backend `auto` (the default) picks the first available: `claude` when the
`claude` command is on `PATH`, then `anthropic_api` when `ANTHROPIC_API_KEY`
is set, then `openai_api` when `OPENAI_API_KEY` is set. `none` skips layer 2.

Layer 2 receives only the files layer 1 read as text, each inside a fence
built from a per-run random nonce (`secrets.token_hex(16)`, regenerated if it
occurs in the content). A file's relative path is the first line inside its
fence, never in the marker, because file names are attacker text. The whole
fenced input is capped at 256 KiB; above that layer 2 does not run. Nothing is
truncated, because a truncated payload can hide at the tail.

The model must answer with one JSON object in the shape
`references/classifier-prompt.md` defines. One wrapping ```` ```json ````
fence is tolerated; any other text, an extra key or a wrong type fails
validation. Summary, evidence and reasoning are display text: longer than
300, 200 and 200 characters they are shortened, and past 4,000 characters the
answer is invalid. The raw answer is written, mode 0600, to
`~/Library/Application Support/Canary/logs/`, outside every discovery root.

The combiner (`verdict`) is the strictest of: the layer-1 `verdict`; the
layer-2 verdict (`SAFE` maps to `LIKELY_SAFE`); `NEEDS_REVIEW` when layer 2 is
`SAFE` with confidence below 0.7; `NEEDS_REVIEW` when layer 2 did not produce
a valid answer for any reason (`unavailable`, `too_large`, `failed`,
`invalid`). Layer 2 can only make a verdict stricter, never safer.

`--json` output (schema `canary.check/1`):

```json
{
  "schema": "canary.check/1",
  "target_id": "f:…",
  "package_digest": "sha256:…",
  "verdict": "LIKELY_SAFE | NEEDS_REVIEW | UNSAFE",
  "scan": { "…": "the full canary.scan/1 result" },
  "classifier": {
    "status": "ok | unavailable | too_large | failed | invalid",
    "backend": "claude | anthropic_api | openai_api | null",
    "model": "…",
    "verdict": "SAFE | NEEDS_REVIEW | UNSAFE | null",
    "confidence": 0.93,
    "findings": [{"category": "…", "severity": "high|medium|low",
                  "evidence_sha256": "…"}],
    "log_id": "…"
  },
  "reasons": ["plain-language reason for the verdict"]
}
```

The model's `evidence`, `reasoning`, `summary` and own category wording are
attacker-influenced, so they appear only with `--excerpts` (as `evidence`,
`reasoning`, `summary`, `model_category`), which is for a person's terminal,
never an agent. Default output names each finding's category from a closed
list (`instruction_override`, `approval_bypass`, `exfiltration`,
`credential_harvesting`, `persistence`, `stealth`, `prompt_extraction`,
`obfuscation`, `remote_code_execution`, `social_engineering`), and `other`
for anything else. Validation rejects duplicate keys, `NaN` and `Infinity`,
and compares confidence as an exact decimal.

## `canary evidence <skill-folder>`

Deterministic evidence for hosted automated badges, schema `canary.evidence/1`
under policy `text-only/1`. The contract, shared with the hosted service, is
`docs/evidence-contract.md`; the identities and shared vectors are in
`canary/evidence.py` and `tests/vectors/evidence-v1.json`. It prints no file
names, paths or text.

## `canary add <source> [--host claude|codex]... [--backend <name>] [--model <id>]`

The one supported way to install a skill. The agent passes the link and gets
back only the outcome; the person decides in a native macOS dialog.

Sources, one skill per link:

- `https://github.com/<owner>/<repo>` (the repository root must be a skill),
  `…/tree/<ref>/<path>` (a folder), `…/blob/<ref>/<path>/SKILL.md` (that
  file's folder). `<ref>` is resolved to a commit SHA through the GitHub API
  first; the tarball is then fetched by SHA from `codeload.github.com`. No
  redirects are followed and the download is capped at 50 MB.
- A local folder path, copied through file handles opened without following
  links, and without `.git`.

Links with `%` in the ref or path, and refs starting with `.`, are refused
before anything is fetched: an encoded path could name a different folder
from the one the person sees.

A link whose folder holds no `SKILL.md` but several subfolders that do is
exit 2 with the count only ("link the folder you want"): folder names are
attacker text and never reach the agent.

Steps:

1. Extract by hand into a temporary directory: symlinks, hard links,
   devices, absolute paths, `..`, NUL in names and more than 5,000 entries
   refuse the whole package. The selected folder moves into
   `~/Library/Application Support/Canary/quarantine/<run-id>/`, is made
   read-only, and the rest is deleted.
2. `canary check` on that snapshot.
3. `UNSAFE`: nothing is installed and nobody is asked. Otherwise the dialog
   asks the person. It shows Canary's verdict and reasons, the source as
   `owner/repo` at a short commit, and the installed name, with every
   package-supplied string labelled as such; never the package's description
   or excerpts, which an attacker writes. `NEEDS_REVIEW` defaults to Cancel.
   The dialog gives up after 300 seconds, which counts as a decline.
4. On approval, one install at a time (an exclusive lock beside the
   lockfile, never held while the person decides): re-read the lockfile and
   destinations, copy the snapshot to a staging folder beside each
   destination, and `rename` it into place only if its tree digest equals
   the checked snapshot's. The tree digest (`canary digest`) hashes every
   file's full bytes, path and program bit with no size or depth limit,
   unlike the scan's `package_digest`, so it binds exactly what lands. Any
   mismatch aborts and removes the staging folders; a failure to write the
   lockfile removes the install again.
5. Record the install in the lockfile and delete the quarantine snapshot.

Install roots come from each host adapter's `install_root(home)`: Claude Code
`~/.claude/skills`, Codex `~/.agents/skills`. Each host gets its own real
copy, not a link, so every file under a discovery root is a file that was
scanned. Default hosts: those whose home folder exists (`~/.claude`,
`~/.codex` or `~/.agents`).

The installed name is the frontmatter `name` if it matches
`^[a-z0-9][a-z0-9-]{0,63}$`, else the folder name if that matches, else the
add is refused. An existing folder of that name is never overwritten
(`canary update` replaces installs).

There is no `--yes`, environment override or typed confirmation: an agent can
type into a terminal. Approval comes only from the dialog (tests inject an
approver through the Python API). With no GUI session the outcome is
`not_installed`, "approve on the Mac's screen".

Errors from unpacking never quote file-system messages, which can contain
package file names; the agent sees a fixed sentence.

Exit codes: 0 installed; 10 not installed and waiting on the person (declined,
dialog unavailable or timed out); 20 refused because `UNSAFE`; 2 usage, link
or fetch error; 3 internal error.

Output (schema `canary.add/1`, all the agent receives):

```json
{
  "schema": "canary.add/1",
  "outcome": "installed | declined | not_installed | refused",
  "verdict": "LIKELY_SAFE | NEEDS_REVIEW | UNSAFE",
  "name": "sanitized-name",
  "source": {"owner": "…", "repo": "…", "commit": "40-hex"},
  "installed": ["~/.claude/skills/<name>"],
  "reasons": ["Canary's own reasons, no package text"]
}
```

`owner` and `repo` are GitHub's validated identifiers (letters, digits, `-`,
`_`, `.`), so they carry no markup.

Lockfile `~/.agents/.canary-lock.json`, written to a temporary file and
renamed:

```json
{"schema": "canary.lock/1",
 "skills": {"<name>": {"source": "<link as given>", "owner": "…", "repo": "…",
   "ref": "…", "commit": "…", "path": "…", "package_digest": "sha256:…",
   "verdict": "…", "installed": ["…"], "installed_at": "2026-09-26T00:00:00Z"}}}
```

## `canary edit start|apply|allow|allowances|revoke`

The one supported way to change an installed skill (`canary/edit.py`;
design and owner decisions in `docs/program-2026-09-28-skill-edits.md`).

- `start <name | folder>` finds every copy of a name in the user skill
  folders, or takes a folder directly inside any folder named `skills`,
  follows links to the real folder, and refuses copies that differ. It copies
  the skill without `.git` to `~/.skillcanary/drafts/<name>-<id>/skill/` and
  records each file's SHA-256 in `edit.json` beside it.
- `apply <draft>` re-validates the targets named in `edit.json` (the agent
  can write that file), copies the draft to a private snapshot under
  `~/Library/Application Support/Canary/edits/<run>/`, and compares it with
  the installed skill. A skill that changed since `start` is a `conflict`.
  - A *code change* touches a file that has, or gains, a capability that
    blocks auto-approval, a file the scanner cannot read as text, a program
    bit, or the SKILL.md frontmatter (including `description`). Anything
    else is a *text change*.
  - Layers 1 and 2 run on a package of only the added and changed files.
    `UNSAFE` is refused without asking.
  - One dialog asks the person; a code change or a verdict other than
    `LIKELY_SAFE` uses the caution form with Cancel as the default. It shows
    file names (labelled as the skill's), lines added and the path of the
    full diff. At Lockdown the write is one administrator step that stages
    each file in a root-owned folder inside the skill, checks its SHA-256
    with `/usr/bin/shasum`, then moves it into place.
  - Writes happen under `canary add`'s lock, after re-checking the skill
    and snapshot, file by file through a temporary file and a rename. Files
    outside the change, and `.git`, are not touched. The lockfile entry gets
    the new `package_digest` and `edited_at`; `edits.jsonl` records the
    change, and the previous files stay under the run folder.
- `allow <name | folder> <pattern> [--days 1-30]` (Guard only): after a
  dialog, the administrator step writes `allowances.json` beside
  `state.json`. An allowance is read only when the file and its folder
  belong to root and are not writable by group or others. It covers a
  change when every changed file already exists, matches the pattern
  segment by segment, ends in `.md` and is not `SKILL.md`; the change is a
  text change; the change scan is `LIKELY_SAFE` with the classifier run; it
  adds at most 200 lines and 16 KiB; and it adds no URL or shell fence. Then
  no dialog is shown, and a notification follows. `revoke` also takes the
  password; `allowances` lists them.

Exit codes: 0 `started`, `applied`, `unchanged`, `allowed`, `revoked`; 10
`declined`, `not_applied`, `conflict`; 20 `refused`; 2 usage or an unusable
draft or folder; 3 internal error. No flag approves an edit.

## `canary setup [--level scan|guard|lockdown]` and `canary doctor`

`setup` asks which level the person wants in a native dialog, with the
recommended one preselected (Guard when Claude Code or Codex is present).
`--level` skips that question, so an agent can start setup on the person's
behalf; Guard and Lockdown still need the person's password in the macOS
administrator dialog, which an agent cannot answer.

| Level | Password | What setup does |
|---|---|---|
| Scan | no | Nothing machine-wide. Reports the existing library. |
| Guard | once | Installs Canary root-owned in `/Library/Application Support/SkillCanary`, a path macOS keeps root-owned all the way up (link `/usr/local/bin/canary`; 0.1.0 used `/usr/local/lib/skillcanary`, which old Homebrew installs leave owned by the person); writes the Claude Code drop-in `managed-settings.d/canary.json` and creates `/etc/codex/requirements.toml` when absent (else prints the block to add). |
| Lockdown | once, and at every `canary add` | Guard, plus the user-level roots `~/.claude/skills` and `~/.agents/skills` become owned by root, so nothing running as the person (an agent, `npx skills`, a script inside a skill) can change them. `canary add` then installs through the administrator dialog (password or Touch ID). |

The privileged step is one shell script passed to
`do shell script … with administrator privileges` as a string, never a file
on disk, so nothing can swap it while the dialog is open. Canary's own files
travel inside it as a base64 archive whose SHA-256 the script checks before
extracting. The script records the level and every file it created in
`/Library/Application Support/SkillCanary/state.json` (root-owned; setup reads a 0.1.0 `state.json` from the old location only as a hint to the previous level, because the person may control that folder, and never deletes inside it as root). Nothing read from disk authorizes a root operation by itself. Setup only
ever writes or removes its two policy files, and only when their content is
exactly what this or an earlier SkillCanary writes, or their hash is recorded
in the root-owned state; any other content is a manual step. It only ever
locks or unlocks the two user skill roots, through the root-owned `canary`,
which opens each folder from `/` without following links and skips (and
`canary doctor` reports) a root reached through a link. Moving to a lower
level removes those files and returns the roots to the person. The program itself stays installed at every
level, since the Mac installer may have put it there.

At Lockdown, `canary add` copies the checked snapshot into a root-owned
staging folder inside the root, has the root-owned `canary digest` confirm the
staged copy's tree digest, and only then renames it into place, all in
one administrator step.

`canary doctor` reads `state.json` and checks the machine against it: the
install and the hook command are root-owned and not writable by the person,
each host's policy file carries the hook, Lockdown roots are root-owned, and
the hook's Python runs. It prints the level, every gap in plain words, and the
public-claims row that applies. Exit 0 when the machine matches its level, 10
when there is a gap.

At every level, setup also installs the SkillCanary skill
(`canary/frontdoor.py`, the same text as `skills/canary/SKILL.md`) as
`canary/SKILL.md` in `~/.claude/skills` and `~/.agents/skills`, so an agent
knows to route installs through `canary add`. It writes only a `canary`
folder that is missing or holds just a SKILL.md ending in SkillCanary's marker
line. A marker can be copied, so this keeps setup from replacing other skills;
it is not proof of who wrote the folder. The skill is always written as the
person, through open folder handles that never follow links, and never by the
privileged step: at Lockdown it is written before the roots are locked.

For Lockdown, the Mac installer is the recommended channel: Homebrew keeps
programs in a folder the person's account can write, so software already
running as them could alter SkillCanary before `canary setup` copies it into
the root-owned location. `SECURITY.md` lists this with the other known limits.

Setup never sets `allowManagedHooksOnly`, because that would disable the
person's own hooks; a managed hook cannot be disabled from user settings
anyway.

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

At Scan and Guard, the `canary add` dialog is the person's checkpoint; an
agent that can control the screen could click it. Lockdown's Touch ID or
password step is what closes that, and no claim above says otherwise.

`canary doctor` prints which row applies to the machine it runs on.

Policy files are added, never replaced. Claude Code reads a drop-in
directory, so Canary owns one file there. Codex reads a single
`requirements.toml`: setup creates it only when absent; otherwise it prints
the exact block for the administrator to add and verifies it afterwards.
