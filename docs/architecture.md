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
call installs a skill without SkillCanary's check, or reads the quarantine.

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

What the hook is for (program 2026-09-30, back to the front door):
SkillCanary checks a skill before any agent can use it, and the hook's only
job is to send installs through that check. It does not guard every write:
an agent may read anything, edit installed skills, change settings and run
any other command. A skill that arrives or changes some other way is for the
guest list and the watcher to report (later slices of that program), not for
the hook to block.

Decision rules (`canary/gate.py`, `decide`), in order:

1. The payload is not a pre-tool-use event with a tool name, a tool input
   object and an absolute `cwd`: deny.
2. `canary` itself is allowed when the command's first word is exactly
   `canary`, it has no other shell syntax, and the `canary` on `PATH` is the
   root-owned install (so an agent cannot put its own `canary` first).
3. A shell command whose words install a skill or plugin
   (`canary/installers.py`). When the whole command is one plain installer
   that `canary install` runs (below), Claude Code runs it through
   `canary install`: the hook allows the call with `updatedInput`, whose
   command is `/usr/bin/python3 -I -B <root-owned canary> install --
   <the same words>` and whose timeout is ten minutes, so the checks and
   the dialog fit. Claude Code does not run hooks again on the new command.
   Codex is denied with a message naming `canary install -- <the same
   words>` (whether Codex can rewrite is probed after 2026-10-03). Any other
   installer command is denied, naming `canary install` and `canary add`. The installer's own
   words decide, wherever they sit: after removing quotes, `$'...'`, line
   continuations and backslashes, the command is searched for a `skills`
   package (`skills`, `@scope/skills`, `skills@1.2.3`) followed, after any
   options, by `add`, `a`, `install`, `i`, `update` or `upgrade`; for
   `plugin` or `plugins` followed, after any options, by `install`, `i`,
   `update`, `add` or `marketplace add`; and for `clone` in a command that
   names a skills folder or runs inside one. Working out which words *run*
   was tried and given up: shell grammar (keywords, functions, wrappers with
   options, variables, `find -exec`) kept leaving ways around it in two
   review rounds. The cost is accepted false denials: `echo` or a heredoc
   that only mentions an installer, or a commit message naming one, is
   denied; the Write tool writes such a file, and `git commit -F` takes such
   a message. A single, plain command (no `;`, `&`, `|`, `$`, quotes of
   commands, brackets or line breaks) asking only for help or a listing
   (`-h`, `--help`, `-l`, `--list`) is allowed. Only the shell tool's command
   is read; words in other tools' input (a message, a question) are not an
   install. A command assembled from pieces (`npx $X add`) and a program
   that starts an installer itself are out of the hook's reach; the watcher
   reports what they put in a skills folder.
4. A file tool (Write, Edit, MultiEdit, NotebookEdit; Codex `apply_patch`)
   that writes into a skill folder with no `SKILL.md` yet: deny, "use
   `canary add`". A skill folder is the first folder under a user skills
   folder (each host's `install_root`, and `CODEX_HOME/skills`) or under any
   repository's `.claude/skills`, `.agents/skills` or `.codex/skills`,
   compared ignoring case. The adapters pass each path as given; the gate
   checks it as given and as resolved, so a link into a skills folder, or a
   link inside one that leads elsewhere, counts. Editing a skill that has a
   `SKILL.md` is allowed. A Codex patch the adapter cannot read is denied.
5. SkillCanary's record: a file tool writing inside the support folder
   (`~/Library/Application Support/Canary`, outside the quarantine) or to
   the lockfile (`~/.agents/.canary-lock.json`) is denied, "canary trust
   and canary add change it". Reading them is allowed.
6. The quarantine (a package waiting for its check): a file tool reading or
   writing inside it, or a shell command naming it, is denied.
7. Otherwise allow. The hook does not parse shell commands for writes and
   does not screen text; a shell command that creates a skill is the
   watcher's to catch.

Deny messages name the way forward: an installer or a new skill names
`canary add`; a quarantine read names `canary check`.

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

def extra_skill_roots(home: str) -> list[str]:   # optional
    """User skills folders besides install_root (Codex: CODEX_HOME/skills)."""

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

## `canary setup [--level scan|guard]` and `canary doctor`

`setup` asks which level the person wants in a native dialog, with the
recommended one preselected (Guard when Claude Code or Codex is present).
`--level` skips that question, so an agent can start setup on the person's
behalf; Guard still needs the person's password in the macOS administrator
dialog, which an agent cannot answer.

| Level | Password | What setup does |
|---|---|---|
| Scan | no | Nothing machine-wide. Reports the existing library. |
| Guard | once | Installs Canary root-owned in `/Library/Application Support/SkillCanary`, a path macOS keeps root-owned all the way up (link `/usr/local/bin/canary`; 0.1.0 used `/usr/local/lib/skillcanary`, which old Homebrew installs leave owned by the person); writes the Claude Code drop-in `managed-settings.d/canary.json` and creates `/etc/codex/requirements.toml` when absent (else prints the block to add). |

The privileged step is one shell script passed to
`do shell script … with administrator privileges` as a string, never a file
on disk, so nothing can swap it while the dialog is open. Canary's own files
travel inside it as a base64 archive whose SHA-256 the script checks before
extracting. The script records the level and every file it created in
`/Library/Application Support/SkillCanary/state.json` (root-owned; setup reads a 0.1.0 `state.json` from the old location only as a hint to the previous level, because the person may control that folder, and never deletes inside it as root). Nothing read from disk authorizes a root operation by itself. Setup only
ever writes or removes its two policy files, and only when their content is
exactly what this or an earlier SkillCanary writes, or their hash is recorded
in the root-owned state; any other content is a manual step. Moving to
Scan removes those files.

Lockdown, a third level that made the two user skill roots root-owned, was
removed in the front-door program (2026-09-30). `canary setup --level
lockdown` is a usage error that names Guard, and so is asking the Python
API for it. When the root-owned `state.json` records Lockdown (never the
0.1.0 state the person may control), setup returns the two user skill roots
of the account running it (from the account database, not `$HOME`) to the
person, through the root-owned `canary _roots unlock`. That helper refuses to
run as anyone but the owner the setup step names (root), accepts only those
two roots, opens each folder from `/` without following links, skips a root
reached through a link, hands files back before their folders, and checks
and re-owns each regular file through one handle, never a file with more
than one name. A failed unlock fails the whole step: the recorded level stays
Lockdown (the state file survives the reinstall) and `doctor` keeps saying
so. The program itself stays installed at every
level, since the Mac installer may have put it there.

`canary doctor` reads `state.json` and checks the machine against it: the
install and the hook command are root-owned and not writable by the person,
each host's policy file carries the hook, and the hook's Python runs. On a
Mac still recorded at Lockdown it reports that, with the command that leaves
it; it reports a user skills folder still owned by root; and a recorded level
it does not know is reported as such, never as Scan. It prints the level, every gap in plain words, and the
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
privileged step, after it has run.

Setup never sets `allowManagedHooksOnly`, because that would disable the
person's own hooks; a managed hook cannot be disabled from user settings
anyway.

## `canary install [--json | --text] [--backend <name>] [--model <id>] [--timeout <seconds>] -- <installer command>`

Runs the person's own installer so that only checked files reach a skills
folder (`canary/install.py`; program 2026-09-30, slice B1). It accepts only
plain installer commands (`installers.kind`):

- `npx`, `bunx`, `pnpm dlx` or `yarn dlx`, optionally `-y`, then a `skills`
  package (`skills`, `@scope/skills`, `skills@<version>`) and `add`, `a`,
  `install` or `i`; or the `skills` command itself. A launcher option that
  picks another program (`npx -p`) is refused.
- `claude plugin install|i|update <name>@<marketplace>` with an optional
  `--scope user|project|local`.
- `claude plugin marketplace add <source>`.

Anything else is a usage error (exit 2). No option approves an install.

**Skills.** The installer runs with `HOME` set to an empty staging home in
the quarantine (holding empty copies of the person's top-level hidden
folders, so it finds the same agents) and its working folder set to an
empty staging project. Its Git and npm settings and npm cache stay the
person's. Its output goes to a log in the support folder, never to the
agent. Every folder holding a `SKILL.md` that lands under either staging
root is copied without links into a snapshot (a link or special file
refuses the whole install), named, and checked with `canary check`'s two
layers, four at a time; each skill costs one classifier call. The person
sees one dialog for everything the command adds. On approval, under `canary
add`'s commit lock, each snapshot is copied to the same place under the real
home or the real working folder and confirmed byte for byte, the links the
installer made between those skills (for example `.claude/skills/<name>` to
`.agents/skills/<name>`) are recreated, and the lockfile and guest list
record each skill. Nothing else the installer wrote is copied, including its
own record (so `npx skills list` does not show these skills). A failed
installer, a skill that already exists, two different skills with one name,
or an unsafe verdict installs nothing.

**Plugins** (owner decision 7). The plugin is installed into a staging
Claude Code folder (`CLAUDE_CONFIG_DIR`), after adding its marketplace there
from the source recorded in the person's `known_marketplaces.json`. The
installed folder is checked and shown once. On approval, the person's real
`claude plugin install` runs, and the folder Claude Code reports in
`installed_plugins.json` must match the checked bytes; otherwise SkillCanary
runs `claude plugin uninstall` and reports it. Claude Code loads plugins when
a session starts, so nothing uses the plugin before the comparison. A
marketplace add runs as given: it installs nothing an agent loads.

Result: `{"schema": "canary.install/1", "outcome": "installed" | "declined" |
"not_installed" | "refused" | "done", "verdict", "kind": "skills" | "plugin"
| "marketplace", "skills": [{"name", "verdict"}], "installed": [...],
"reasons": [...]}`, with `canary add`'s exit codes (`done` is 0).

Limits: the installer is the person's program and runs as them; staging
changes where it writes by default, not where it can write, so an installer
that writes to an absolute path elsewhere is the guest list's and the
watcher's to report.

## The guest list: `canary list [--json]`, `canary trust <folder>`, `canary session-start --host claude|codex`

SkillCanary records every skill in a skills folder, how it got there, and
every later change or removal (`canary/guestlist.py`). The record is an
append-only ledger, `ledger.jsonl` in `~/Library/Application Support/Canary`,
one JSON event per line, written under a file lock: `first_look`,
`baseline`, `arrived` (with `how`), `checked`, `approved` (with `how: canary
add`), `declined`, `refused` or `not_installed`, `changed`, `removed` and
`trusted`. A damaged line is skipped. Each skill is keyed by its resolved
path; a skill reached under several names is listed under each. Its
fingerprint covers every file's bytes, path and program bit, without `.git`.
Links inside a skill are recorded and followed (each folder once), so a
change to what a link points at is a change to the skill; past 5,000 files or
64 MB, the rest is left out. A cache keyed on names, sizes, modification and
change times and inodes keeps a scan from rereading unchanged skills; the
change time moves with every write and software cannot set it back. Skills
are fingerprinted before the lock is taken, so a large skill does not hold up
another session.

Every skill has one status:

- **yours**: in a user skills folder at setup's first look, or marked with
  `canary trust`. Changes are recorded and never reported. Only setup takes
  the first look, once per ledger: without a ledger, every skill counts as
  unchecked until setup runs again or the person trusts it.
- **checked**: installed by `canary add`. A change after approval is
  reported as **changed since approval**.
- **unchecked**: arrived any other way. Reported until the person trusts it
  or removes it.

The folders scanned are the user skills folders (each host's `install_root`
and `CODEX_HOME/skills`) and the `.claude/skills`, `.agents/skills` and
`.codex/skills` folders of the repository around the current folder (the
session's `cwd` for `session-start`). Setup's first look does not cover
repositories, so a repository's skills are reported in every session there
until the person runs `canary trust <repo>/.claude/skills`, which marks them
all as theirs (owner decision 6 of the front-door program). A cloned
repository's skills are what this report is for.

- `canary list` prints each skill, its status and path; `--json` prints
  `{"schema": "canary.list/1", "skills": [{"name", "path", "status",
  "changed_since_approval", "since"}], "unchecked": [...], "changed": [...]}`.
  Listing scans first, so it also records what changed.
- `canary trust <folder>` marks one skill, or every skill in a skills
  folder, as the person's.
- `canary session-start --host claude|codex` is the SessionStart hook that
  setup installs at Guard in both hosts (Claude Code matcher
  `startup|resume|clear`, Codex `startup|resume`). It prints nothing when
  nothing is unchecked or changed. Otherwise it prints one notice as
  `{"systemMessage": …, "hookSpecificOutput": {"hookEventName":
  "SessionStart", "additionalContext": …}}`, so the person and the agent
  both see it. It always exits 0, and any error is silence: the guest list
  never blocks a session.

The guest list is a report, not proof. The ledger lives in the person's
account; the hook keeps agents' file tools from rewriting it, but a shell
command, a tool the hook does not read (such as an MCP server's file tool),
or other software running as the person can change it.

## How people get Canary and use it

Canary itself is the one install that happens without Canary, so it only
arrives through channels that check integrity, and no agent ever reads a web
page to install it.

1. **Install:** `brew install skillcanary/tap/canary` (signed GitHub release
   behind a Homebrew tap), or a signed, notarized macOS `.pkg`. An agent may
   run that exact command when asked; it never fetches instructions from a page.
2. **Setup:** `canary setup` detects Claude Code and Codex, shows the two
   protection levels (Scan, Guard) with their trade-offs, recommends one, and
   asks for the password once for Guard. It then scans the
   existing library in report-only mode and prints the counts.
3. **Every install:** the person says "use Canary to install <link>" in chat,
   or runs `canary add <link>`. The agent only passes the link. Canary fetches
   into quarantine, scans, classifies, and asks the person in a native macOS
   dialog that summarizes publisher, version and capabilities in plain words.
   The agent receives only the outcome.
4. **Redirects:** at Guard and above, `npx skills add`, plugin installs and
   file-tool creation of a new skill are denied with the message "use `canary
   add <source>`", so the insecure path points to the secure one.
5. **Updates:** `canary update` fetches, shows what changed in plain words
   (for example "now adds a shell script"), and installs only after approval.

The Claude Code and Codex marketplace plugins are front doors: a descriptive
skill that teaches the agent to use `canary add` and, when `canary` is
missing, to tell the person the install command. Each plugin must scan
`LIKELY_SAFE` under Canary itself.

## Enforcement layers and their limits

SkillCanary is a front door (program 2026-09-30): it checks a skill before
any agent can use it, and does not try to stop software already running on
the Mac from changing files. Three layers, and what each covers:

1. **Install path.** `canary add` is the supported way in: fetch to quarantine,
   scan an immutable snapshot, install that exact snapshot. It is only as
   strong as the layers that stop other ways in.
2. **Managed hooks.** Claude Code: a drop-in under
   `/Library/Application Support/ClaudeCode/managed-settings.d/` with a
   `PreToolUse` hook and managed `permissions.deny` rules on protected paths.
   Codex: `[hooks]` in `/etc/codex/requirements.toml`, which users cannot
   override. Both deny agent tool calls that install a skill without the
   check, or read the quarantine. Known gaps, from each host's documentation:
   Codex hosted tools and tools that opt out of hooks never reach the hook;
   input sent with `write_stdin` to an already-approved process does not
   re-run the hook; hooks run concurrently; and a shell command can hide its
   target from any parser. Hooks are a guard, not proof.
3. **Detection.** The guest list (above) reports skills that arrived without
   the check or changed since approval, once per session. A watcher that
   holds a new, unchecked skill for the person's decision is in progress in
   the front-door program. Root-owned skill folders (Lockdown) were tried and
   removed: they blocked ordinary work, and the hook is not proof either.

Public claims follow the layers actually installed:

| Installed | What Canary may say |
|---|---|
| 1 and 2 | "Guards installs by agents in Claude Code and Codex." |
| any | Cursor, opencode and Gemini: "scanned and monitored, not enforced." |

The `canary add` dialog is the person's checkpoint; an agent that can
control the screen could click it, and no claim above says otherwise.

`canary doctor` prints which row applies to the machine it runs on.

Policy files are added, never replaced. Claude Code reads a drop-in
directory, so Canary owns one file there. Codex reads a single
`requirements.toml`: setup creates it only when absent; otherwise it prints
the exact block for the administrator to add and verifies it afterwards.
