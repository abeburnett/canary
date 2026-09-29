# Program 2026-09-28: editing installed skills

Status: approved by the owner on 2026-09-28. Branch
`program/2026-09-28-skill-edits`. Owner decisions: build both slices;
allowances need the password and are stored root-owned; a text-only edit
without an allowance gets a one-click dialog; Fable runs the independent
refutation.

Changes made while building slice A, with the reason for each:

- The "exists on disk" exception applies only to git, not to unknown
  commands. Applied to unknown commands, it would let `rsync /tmp/evil/
  ~/.claude/` or `unzip -d <repo>` create a skills folder that is not there
  yet. `python3 tool.py <repo root>` therefore stays denied, as before.
- Writes into any repository's `.claude/skills`, `.agents/skills` or
  `.codex/skills` are protected, not only those above the working folder.
  Before, `echo x > <other repo>/.claude/skills/x/SKILL.md` and
  `git -C <other repo> reset --hard` passed.
- The shell lexer is SkillCanary's own. shlex cannot tell a quoted `;` from
  a separator, and it read `cp a b 2>/dev/null` as a copy to `2`, which the
  old hook allowed into a skills folder.

## Problem

At Guard, SkillCanary makes installed skills painful to live with, and people
will uninstall it. Observed on 2026-09-28:

1. The hook blocks reads and mentions. `ls <skills> | head`, `grep` and
   `git -C ~/.agents status` are denied, and so is any AskUserQuestion or
   spawn_task whose text names a skills folder. Any unknown command given a
   repository path is denied too, because a repository contains its own
   `.claude/skills`.
2. There is no approved way to change an installed skill. `canary add` only
   installs new ones, so an approved one-line edit to a SKILL.md, or the
   lessons distillation's allowed update to two Markdown files, took a side
   branch, a patch file and several manual rounds.

The same probes found two writes the hook lets through today:
`python3 -c "open('…/.claude/skills/x.md','w')"` (a simple command whose path
sits inside a quoted string), and `git checkout <branch>` run inside
`~/.agents`, which rewrites its skills folder without naming it.

## Design

### 1. The hook tells reads from writes

- **Known read-only commands pass.** A command, or a pipeline or `&&`/`;`
  chain, made only of known read-only commands (`ls`, `cat`, `head`, `tail`,
  `wc`, `grep`, `find` without `-exec`/`-delete`/`-fprint*`, `stat`, `file`,
  `diff`, `du`, `echo`, read-only `git` subcommands, and a few more) is mapped
  exactly: reads only, so it passes unless it reads the quarantine. Output
  redirection is a write and is checked like any other write; `2>/dev/null`
  and `2>&1` are allowed. `cd` inside a chain moves the working folder for
  what follows.
- **Writes stay fail-closed.** `sed -i`, `tee`, `>`/`>>`, `cp`, `mv`, `rm`
  into a protected folder are denied as now. `git` subcommands that touch only
  the index and history (`status`, `log`, `diff`, `show`, `blame`,
  `ls-files`, `rev-parse`, `branch`, `tag`, `add`, `commit`, `fetch`,
  `push`) pass, so agents can still commit in `~/.agents`. Every other
  subcommand, including aliases and unknown ones (`checkout`, `merge`,
  `pull`, `reset`, `stash`, `apply`, `rebase`, `config`, …), counts as a
  write to the whole repository: the `-C` folder or working folder, walked up
  to the repository root. It is denied when that repository holds a
  protected folder. `--output` on `log`/`diff`/`show` is a write to its file.
  Global options other than `-C` and `--no-pager` (`-c`, `--git-dir`,
  `--work-tree`) cannot be mapped and are screened as text.
- **Unknown commands are screened as text, and their path arguments still
  count.** A command the hook has no model of (`python3`, `node`, `vim`) is
  denied if its text names a protected folder. This closes the `python3 -c`
  hole. Its path arguments, including `--opt=<path>` values, still count as
  writes, so `python3 tool.py ~/.agents` stays denied.
- **Heredocs stay screened as text.** A command whose text names a protected
  folder, such as a heredoc that writes a note mentioning one, is still
  denied, and the message says to write that file with the Write tool.
- **Tools that only carry text pass.** AskUserQuestion, TodoWrite, Agent,
  SendMessage, spawn_task and plan-mode tools cannot touch files. Anything
  they start is itself checked by the hook. Other MCP tools are still
  screened as text, because their effects are unknown.

### 2. `canary edit`: the sanctioned route

```
canary edit start <skill>        # copy the installed skill into a draft; prints its path
  … the agent edits the draft with ordinary Edit/Write tools …
canary edit apply <draft>        # scan the change, ask the person once, write it
```

- `start` takes a name, found in the user skill folders, or a path to a
  skill folder in any protected skills folder, including a repository's own
  `.claude/skills` or `.agents/skills`. It follows a link to the real folder,
  so `~/.claude/skills/x -> ~/.agents/skills/x` edits the real one. A folder
  that no protected location covers is refused ("edit it directly"). It
  copies the skill, without `.git`, into
  `~/.skillcanary/drafts/<name>-<id>/skill/` and records the fingerprint of
  every file it copied.
- `apply` first takes a private snapshot of the draft, so the agent cannot
  change it while the person reads the dialog. It compares the snapshot with
  the installed skill file by file, then refuses if the installed skill
  changed since `start` ("start again", so one session can't undo another's
  edit).
- **Canary scans the change, not the whole skill.** Layer 1 and layer 2 run
  on a package made of only the added and changed files. Canary also compares
  the capabilities of the old and new skill. An `UNSAFE` change is refused
  without asking anyone.
- **Change classes:**
  - *Text change:* every added, changed or removed file is a document on the
    inert allowlist, neither version of it has a capability, and the
    SKILL.md frontmatter is byte-for-byte unchanged.
  - *Code change:* everything else: a script, a `bin/` file, a program bit, a
    hook, `allowed-tools`, inline shell, an MCP or package manifest, an
    unrecognised file, any frontmatter change, or any change to a file that
    already has a capability. A change to an existing script counts even
    when the skill already had scripts. A change to the `description` is a
    code change too: it is the text every session loads at start, and it
    decides when the skill runs, so expect the caution dialog for it.
  - A draft without `SKILL.md`, or with a link or special file, is refused.
- **Who decides:** one native dialog, as with `canary add`. A text change
  shows "Apply" as the default. A code change uses the caution icon,
  defaults to Cancel, and lists what the edit adds in plain words. At
  Lockdown every edit also goes through the administrator step (password or
  Touch ID), which re-checks the staged files' fingerprint as root.
- **Writing:** file by file, under the same lock `canary add` uses. Inside
  the lock, right before writing, SkillCanary re-checks that the installed
  skill still matches the draft's starting point. Each file goes to a
  temporary file beside it, and SkillCanary checks its fingerprint before
  renaming it into place. Files outside the change, including `.git`, are
  never touched, so a skill folder inside a git repository shows a normal
  diff that the agent or the person commits. A skill recorded in the
  lockfile gets its new fingerprint and an `edited_at` time, so
  `canary doctor` does not report it as changed outside SkillCanary.
- If nobody answers (for example in a scheduled run), nothing is written and
  the draft stays. The person can run `canary edit apply <draft>` later from
  their own terminal. That replaces the side-branch-and-patch workaround.
- Every applied edit is logged to
  `~/Library/Application Support/Canary/edits.jsonl` with the skill, the
  files, their fingerprints before and after, the change class and the
  approval route. The previous versions of the files are kept beside the
  log, so an edit can be undone by hand.

### 3. Scoped, expiring allowances

```
canary edit allow <skill> "<pattern>" [--days N]   # the person approves in a dialog
canary edit allowances                              # list them
canary edit revoke <skill> "<pattern>"
```

An allowance lets `canary edit apply` skip the dialog for one skill and one
file pattern, until it expires. Example:
`canary edit allow orchestrate "references/lessons-*.md" --days 7`.

- **Only the person creates one, with their password.** The agent can run
  the command; the approval is the macOS administrator dialog (password or
  Touch ID). Allowances are stored root-owned beside `state.json` in
  `/Library/Application Support/SkillCanary/`, so no process running as the
  person, agent or script, can create or widen one. A plain dialog would not
  be enough: at Guard an agent that controls the screen could click it, and an
  allowance lasts days, not one install. Revoking also takes the password;
  expiry needs none. Allowances need Guard, because at Scan nothing blocks
  the edit in the first place.
- **What it covers:** changes to existing files that match the pattern, where
  the pattern can only match `.md` files other than `SKILL.md`, and only text
  changes. It never covers adding, removing or renaming files. Default 7
  days, at most 30.
- **Untrusted input.** The lessons inbox is written by many sessions, so
  text copied from it may carry an injection. An allowance therefore applies
  only when all of these hold; otherwise the edit falls back to the dialog:
  - the change's scan is `LIKELY_SAFE` with layer 2 available (no model, no
    skipped dialog);
  - the change adds at most 200 lines and 16 KiB;
  - it adds no URL and no shell fence (```` ```sh ````, `bash`, `zsh`,
    `shell`, `console`, or ```` ```! ````). The two lessons files contain
    neither today, so this does not block the distillation.
- After an unattended apply, SkillCanary shows a macOS notification naming
  the skill and the files. The log keeps the diff and the previous versions.
- **What Canary cannot check.** A hook cannot tell which session or
  scheduled task is calling, so the allowance covers files and a time window,
  not a task, and the docs will say so. Text that reads as ordinary advice
  but steers an agent can pass both scanners. The narrow file pattern, the
  size cap, the log and the expiry limit how far it can spread; they do not
  prevent it.
- At Lockdown, allowances do not apply: every edit needs the password,
  because that is Lockdown's promise.

### 4. The denial message names the route

Writes into a skill folder get: "SkillCanary protects this skills folder. To
change an installed skill, run `canary edit start <name>`, edit the draft it
prints, then run `canary edit apply <draft>`; the person approves in a
dialog. To install a new skill, use `canary add <link>`. Reading this folder
is allowed." Writes to settings or policy files keep a message without the
edit route, because `canary edit` does not change settings. A command denied
only because its text names a protected folder gets: "SkillCanary could not
tell whether this command changes the protected folder it names. To read,
use plain commands (`ls`, `grep`, `cat`) or the Read tool. To write a file
whose text mentions the folder, use the Write tool. To change a skill, use
`canary edit`."

### 5. Shipped for every user

The SkillCanary skill that `canary setup` installs (`canary/frontdoor.py`,
`skills/canary/SKILL.md`, the Codex plugin copy) gains a "When the person
wants to change an installed skill" section. `canary --help`,
`docs/architecture.md` (decision rules and the new command), `README.md` and
`SECURITY.md` (the allowance's limits) change to match. Existing installs pick
up the new skill text the next time `canary setup` runs.

## Done when

Slice A: the hook.

1. In both hosts, reads pass: `ls <skills> | head`, `grep -rn x <skills>`,
   `wc`, `cat`, `find` without actions, `git -C ~/.agents status|log|diff`,
   `git -C ~/.agents commit`, and AskUserQuestion, spawn_task and Agent calls
   that mention a skills folder. `git checkout` passes in a repository whose
   skills folders do not exist.
2. In both hosts, writes stay denied: `>`, `>>`, `tee`, `sed -i`,
   `cp`/`mv`/`rm`, `find -delete`/`-exec`, `git checkout|merge|reset|stash|pull`
   and git aliases in or into a repository that holds a skills folder (with
   `-C`, with `cd … &&`, and from a subfolder of that repository),
   `git log --output=<skills>/x`, `python3 -c` naming the folder,
   `python3 tool.py ~/.agents`, and every existing `tests/test_gate.py` case.
3. A deny for a skills folder names `canary edit`; a settings deny does not;
   a text-screen deny names the Write tool.
4. A deliberate break (treating `sed` as read-only, or dropping the git
   worktree rule) turns a named test red.

Slice B: `canary edit`.

5. `start` then `apply` with a Markdown-only change writes exactly the changed
   files after one approval, leaves `.git` and other files untouched, logs
   the edit, and updates the skill's lockfile entry. A decline writes nothing
   and keeps the draft. A repository skill can be edited by path. A draft
   without `SKILL.md` is refused.
6. A new script, a program bit, an `allowed-tools` or `hooks` frontmatter
   change, inline shell, or an edit to an existing script is a code change
   (caution dialog, Cancel default); an `UNSAFE` change is refused without a
   dialog.
7. A draft changed after the snapshot, or an installed skill changed since
   `start` (checked inside the lock), writes nothing.
8. Creating an allowance runs the administrator step and writes it
   root-owned; an allowance file that is not root-owned, or is writable by
   others, is ignored. An allowance applies a matching text change with no
   dialog. It does not
   apply after expiry, to `SKILL.md`, to a new file, to a code change, to a
   change with a finding, over the size cap, with a new URL or code fence,
   when layer 2 is unavailable, or at Lockdown. The dialog runs instead in
   each of those cases.
9. At Lockdown the edit goes through the administrator step, and a staged file
   changed before that step is not written.
10. The front-door skill text, `--help` and the docs describe the route; the
    front-door test still passes.
11. `python3 -m unittest discover -s tests` passes, including
    `tests/test_corpus.py`, and an independent refutation pass finds no
    bypass.

## Not in this program

`canary update` for fetched skills, an `undo` command, and editing settings
files through Canary. `AGENTS.md` files in the working folder and its parents
stay protected with no edit route: the Codex adapter protects them, and both
adapters' locations apply in both hosts, so `Write ~/workspace/AGENTS.md` is
denied in Claude Code too. That is the next likely complaint.
