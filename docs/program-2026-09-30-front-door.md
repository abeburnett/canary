# Program 2026-09-30: back to the front door

Status: design for owner approval. Branch `program/2026-09-30-front-door`,
based on `main` (`140d87e`). PR 6 (the quote-glue fix) merges first; this
program then removes the code it patched.

## Goal

Every new skill passes a thorough check before any agent can use it, however
it was installed. After that, SkillCanary stays out of the way, and it tells
the person when a skill arrives or changes without going through the check.

People keep installing skills the way they already do: `npx skills add`,
`claude plugin install`, a folder copy, asking an agent. They never have to
learn a SkillCanary command.

## Where SkillCanary drifted

The owner asked for a front door that checks new skills thoroughly. To make
sure nothing could get around the door, we made the hook refuse *any* write
to skill and settings folders. A shell command can hide what it writes, so
the hook grew a shell parser, then exceptions for the reads and edits it
wrongly blocked, then rules for the holes those exceptions opened.

| | The door | The guard built around it |
|---|---|---|
| Code | `add`, `scan`, `classify`: about 1,600 lines | `gate`, `shellparse`, `edit`: about 1,300 lines |
| What it does | checks each new skill once and asks the person | inspects every agent tool call |
| Cost to the person | one dialog per install | blocked reads, `git`, heredocs and edits to their own skills; six review rounds; a live hole (PR 6) |

The guard never fully worked: `SECURITY.md` already says "Hooks are a guard,
not proof", because any script can write a file. This program keeps the door,
makes it stronger and measurable, and replaces the guard with interception at
install time and a record of what arrived.

## Design

### 1. The door stays, and becomes measurable

The check stays as it is: quarantine, the pattern scan, the isolated model
check, and one dialog in which the person decides. Three additions make it
stronger:

- **A benchmark.** `canary bench` runs `canary check` over a corpus of
  malicious and benign skills and prints the catch rate and the false-alarm
  rate. The corpus starts from the existing probe corpus and adds realistic
  attacks: instructions hidden in reference files, exfiltration, hooks and
  install scripts, obfuscated or look-alike text, and triggers that wait for
  a condition. CI fails when the catch rate drops. This is how SkillCanary
  can back a claim like "catches 99%": by measuring it, then saying it only
  if it holds.
- **A second opinion from another model family,** when the person has a key
  for one. It can only make a verdict stricter.
- **Updates are checked as diffs.** When an installed skill changes (an
  update, or a change found later), SkillCanary checks what changed, with
  the same scans.

### 2. Installs are intercepted where they happen

**Agent-run installs, Claude Code.** The hook recognizes installer commands
(`npx`, `bunx`, `pnpm dlx` or `yarn dlx` with `skills add`;
`claude plugin install` and `marketplace add`; `git clone` into a skills
folder). It rewrites each one, with Claude Code's `updatedInput`, into
`canary install -- <the original command>`. `canary install` works in three
steps:

1. It runs the original installer against a private staging home, so the
   files land in quarantine instead of a real skills folder.
2. It checks what landed, with the door's full check.
3. It asks the person. On approval, it copies the checked files into place
   and records them.

The agent and the person see a normal install with one SkillCanary dialog in
it.

**Agent-run installs, Codex.** It is unverified whether Codex hooks can
rewrite a command. The program probes that first. If they cannot, the hook
denies the installer with a message naming `canary install -- <same command>`,
and the agent reruns it. The person still sees nothing new.

**Installs from the person's own terminal,** or by any other route: a small
background watcher (a macOS launch agent watching the skills folders) moves a
new, unchecked skill folder into quarantine within about a second. It then
shows a notification and the same dialog, and puts the skill back on
approval. Nothing is deleted: a declined skill stays in quarantine, and
`canary list` shows how to restore it.

### 3. The guest list

SkillCanary records every skill and what happened to it: arrived (and how),
checked, approved or declined, changed, removed, with dates. It keeps these
in the lockfile and an append-only ledger in its support folder.

- `canary list` shows each skill as **checked**, **changed since approval**,
  **unchecked** (arrived another way) or **yours**.
- At session start, a Claude Code SessionStart hook prints one line when
  something is unchecked or changed, and nothing otherwise. It never blocks.
- **Your own skills are never flagged.** Skills present when SkillCanary is
  set up, and skills the person marks with `canary trust <folder>`, count as
  theirs. Their changes are recorded, never reported.

### 4. What the hook stops doing

Guard keeps the installer interception (section 2) and one narrow rule: an
agent's file tool (Write, Edit, `apply_patch`) cannot create a *new* skill
folder in a skills location; the message names `canary install`. Everything
else passes: reads, `git`, heredocs, settings, notes, and edits to existing
skills. A shell command that writes a new skill folder some other way is
caught by the watcher, not the hook.

Removed:

- the shell write parser and the text screen;
- `canary edit`, allowances and the Codex notes exception, since edits are
  no longer blocked;
- Lockdown's root-owned skill folders. Setup returns them to the person.

### 5. What SkillCanary claims

"Every skill installed through a supported installer, or found by the
watcher, is checked before any agent can use it. SkillCanary reports skills
that arrive or change any other way. It does not stop software that is
already running from changing files." `SECURITY.md`, the site claims and
`canary doctor` change to match.

## Done when

Slice A, the guard comes out:

1. Reads, `git`, heredocs, notes, settings and edits to existing skills pass
   in both hosts. The hook denies only uninterceptable installer commands
   and file-tool creation of a new skill folder.
2. The shell parser's write rules, the text screen, `canary edit`,
   allowances, the notes exception and Lockdown are gone; setup undoes
   Lockdown on a Mac that has it.
3. The door's tests and the scanner corpus pass unchanged.

Slice B, installs are intercepted:

4. In Claude Code, an agent's `npx skills add <owner/repo>` and
   `claude plugin install <name>` become `canary install -- …`, check the
   files, ask once, and install only the checked files.
5. The Codex rewrite probe's result is recorded in `docs/codex-facts.md`,
   with deny-and-redirect as the fallback.
6. The watcher moves a new unchecked skill folder into quarantine and shows
   the dialog; approval restores it.

Slice C, the guest list:

7. `canary list` and the ledger record arrivals, checks, approvals, changes
   and removals. The SessionStart line appears only when something is
   unchecked or changed.
8. Changes to the person's own skills are recorded and never reported.

Slice D, a measurable door:

9. `canary bench` prints catch and false-alarm rates over at least 50
   malicious and 50 benign skills, and CI fails when the catch rate drops.

Every slice: the suite passes on Python 3.10 and `/usr/bin/python3`;
deliberate breaks turn named tests red; an independent review, and a
done-when audit by a model other than the author.

## Unverified; probed before building on them

- Whether Codex hooks can rewrite a command.
- Whether `npx skills add` and `claude plugin install` honour a staging home
  (`HOME`, `CLAUDE_CONFIG_DIR`), and whether plugin install needs sign-in
  there.
- Whether a SessionStart hook runs before a session loads its skills.
- How quickly a launch agent reacts to a new folder, and whether a running
  session can load a skill inside that gap.

## Decisions for the owner

1. **The watcher:** on by default (I recommend it; it is the only thing that
   catches terminal installs without asking people to change habits), or
   opt-in?
2. **Lockdown:** remove it (I recommend it), or keep it as an opt-in strict
   mode?
3. **The benchmark target:** measure first, then set the number SkillCanary
   may claim. I recommend not publishing "99%" before the benchmark shows it.
4. **The protected-file program** (`program/2026-09-29-protected-file-edits`):
   close it unmerged, since edits are no longer blocked. I recommend closing
   it.
