# Program 2026-09-30: back to the front door

Status: approved by the owner on 2026-09-30, with every recommendation
below: the watcher is on by default, Lockdown is removed, SkillCanary
publishes a catch rate only after the benchmark measures it, and the
protected-file program is closed unmerged (branch deleted). Branch
`program/2026-09-30-front-door`, based on `main` (`1307a53`, after PR 6).

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
in an append-only ledger in its support folder.

- `canary list` shows each skill as **checked**, **changed since approval**,
  **unchecked** (arrived another way) or **yours**.
- At session start, a SessionStart hook (Claude Code and Codex) prints one
  line when something is unchecked or changed, and nothing otherwise. It
  never blocks.
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
   in both hosts. The hook denies only installer commands (all of them until
   slice B), file-tool creation of a new skill folder, the quarantine, and
   the mention-only commands in owner decision 5; failing closed, it also
   denies a Codex patch it cannot read and any internal error.
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
   Their own skills are those in a user skills folder at setup's first look
   and those they mark with `canary trust` (owner decision 6).

Slice D, a measurable door:

9. `canary bench` prints catch and false-alarm rates over at least 50
   malicious and 50 benign skills, and CI fails when the catch rate drops.

Every slice: the suite passes on Python 3.10 and `/usr/bin/python3`;
deliberate breaks turn named tests red; an independent review, and a
done-when audit by a model other than the author.

## Probe results (step 1, 2026-09-30)

- **Claude Code rewrites a command: verified live.** A PreToolUse hook that
  returned `permissionDecision: "allow"` with `updatedInput` changed
  `echo PROBE_A > out.txt` into `PROBE_B` before it ran (`claude -p`,
  Claude Code's current release).
- **Codex rewrites a command: documented, not yet run live.** The Codex hooks
  page says a PreToolUse hook rewrites a call with `permissionDecision:
  "allow"` plus `updatedInput`, and does not support `ask`. A live run waits
  until the Codex usage limit resets (2026-10-03). Until then the plan
  assumes deny-and-redirect for Codex.
- **SessionStart runs after the session lists its skills: verified live.** A
  skill created by a SessionStart hook was missing from the session's init
  event and the model said it was unavailable; a positive control (the skill
  created before the session) showed up in both. So the session-start line
  can only report; holding a skill back is the watcher's job.
- **Skills arriving mid-session: inconclusive.** The probe model backgrounded
  its wait and ended early on two of three runs. The plan keeps assuming what
  `docs/architecture.md` records: both hosts reload skills mid-session.
- **The watcher: fast, and it must wait for a folder to settle.** A kqueue
  watch noticed a new folder in under 1 ms (median 0.13 ms over 20 trials)
  and moved it in under 1 ms. Moving a folder on first sight broke a write
  into it in 1 of 40 trials, so the watcher waits until a new folder stops
  changing before it moves it.
- **Installer staging: verified by the owner, 2026-10-01.**
  `scripts/probe-installer-staging.sh`, run in the owner's terminal (the hook
  blocks agents from running installers):
  - `npx skills add mattpocock/skills -g -y -a claude-code --copy` with
    `HOME` set to a staging folder exited 0 and put all ten skills under the
    staging home's `.claude/skills`.
  - `claude plugin marketplace add` and `claude plugin install
    code-simplifier@claude-plugins-official` with `CLAUDE_CONFIG_DIR` set to a
    staging folder both exited 0, and the marketplace and plugin files landed
    under the staging folder's `plugins/`.
  - The real `~/.claude/skills`, `~/.agents/skills` and `~/.claude/plugins`
    had the same number of entries before and after (595, 2367, 10416).

  So `canary install -- <command>` can run the person's own installer
  against a staging home, check what lands, and copy only checked files into
  place.
- **Found on the way:** the hook denies `claude plugin install --help`,
  which only prints help. Slice A exempts help and list commands.

## Slice A1: the hook (2026-09-30 to 2026-10-01)

The hook now stops only installs that skip the check (installer commands,
`git clone` into a skills folder, a file tool creating a new skill) and the
quarantine; everything else passes. `canary edit`, allowances, the Codex
notes exception and the shell write parser are gone (about 2,200 lines
removed). Contract: `docs/architecture.md`, "canary hook", rules 1 to 6.

- 96 hook cases in `tests/test_corpus.py` (28 allow, 68 deny), 171 runs over
  both hosts. Against the hook before A1, 27 allow cases were denied.
- Review: Muse Spark 1.3 Contributor, read-only, two rounds.
  - Round 1 found installer commands that the first text pattern missed
    (quoting, line continuations, `npx -p`, `npm exec`, options before
    `clone` and between `plugin` and its verb), and three quarantine gaps.
    One reproduction was wrong (`npx\\<newline>skills` joins into the word
    `npxskills`, checked in bash); the form with a space is real and covered.
  - Round 2 found that a parser of what *runs* could still be beaten by
    shell keywords, functions, wrapper options, variables, a fake heredoc
    marker, `find -exec` and `$"..."`. Instead of patching a third time, the
    check now looks for the installer's own words anywhere in the tidied
    text. Accepted cost: `echo` or a heredoc that only mentions an installer
    is denied. All 18 round-2 forms are covered.
- Deliberate breaks: every rule in `canary/gate.py` and
  `canary/installers.py` has a named case that turns red when the rule is
  removed (36 breaks run).
- Out of reach, stated in the contract: a command assembled from pieces
  (`npx $X add`) and a program that starts an installer itself. The watcher
  (slice B) reports what they put in a skills folder.
- No third review round (the two-round limit); the words-based check has had
  no independent review of its own.

## Slice A2: Lockdown removed (2026-10-01)

Lockdown can no longer be chosen (`canary setup --level lockdown` and the
Python API both refuse it and name Guard). A Mac whose root-owned state still
records Lockdown gets its two user skill folders back through `canary setup
--level guard`. `canary doctor` drops the Lockdown-only gaps (links and hard
links in skills folders; the owner's 2026-09-30 doctor gap was one), and
`canary add` loses its administrator install path.

- Review: Muse Spark 1.3 Contributor, read-only, one round. Confirmed and
  fixed, each with a test:
  - (blocking, older than this slice) a Lockdown level in the 0.1.0 state
    file, which the person controls, started the root unlock, and setup took
    the home folder from `$HOME`, so root could be aimed at another
    account's skill folders. Now only the root-owned state starts it, and
    the home comes from the account database;
  - a skipped or failed unlock still recorded Guard (the state file was lost
    when the install was replaced, and a missing helper was skipped);
  - the root-only helper accepted any folders from any caller; it now
    accepts only the two known folders, as the owner the setup step names;
  - `doctor` called an unknown recorded level Scan, and did not report a
    skills folder still owned by root;
  - `canary add` on a Mac left at Lockdown blamed a changed package; it now
    names the unwritable folder and the setup command before asking;
  - `setup("lockdown")` from Python reported "cancelled".
- Plausible, not reproduced: a race in handing back a folder before its
  contents. The unlock now works bottom up and checks and re-owns each file
  through one handle; no test can create the race.
- Deliberate breaks: 16 (15 in setup, 1 in add), each turning a named test
  red.

## Slice A done-when audit (2026-10-01)

Auditor: Sonnet, read-only (the author was Opus 5.5). First pass: bullets 2
and 3 shown; bullet 1 blocked as re-scoped, because the hook also denies
mention-only installer commands, the quarantine and every installer until
slice B. The owner accepted all three (decision 5) and bullet 1 was amended;
the re-audit passed it. Gate evidence: step 1 of the CI workflow over the
final tree on Python 3.10 and 3.9; step 2 (the composite Action on GitHub)
runs only in CI. Limit the auditor noted: the Lockdown unlock has not been
run as root on a real Lockdown Mac.

## Slice C: the guest list (2026-10-01)

`canary/guestlist.py` keeps the ledger and works out each skill's status;
`canary list`, `canary trust` and `canary session-start` use it; `canary add`
records its checks, approvals and declines; setup takes the first look and
installs the SessionStart hook in both hosts; the hook denies file-tool
writes to the ledger and the lockfile. Interface: `docs/architecture.md`,
"The guest list".

- Tests: `tests/test_guestlist.py` (18), two in `tests/test_setup.py`, and
  four hook cases in the corpus (three record writes denied, a read
  allowed).
- Review: Muse Spark 1.3 Contributor, read-only, one round, 10 findings.
  Fixed, each with a test that failed first:
  - a same-size edit with its modification time put back reused the cached
    fingerprint; the cache key now includes the change time and inode;
  - a change to a file a link inside the skill points at went unseen; links
    are now followed, each folder once, within a size limit;
  - a deleted ledger made every skill "yours" again; only setup takes the
    first look now, and any other scan reports skills it has no record of;
  - a refused install, and one stopped before the dialog, were not recorded;
  - one skill under two names showed only one; both are listed.
  Also fixed: fingerprinting before taking the ledger lock; `canary list`
  and `canary trust` report a file error instead of a traceback; the docs
  now say `list` scans the current repository too.
  Recorded, not changed: a tool the hook does not read (an MCP server's file
  tool) can write the ledger, as with every hook rule (documented); an
  unknown `--host` prints nothing, which only a hand-edited hook command
  can cause. Repository skills are not in setup's first look, so they are
  reported until trusted; the audit called that a re-scope of bullet 8, and
  the owner accepted it (decision 6).
- Deliberate breaks: 20, each turning a named test red. The first run found
  one gap: the "never fails the session" test fed a damaged ledger, which is
  skipped without an error, so it could not fail; it now makes the scan
  itself raise.
- Not verified here: that a SessionStart notice reaches the agent before it
  uses a skill in a live Claude Code or Codex session. The hook's output
  shape follows each host's documentation.

## Unverified; probed before building on them

- Whether Codex hooks can rewrite a command.
- Whether `npx skills add` and `claude plugin install` honour a staging home
  (`HOME`, `CLAUDE_CONFIG_DIR`), and whether plugin install needs sign-in
  there.
- Whether a SessionStart hook runs before a session loads its skills.
- How quickly a launch agent reacts to a new folder, and whether a running
  session can load a skill inside that gap.

## Owner decisions (2026-09-30)

1. The watcher is on by default.
2. Lockdown is removed; setup returns locked skill folders to the person.
3. The benchmark measures first; SkillCanary publishes a catch rate only
   once the benchmark shows it.
4. The protected-file program is closed unmerged; its branch is deleted.
5. (2026-10-01, after the slice A done-when audit) The hook may also deny:
   a shell command that only mentions an installer (`echo`, a heredoc, a
   commit message, `git clone` text naming a skills folder), because the
   installer's words decide and parsing what runs kept losing to shell
   tricks; reads, writes and shell commands touching the quarantine, as
   before; and every installer command until slice B routes them through
   `canary install`.
6. (2026-10-01, after the slice C done-when audit) Skills in a repository's
   skills folders are not part of setup's first look. They are reported as
   unchecked in every session in that repository until the person runs
   `canary trust <repo>/.claude/skills` (or removes them), because a cloned
   repository full of skills is the main case the guest list exists to
   catch.

## Plan

Each step ships as its own pull request, so the friction goes away as soon
as step 2 merges instead of at the end. The coordinator is Opus 5.5, because
the hook and installer work is fail-closed security work (the owner's
escalation list). Reviews and audits go to a model other than the author.
Hook refutations go to Muse Spark 1.3 Contributor (`spark-muse`, read-only):
two of this week's Fable and Opus refutations were stopped by a safety
classifier before probing, and Spark completed its review.

1. **Probes, before any design depends on them** (coordinator, about half a
   day). Answer the four questions under "Unverified" with runs that could
   fail, and record the answers in `docs/architecture.md` and
   `docs/codex-facts.md`. If a probe fails, the owner decides the fallback
   before step 4 starts.
2. **Slice A: take the guard out** (coordinator). This is the step that
   removes the everyday friction.
   - Write the new hook's cases first: the reads, edits, heredocs and
     `git` commands that must pass, and the installer commands and
     file-tool skill creations that must not.
   - Delete the shell write parser, the text screen, `canary edit`,
     allowances, the notes exception and Lockdown; keep the installer rule
     and the new-skill-folder rule.
   - Setup undoes Lockdown on a Mac that has it; `canary doctor` drops the
     Lockdown gaps, which also clears the owner's hard-link gap.
   - Review: Spark refutation of the remaining hook; done-when audit.
   - The owner reinstalls with `python3 bin/canary setup --level guard`
     from an updated main checkout.
3. **Slice C: the guest list** (coordinator, or a worker with a frozen
   contract). The ledger, `canary list`, `canary trust`, and the
   SessionStart line. It comes before interception because interception and
   the watcher both write to the ledger.
4. **Slice B: intercept installs** (coordinator; the installer staging is
   the riskiest code in the program).
   - `canary install -- <command>`: run the installer against a staging
     home, check, ask, copy, record.
   - The Claude Code hook rewrites installer commands with `updatedInput`;
     Codex rewrites or denies with a redirect, depending on the probe.
   - The watcher: a launch agent that moves a new unchecked skill folder
     into quarantine and shows the dialog.
   - Review: Spark refutation aimed at one question: can a new skill reach
     a skills folder, usable by an agent, without the check?
5. **Slice D: the benchmark** (runs in parallel with steps 3 and 4). A
   worker builds the malicious and benign corpus from a frozen contract;
   the coordinator reviews every sample, adds `canary bench` and the CI
   check, and records the first catch and false-alarm rates. The owner then
   sets the target.
6. **Claims and docs.** `SECURITY.md`, the README, the SkillCanary skill that
   setup installs, `canary --help` and `doctor` describe the front door and
   what it does not do. The site copy changes only after step 5's numbers
   exist.

Per slice: the tests run on Python 3.10 and `/usr/bin/python3` before each
commit, the review runs before the full gate, and the done-when audit runs
before the slice is called done.
