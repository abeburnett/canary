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
   `claude plugin install <name>@<marketplace>` (owner decision 8) become
   `canary install -- …`, check the files, ask once, and install only the
   checked files.
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
  assumes deny-and-redirect for Codex. **Run live 2026-10-01 local
  (2026-10-02 UTC)** (Codex ran
  again before that date): Codex applies a rewrite only with `allow`, and
  ignores one with no decision, so Codex keeps deny-and-redirect
  (`docs/codex-facts.md`, "Rewriting an installer command").
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

## Slice C done-when audit (2026-10-01)

Auditor: Sonnet, read-only (the author was Opus 5.5). First pass: bullet 7
shown; bullet 8 blocked as re-scoped, because repository skills are not in
setup's first look; the deliberate-break results were blocked as asserted,
since no log was saved. The owner chose to report repository skills until
trusted (decision 6), bullet 8 was amended and a test added; the break run
was saved as a log (20 breaks, all red). The re-audit passed every bullet.
Gate evidence: step 1 of the CI workflow over the final tree on Python 3.10
and 3.9 (168 tests); the composite Action steps run only in CI, on the PR.

## Slice B1: installs through `canary install` (2026-10-01)

`canary install -- <installer command>` (`canary/install.py`) stages, checks,
asks once and copies skills into place; plugins follow decision 7. The
Claude Code hook rewrites a plain installer command into it; Codex is told
the command. Interface: `docs/architecture.md`, "canary install".

- Confirmed in Claude Code's hook documentation before building: hooks do
  not run again on a rewritten command; deny rules still apply to it; when
  several hooks rewrite one call the last to finish wins (now a limit in
  `SECURITY.md`).
- Tests: `tests/test_install.py` (19, with fake installers on `PATH`),
  three gate tests, and ten corpus cases moved from deny to rewrite.
- The code came before its tests in this slice, so the red evidence is the
  deliberate breaks: 29 after the review fold, each turning a named test
  red (saved log over the final commit). The failed-installer test could not fail at first
  (the fake wrote nothing on failure); it now writes a skill and exits 1.
- Permission probe (live, `claude -p`, 2026-10-01): a rewrite with no
  `permissionDecision` is checked against the person's permission rules as
  the replaced command (a rule for the new command let it run; a rule for
  only the old one did not); with `allow` it ran with no rule at all. The
  first version returned `allow`, which skipped the person's prompt for the
  installer; the rewrite now returns no decision. The first probe could not
  fail (Claude Code auto-allows `echo`), so its controls were redone with a
  script command that needs approval.
- Review: Muse Spark 1.3 Contributor refutation, read-only, one round. Its
  answer to "can a new skill reach a skills folder without the check?" was
  yes. Fixed, each with a test that failed first:
  - `@someone/skills` was accepted, so any npm package could run as the
    person and write a skill straight into a real folder; only the real
    `skills` package is accepted now, with its known options only (an option
    like `--dir` or `--metadata` was accepted before), and a skill that
    appears in a real skills folder during the staged run stops the install;
  - the installer's log, which can quote package text, sat where agents can
    read; it is in the quarantine now;
  - a failed real plugin update uninstalled the plugin that was there; and
    installing an already-installed plugin could uninstall it on a mismatch;
  - `marketplace add` ran with no question; the person agrees first now;
  - folder names from the package reached the agent's result; they must be
    usable skill names, and errors no longer quote them; the dialog now says
    where skills go; the rewrite carries only the command, timeout and
    description.
  Recorded, not changed: the real plugin install also changes Claude Code's
  records and marketplace copy, which are not compared (documented); an
  agent can pass `--backend none` itself, which caps the verdict at "needs
  your judgment" and still asks the person.
- Real skills install, owner's terminal, 2026-10-02: `canary install --
  npx skills add vercel-labs/agent-skills -g -y -s writing-guidelines`
  installed after one dialog (verdict NEEDS_REVIEW). The first attempt named
  a skill the repository does not have; the installer failed in staging and
  nothing was installed, as designed. Without `-a`, the skills installer
  installs into every agent it supports, so the skill landed as one copy in
  `~/.agents/skills` plus 46 links, most in agent folders created for it;
  the dialog listed all 47 places. The owner chose to leave them. Possible
  follow-up: the dialog warns when an install creates folders for agents
  the person does not have.
- Real plugin install, owner's terminal, 2026-10-02: `canary install --
  claude plugin install code-review@claude-plugins-official` staged and
  checked the plugin (NEEDS_REVIEW: it grants tools), asked once, ran the
  real install, and the installed folder
  (`~/.claude/plugins/cache/claude-plugins-official/code-review/ab024cdcfa7c`)
  matched the checked bytes, so it stayed installed.
- Live rewrite in a Claude Code session (2026-10-02, after merge and
  `canary setup`): an agent asked to `npx skills add vercel-labs/agent-skills
  -g -y -a claude-code -s web-design-guidelines` first added `; echo`, was
  denied with the message naming `canary install`, reran the installer on
  its own, and the rewritten command installed the skill after one dialog.
  Claude Code loaded it mid-session (it appeared in another running
  session's skill list without a restart).

## Slice B1 done-when audit (2026-10-01 local)

Auditor: Sonnet, read-only (the author was Opus 5.5). First pass: bullets 4
and 5 blocked. Bullet 4 lacked an owner decision for the
`<name>@<marketplace>` plugin form, a real installer run, and an ask-once
assertion for skills; bullet 5 had no probe result in `docs/codex-facts.md`.
Then the owner made decision 8 and ran a real skills install and a real
plugin install through `canary install`, and the live Codex probe ran (the
October 3 date in the plan was a stale usage-limit note). The ask-once
assertion and the Codex record were added. The re-audit passed every bullet,
checking the real installs against the machine (the installed folders,
`installed_plugins.json` and the ledger). Gate evidence: step 1 of the CI
workflow over the final tree on Python 3.10 and 3.9 (190 tests); 29
deliberate breaks red over the final code. Stated limit: the rewrite has not
run inside a live Claude Code session; that needs this branch's hook,
installed after merge.

## Slice B2: the watcher (2026-10-02)

`canary/watcher.py`, `canary watch` (the launch agent) and `canary restore`;
setup installs and loads the launch agent at Guard and removes it at Scan;
`canary doctor` reports when it is not running; the hook protects it
(decision 10). `canary add` and `canary install` now record their approval
before their files appear, so the watcher never holds them. Interface:
`docs/architecture.md`, "The watcher".

- Probe (owner's terminal, 2026-10-02,
  `scripts/probe-launch-agent-dialog.sh`): a launch agent showed a dialog and
  got the person's answer back, and launchd restarted it about ten seconds
  after it was killed.
- An accident on the way, now guarded: the first full test run used the real
  `launchctl` before the setup tests had a stand-in, and loaded a real
  watcher from a temporary test install. It watched the owner's real skills
  folders for a few minutes; the ledger shows it held nothing. It was
  unloaded at once. The setup tests now use a stand-in, and a test that
  reaches the real `launchctl` fails.
- Review: Muse Spark 1.3 Contributor refutation, read-only. (A first attempt
  was stopped while the disk was full; its log shows it had run no commands,
  so it did not cause that.) Its answer to "can a new skill stay in a watched
  folder without the check?" was yes, five ways. Fixed, each with a test:
  - an agent could run `canary trust` on its own skill; trust now asks the
    person in SkillCanary's dialog;
  - a folder there at start, or let go without a `SKILL.md`, was never
    looked at again when it gained one; such folders now stay watched;
  - a hold that failed was dropped; it is retried;
  - put-back moved the held entry without comparing it with what was
    checked; it must match;
  - holds were read from the ledger, which a shell can forge or break; they
    are read from the quarantine, with each origin confined to a watched
    folder, and survive a broken ledger;
  - one failed look ended the loop, and a restart took arrivals as given;
    the loop survives, and the watcher saves what it has seen (found by the
    author before the review too);
  - an entry that never stops changing is held after 30 seconds;
    `.canary-staging-*` names lost their exemption; doctor checks the launch
    agent file's contents; a failed put-back is reported, not raised.
  Recorded as limits in `SECURITY.md`: an approval is sampled once, when the
  entry settles; agents can trigger `restore` and `trust` dialogs
  repeatedly.
- Done-when audit, first pass (Sonnet): bullet 6 blocked, because the real
  launch agent has not run the watcher code (the evidence is tests with
  stand-ins plus the dialog probe). It also found that launchd's minimal
  `PATH` would hide `claude`, so a held skill would get only the first
  layer's check; the launch agent now runs with a `PATH` that has the
  folder holding `claude`, found when setup runs (one test, one break).
- Real run on the owner's Mac (2026-10-02 UTC, ledger events quoted):
  after PR 12's merge and `canary setup`, a throwaway skill created in
  `~/.agents/skills/watcher-test` was `held` at 21:41:53; the dialog was
  answered Cancel (`declined` at 21:42:00) and it stayed held. That watcher
  predated the `PATH` fix, so its check was the scanner's alone
  (NEEDS_REVIEW). After PR 13 and setup again (the launch agent's file now
  carries `PATH=~/.local/bin:/usr/bin:...`), the restarted watcher asked
  again about the held skill, the classifier ran (`checked` LIKELY_SAFE),
  the owner clicked Install, and it was `approved` (how: watcher) and back
  in place at 21:49:53. Not exercised for real: `canary restore` and the
  held list in `canary list` (covered by tests).
- Tests: `tests/test_watcher.py` (26), one setup test, five corpus cases.
  The code came before its tests, so the red evidence is the deliberate
  breaks: 31 after the review fold and the audit fix, each turning a named
  test red. The
  first run found one gap:
  the link test used an absolute target, which resolves the same from the
  quarantine; it now uses a relative one, as installers write them. The
  fold's run found another: the forged-hold test used an id the id check
  already refuses, so it never reached the origin check; it now uses a
  well-formed id.

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
7. (2026-10-01, before slice B) Plugins: `canary install` stages and checks
   a plugin, asks once, then runs the person's real `claude plugin install`
   and confirms the installed folder matches what was checked, uninstalling
   it on a mismatch. Copying a plugin into place would mean writing Claude
   Code's private, versioned registry (`installed_plugins.json`, absolute
   install paths, `enabledPlugins` in settings), which any release can
   change. Plugins load at session start, so nothing unchecked is used in
   between. Skills are copied from staging, as section 2 says.
8. (2026-10-02, after the slice B1 done-when audit) A plugin install goes
   through `canary install` only as `claude plugin install
   <name>@<marketplace>`: SkillCanary has to know the marketplace to stage
   the plugin. A bare `claude plugin install <name>` stays denied, with a
   message naming both routes.
9. (2026-10-02, before slice B2) The watcher holds the person's own new
   skills too: a skill folder they create, or a `git pull` that adds skills,
   is moved to the quarantine once it settles, with one dialog per skill to
   put it back. Any exception for "the person's own" would be open to an
   agent as well. Skills already present, and changes to them, are never
   held.
10. (2026-10-02, before slice B2) The watcher is protected the way the
   installers are: the hook denies a shell command naming the watcher's
   label or launch-agent file (as decision 5, a command that only mentions
   them is denied too), file tools may not rewrite that file, and `canary
   doctor` reports a gap when the watcher is not running.

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
   the riskiest code in the program). Split in two pull requests, same
   bullets: **B1** is `canary install`, the Claude Code rewrite and the
   Codex deny-and-redirect (bullets 4 and 5); **B2** is the watcher (bullet
   6). B2 also moves `canary add`'s guest-list record ahead of the rename,
   so the watcher never sees a checked install as unchecked.
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
