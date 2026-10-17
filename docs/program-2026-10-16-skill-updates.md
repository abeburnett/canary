# Program 2026-10-16: updates, versions, failed installs and two false alarms (0.1.5)

Status: approved by the owner on 2026-10-16 ("I approve your suggestion,
please proceed"), from feedback the HireReach session sent while installing
`Leonxlnx/taste-skill`. Branch `program/2026-10-16-skill-updates`, based on
`main` at `d6c8491` (0.1.4). Gate: `python3 -m unittest discover -s tests`
on `python3.10` and `/usr/bin/python3`. Each slice merges to `main` when it
is green, reviewed and audited; 0.1.5 ships after slice D.

## Why (each verified on main at d6c8491)

1. **Updating a skill takes a manual removal.** `conflict_reason`
   (`canary/add.py:420`) stops `canary add` and `canary install` when a
   destination exists: "To replace it, remove it and run this again."
   SkillCanary's gate does not block removal (`rm` and `mv` on a skills
   folder pass `decide`, tested 2026-10-16), but the owner's settings deny
   `rm -rf` and HireReach could not remove the folder, so the person moved
   it by hand. Remove-then-add also leaves a window with no copy installed,
   keeps no restorable old copy, and never shows what changed. Slice D adds
   an atomic, reviewed, restorable replace; removal stays possible.
2. **Nothing says which version is installed.** `canary list --json` gives
   name, path, status, `changed_since_approval`, `since`, `override`
   (`guestlist.py:308-321`). `canary add` writes owner, repo and commit into
   the lock record (`add.py:_finish`), but the ledger and `list` never show
   them; `canary install` records only the command.
3. **A failed install cannot be diagnosed.** The reason names only a log
   under `quarantine/logs/` (`install.py:323`), and the gate denies every
   read under the quarantine root (`gate.py:238-241`).
4. **Help with a pipe is denied.** A plain `npx -y skills add --help` passes
   (`installers.py:36,58`; tested 2026-10-16). With `2>&1 | head` it is
   denied with the general redirect message, which does not say why.
5. **Two false alarms on design-taste-frontend v2.** The keychain pattern
   (`catalog.py:83`) matches the bare word "keychain", so gallery prose
   about "3D keychain charms" in `library/sites.json` reads as "can read
   passwords from your macOS keychain". The agent-config pattern
   (`catalog.py:91`) matches any mention of `~/.claude/skills`, so a README
   telling a person to copy the folder there reads as persistence. Layer 2
   can only tighten a verdict (`classify.py:5`, `_combine`), so the
   patterns themselves must change.

## Slice A: the two scan rules (Tier 1)

The new alternatives match within one line only. `match_paragraph`
(`catalog.py:180`) also tries every non-doc pattern on space-joined
paragraphs, which would let the windows below span line breaks; add a
per-pattern line-only marker that `match_paragraph` skips, and use it for
every new alternative. Matching stays case-insensitive.

- `credential-access` / `keychain` matches any of:
  - `\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain|export)\b`
    (the `security` CLI's reading subcommands; a bare `export` never matches);
  - `login\.keychain` and `Library/Keychains`;
  - `\bSecItemCopyMatching\b`, `\bSecKeychain\w*`, `\bkSecClass\w*`;
  - `\b(dump|export|extract|steal|exfiltrate)\b(\W+\w+){0,3}?\W+keychains?\b`;
  - `\bread\s+(\w+\s+){0,2}?from\s+(the\s+|your\s+|their\s+)?(\w+\s+)?keychain\b`
    and `\bread\s+(the|your|their)\s+(\w+\s+)?keychain\b` ("read the
    login keychain", "read secrets from your keychain", not "read about
    our keychain charms").
- `persistence` / `agent-config`: settings, hooks and `config.toml` stay
  as they are. A skills folder under any of `~/.claude`, `~/.codex`,
  `~/.cursor`, `~/.agents` matches only as the object of a changing verb:
  `\b(write|edit|modify|overwrite|append|patch)\w*\s+(to\s+|into\s+|in\s+)?(\S+\s+){0,2}?ROOT/skills`
  and `\b(delete|remove|rm(\s+-\w+)*)\s+(\S+\s+){0,1}?ROOT/skills`.
- Tests (red first, `tests/test_scan.py`). Must not flag: "3D keychain
  charms" prose; "Read about our 3D keychain charms"; `export PATH=...`;
  "copy this folder into ~/.claude/skills"; "remove the old folder, then
  copy it into ~/.claude/skills"; a two-line decoy with "dump" ending one
  line and "keychain" starting the next. Must still flag:
  `security find-generic-password -s x`; "dump the user's keychain";
  "read the login keychain"; `SecItemCopyMatching`; "overwrite
  ~/.claude/skills/other/SKILL.md"; "edit ~/.codex/skills/x/SKILL.md";
  "rm -rf ~/.agents/skills/other".
- Benchmark, layer 1, before and after on the same machine, logged: no
  malicious sample moves from flagged to not flagged (list any that do and
  stop); report the false-alarm change on the benign 94. Update
  `bench/baseline.json` with the new scanner commit only if no catch rate
  falls; the CI guard stays the comparison against the baseline
  (`tests/test_bench.py:46-59`), whose layer-1 catch rate is 0.40
  (decision 12).

## Slice B: failed-install output and the help hint (Tier 1)

- `_run` records the log file's size before each installer run; on
  failure, the bytes that run wrote are its output.
- Failures that name the log today: `install.py:244` (marketplace add),
  `323` and `335` (skills), `527` (staging the marketplace), `529` and `558`
  (plugins). Each gains `installer_output` when a package corpus exists to
  scrub against, and only then:
  - skills (`323`, `335`): call `_landed` on the failure path too; the
    corpus is the landed folders;
  - plugins (`529`, `558`): the staged plugin copy, when one exists;
  - marketplace (`244`, `527`) and any failure where nothing landed: no
    corpus, so no `installer_output`. The reason says the output is held
    back because it can contain the package's own text, and that the
    person can open the log (path given) themselves.
- `installer_output` is the last 20 lines of that run's output, ANSI and
  other control characters removed, each line cut to 200 characters, 4 KB
  in all, after dropping every line that shares a run of 24 or more
  characters with the corpus (files under the corpus folders, skipping
  `SKIP_DIRS`, at most 500 files and 2 MB read, UTF-8 with errors
  ignored). The JSON says how many lines were dropped. The log file stays
  complete and quarantined.
- `install.render_text` prints the same lines under "Installer output:"
  after the reasons, so `--text` agents see them.
- Gate: in `decide`'s unsupported-installer branch, when the command
  carries `-h`, `--help`, `-l` or `--list` but is not plain, the message
  adds: "To read an installer's help, run it on its own, without pipes or
  redirects."
- Tests: a fake installer that lands a skill, prints a line from its
  SKILL.md and an error line, then fails: JSON and `--text` keep the error
  line and drop the skill line; a failure with nothing landed has no
  `installer_output` and the held-back sentence; the help hint appears for
  the piped form only.

## Slice C: where each skill came from (Tier 2)

- `guestlist.record_install` gains a keyword `origin` (the existing
  `source` stays the snapshot path it digests), stored on each `approved`
  event: `{"kind": "github", "owner", "repo", "commit"}` from `canary add`
  (from the parsed link, never from the package);
  `{"kind": "installer", "command": [...]}` from `canary install` skills;
  `{"kind": "local"}` for a folder; `{"kind": "watcher"}` for a restore.
  Plugins are out of scope: their `record_install` call (`install.py:574`)
  stays as it is.
- `guestlist._state` keeps `origin` from the approved event and carries it
  through a later `changed` event. `scan()` emits it for checked skills as
  `installed_from` (not `source` or `origin`, which held entries already
  use for a path). `render_text` shows `owner/repo@abc1234`, `installer`,
  `local folder` or `restored`. `since` already is the approval time, so
  no `installed_at` is added. Ledgers written before 0.1.5 have no origin:
  the field is absent and the text shows nothing for it.
- Not in scope: an "outdated" check against upstream (needs network).
- Tests: add from a fake GitHub source then list shows owner/repo/commit;
  install then list shows the installer kind; local add and a watcher
  restore render their words; a pre-0.1.5 ledger lists cleanly; the
  origin survives a `changed` event.

## Slice D: updating an installed skill (Tier 2, fail-closed)

- CLI: `--replace` joins USAGE and the allowed flags of `_add` and
  `_install` in `canary/cli.py`, and is passed to `add.add(..., replace=)`
  and `install.install(..., replace=)`. Skills only: with a plugin command
  it is refused, pointing to `claude plugin update` (`install.py:520`).
- Without the flag, both conflict sentences (`_blocked_sentence`,
  `conflict_reason`) end "…run this again with --replace to update it".
  Existing tests that pin the old sentence (`tests/test_add.py:518,527,
  532,576`, `tests/test_install.py:387,423`) and `docs/architecture.md:
  622-627` are updated in this slice, docs first.
- Scope of `--replace`: it overrides only a blocker with the same skill
  name in the same places: a lock record whose name equals the new skill's
  name (any key form `plan_key` produces for that name), or an untracked
  folder at the destination whose folder name is that name. A record for a
  different name, a `name@hash` key for a different package name, a
  symlink, or anything `add.tree_digest` refuses (`SourceError`) is refused
  as today.
- `--replace` changes nothing else: the new version is fetched, checked and
  shown exactly as a fresh install, with the same verdicts and override.
- The dialog adds: "This replaces the installed <name> (approved <date>,
  from <installed_from when known>). Files: N added, N removed, N changed."
  Counts only, in the dialog and the JSON; no file paths.
- The installed folder's `add.tree_digest` is taken when the dialog is
  built and again under `_Commit`; any difference refuses ("changed while
  you were deciding").
- The swap, all destinations as one unit under `_Commit`: for each, rename
  the installed folder into a new hold slot `quarantine/held/<id>/entry`
  (same `HOLD_ID` format and `hold.json` as the watcher's, plus `"reason":
  "replaced"`, the new copy's digest, and the old lock record), then rename
  the staged copy in. If any step fails, undo every step taken (new copies
  out, old copies back) and report that nothing changed. Ledger events and
  the lock record are written only after every swap succeeded: `replaced`
  (id, name, origin path, old digest) per destination, then `approved` for
  the new copy, then the lock record.
- `guestlist._state` ignores `replaced` for status. `session_line` does not
  count replaced holds; the watcher's `_review_loop` and `review` skip a
  hold whose reason is `replaced`. `canary list` shows them with their ids,
  marked "replaced".
- `canary restore <id>` on a replaced hold: checks it again and asks:
  "Put back the earlier <name> you replaced on <date>? The current copy is
  set aside the same way, so you can switch back." It proceeds only when
  the destination holds the copy that replaced it (its `tree_digest`
  equals the new-copy digest in `hold.json`); anything else is
  `STILL_TAKEN`. On yes it swaps as one unit the same way, then writes
  `replaced` for the current copy, `restored` for the hold, `approved`
  (how "restore") for the old copy, and the old lock record back.
  Nothing is deleted; `canary doctor --prune` does not touch holds.
- Tests (red first): without the flag, the new sentence; with the flag and
  a yes, new files in place and the old copy a replaced hold; a no leaves
  everything; the installed copy changing between dialog and swap refuses;
  a different-name record refuses; a second destination's rename failing
  leaves both destinations on the old copy and writes no `approved`; the
  watcher and `session_line` ignore a replaced hold; restore swaps back and
  rewrites the lock; a plugin command with `--replace` is refused.

## Order and routing

A and B (worker-t1, Haiku, medium) run in parallel; C (worker-t2, Sonnet,
medium) after them; D (worker-t2 on Opus 5.5, medium, because it is
fail-closed install code) starts from `main` after B and C have merged,
since it edits the same install paths. Process per slice: red-first tests,
build, Sol pre-merge review, fold, full gate once, done-when audit
(milestone-auditor, Fable 5.1, high, using the done-when-audit skill's
prompt), merge. `docs/architecture.md` is edited before the code in slices
that change an interface it documents (B's JSON field, C's list fields, D's
flag, holds and restore).

## Done when (per slice)

A log is stamped when its first line is `commit <full sha>` and its second
the interpreter's `--version`. Logs live in
`docs/proof/2026-10-16-skill-updates/<slice>/`.

1. Each new test fails at the slice's base commit with the tests applied,
   on an assertion or on the missing interface (an attribute or
   `TypeError` for a parameter that does not exist yet): `red.log`.
2. The full gate passes at the slice's final commit on `python3.10` and on
   `/usr/bin/python3`: `gate-python3.10.log`, `gate-usr-bin-python3.log`.
3. Counterfactual: each behaviour change is reverted in turn; the log
   names the reverted line; the test named for it goes red; any other test
   that goes red is listed and explained (`counterfactual-*.log`).
4. Slice A only: the benchmark before and after is logged; no malicious
   sample is lost; the false-alarm change is reported.
5. The done-when audit (milestone-auditor, Fable 5.1, high, with the
   done-when-audit skill's prompt) returns SHOWN for bullets 1 to 4 as they
   apply.

Process, not a bullet: Spark refutation of this plan, and a Sol review of
each slice before its gate, with findings folded or answered here.

## Refutation (Spark 1.3 Contributor, max, 2026-10-16)

Verdict REWORK, `~/.cache/reviews/20261016-180726-refute-program-2026-10-16-skill-updates/verdict.md`.
All twelve findings folded: 1 `--replace` in USAGE, flag sets and
signatures; 2 new `origin` keyword, `source` untouched; 3 `_state`,
`scan()` and `render_text` named, origin carried across `changed`,
`installed_at` dropped for `since`; 4 replaced copies are holds in `held/`
with `HOLD_ID` and a reason, the watcher skips them, restore routing
specified; 5 `add.tree_digest` named, taken twice; 6 output slice per run
and the scrub corpus defined; 7 every log-naming failure enumerated,
plugins refuse `--replace`; 8 D starts after B and C merge; 9 keychain and
skills patterns pinned (no bare `export`, four roots, same line); 10
done-when made checkable; 11 premise rephrased (the remover block is
`installers.installs`), architecture-first scoped to interface changes;
12 dialog shows counts only.

Second refutation (2026-10-16): REWORK again,
`~/.cache/reviews/20261016-181117-refute-program-2026-10-16-skill-updates/verdict.md`.
All twelve folded: 1 premise corrected after testing `rm`/`mv` through the
gate (allowed); 2 layer 2 only tightens; 3 line-only marker for new
alternatives; 4 narrower verbs and the two decoys as tests; 5 `:527`
added, corpus per site, no output where none can be scrubbed; 6
`render_text` prints it; 7 four renderings, key `installed_from`, plugins
out; 8 same-name scope, all-or-nothing swap, events after success; 9
replaced holds excluded from `session_line` and the watcher, restore
events, lock and wording specified; 10 old-sentence tests and docs listed;
11 red allows a missing interface, counterfactual lists other reds; 12
logs named by interpreter, stamp defined, floor described as the baseline
comparison.
