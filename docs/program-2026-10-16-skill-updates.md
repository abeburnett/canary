# Program 2026-10-16: updates, versions, failed installs and two false alarms (0.1.5)

Status: approved by the owner on 2026-10-16 ("I approve your suggestion,
please proceed"), from feedback the HireReach session sent while installing
`Leonxlnx/taste-skill`. Branch `program/2026-10-16-skill-updates`, based on
`main` at `d6c8491` (0.1.4). Gate: `python3 -m unittest discover -s tests`
on `python3.10` and `/usr/bin/python3`. Each slice merges to `main` when it
is green, reviewed and audited; 0.1.5 ships after slice D.

## Why (each verified on main at d6c8491)

1. **An agent cannot update a skill.** `conflict_reason` (`canary/add.py:420`)
   stops `canary add` and `canary install` when a destination exists: "To
   replace it, remove it and run this again." The gate treats a shell
   command that writes into or moves a skills folder as an install
   (`installers.installs` with `in_skills`, `gate.py:206-218`), so the agent
   cannot remove it either; the person had to `mv` it by hand.
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
   telling a person to copy the folder there reads as persistence. The
   skill is over the classifier's 256 KB input, so no AI review could
   overrule them.

## Slice A: the two scan rules (Tier 1)

Both patterns keep their current matching mode (the tuple's flag; same
line-or-paragraph behaviour as today) and are case-insensitive as today.

- `credential-access` / `keychain` matches any of:
  - `\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain|export)\b`
    (the `security` CLI's reading subcommands; a bare `export` never matches);
  - `login\.keychain` and `Library/Keychains`;
  - `\bSecItemCopyMatching\b`, `\bSecKeychain\w*`, `\bkSecClass\w*`;
  - an access verb, then up to four words, then "keychain":
    `\b(read|dump|export|extract|access|query|steal|copy)\b(\W+\w+){0,4}?\W+keychains?\b`.
- `persistence` / `agent-config`: the settings, hooks and `config.toml`
  alternatives stay as they are. Skills folders match only after a changing
  verb on the same line, up to 40 characters before any of the four roots:
  `\b(write|edit|modify|overwrite|append|delete|remove|replace|patch)\w*\b.{0,40}(~/\.claude|~/\.codex|~/\.cursor|~/\.agents)/skills`.
- Tests (red first, `tests/test_scan.py`): "3D keychain charms" prose is not
  credential access; `security find-generic-password -s x`, "dump the
  user's keychain" and `SecItemCopyMatching` still are; `export PATH=…` is
  not; "copy this folder into ~/.claude/skills" is not persistence;
  "overwrite ~/.claude/skills/other/SKILL.md" and "edit ~/.codex/skills/x"
  still are.
- Benchmark, layer 1, before and after on the same machine, logged: no
  malicious sample moves from flagged to not flagged (list any that do and
  stop); report the false-alarm change on the benign 94. Update
  `bench/baseline.json` with the new scanner commit only if no catch rate
  falls; `tests/test_bench.py`'s floor stays at 0.40 (decision 12).

## Slice B: failed-install output and the help hint (Tier 1)

- `_run` records the log file's size before each installer run; on failure
  the slice of the log that run wrote is the run's output.
- Every failure that names the log today gains `installer_output` in the
  JSON: `install.py:244` (marketplace), `323` and `335` (skills), `529` and
  `558` (plugins). It holds the last 20 lines of that run's combined output,
  ANSI and other control characters removed, each line cut to 200
  characters, 4 KB in all. The text reason says the output is in that field.
- The agent never reads skill text, and installer output can echo it (a
  description). Before the staging folders are removed, drop every output
  line that shares a run of 24 or more characters with the package text:
  the files under the folders the installer landed (`_landed`), skipping
  `SKIP_DIRS`, at most 500 files and 2 MB read, decoded as UTF-8 with
  errors ignored. When nothing landed, nothing is dropped. The JSON says
  how many lines were dropped. The log file stays complete and quarantined.
- Gate: when a denied installer command carries `-h`, `--help`, `-l` or
  `--list` but is not plain, the message adds: "To read an installer's
  help, run it on its own, without pipes or redirects."
- Tests: a fake installer that lands a skill, prints a line from its
  SKILL.md and an error line, then fails; the JSON keeps the error line and
  drops the skill line. A marketplace failure carries the field. The help
  hint appears for the piped form only.

## Slice C: where each skill came from (Tier 2)

- `guestlist.record_install` gains a keyword `origin` (the existing
  `source` stays the snapshot path it digests). It is stored on each
  `approved` event: `{"kind": "github", "owner", "repo", "commit"}` from
  `canary add` (from the parsed link, never from the package);
  `{"kind": "installer", "command": [...]}` from `canary install`;
  `{"kind": "local"}` for a folder; `{"kind": "watcher"}` for a restore.
- `guestlist._state` keeps `origin` from the approved event and carries it
  through a later `changed` event; `scan()` emits it as `source` for
  checked skills; `render_text` shows `owner/repo@abc1234` or `installer`.
  `since` already is the approval time, so no `installed_at` is added.
  Ledgers written before 0.1.5 have no origin: the field is absent and the
  text shows nothing for it.
- Not in scope: an "outdated" check against upstream (needs network).
- Tests: add from a fake GitHub source then list shows owner/repo/commit;
  install then list shows the installer kind; a pre-0.1.5 ledger lists
  cleanly; the origin survives a `changed` event.

## Slice D: updating an installed skill (Tier 2, fail-closed)

- CLI: `--replace` joins USAGE and the allowed flags of `_add` and
  `_install` in `canary/cli.py`, and is passed to `add.add(..., replace=)`
  and `install.install(..., replace=)`. Skills only: with a plugin command
  it is refused, pointing to `claude plugin update` (the message at
  `install.py:520` already does).
- Without the flag, both conflict sentences (`_blocked_sentence`,
  `conflict_reason`) now end "…run this again with --replace to update it".
- `--replace` changes nothing else: the new version is fetched, checked and
  shown exactly as a fresh install, with the same verdicts and override.
- The dialog adds: "This replaces the installed <name> (approved <date>,
  from <source when known>). Files: N added, N removed, N changed." Counts
  only, in the dialog and the JSON; no file paths (path listing deferred).
- The digest is `add.tree_digest` of the installed folder, taken when the
  dialog is built and taken again under `_Commit`. A `SourceError` (links,
  special files) refuses; so does any difference ("changed while you were
  deciding"). A destination that is a symlink, or that the lock attributes
  to a different name, is refused as today.
- The swap, per destination, under `_Commit`: rename the installed folder
  into a new hold slot `quarantine/held/<id>/entry` (same `HOLD_ID` format
  and `hold.json` as the watcher's, with `"reason": "replaced"` and the new
  copy's digest); rename the staged copy in; if that fails, rename the old
  folder back and report nothing changed. Each destination gets its own id.
- Ledger: `replaced` (id, name, origin path, old digest) before the swap,
  then `approved` for the new copy; the lock record is replaced.
  `guestlist._state` ignores `replaced` for status (the new `approved`
  decides it).
- The watcher never reviews a hold whose reason is `replaced`: it asks
  about arrivals, and this copy was the person's own choice to set aside.
  `canary list` shows replaced holds with their ids, marked "replaced".
- `canary restore <id>` on a replaced hold: checks it again and asks. When
  the destination holds the copy that replaced it (its `tree_digest`
  equals the new-copy digest in `hold.json`), a yes swaps them the same way
  (the current copy becomes a new replaced hold). Anything else at the
  destination: `STILL_TAKEN` as today. Nothing is deleted; `canary doctor
  --prune` does not touch holds.
- Tests (red first): replace without the flag refuses with the new
  sentence; with the flag and a yes the new files are in place and the old
  copy is a replaced hold; a no leaves the old copy in place; the installed
  copy changing between dialog and swap refuses; a failed rename restores
  the old copy; the watcher does not ask about a replaced hold; restore of
  a replaced id swaps back; a plugin command with `--replace` is refused.

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

1. The slice's tests above exist, and a log run at the slice's base commit
   with the tests applied shows each new test failing on its assertion
   (`docs/proof/2026-10-16-skill-updates/<slice>/red.log`, first line
   `commit <sha>`).
2. The full gate passes on both interpreters at the slice's final commit
   (`gate-<sha>-py310.log`, `gate-<sha>-py39.log`, stamped).
3. Counterfactual: each behaviour change is reverted in turn, the log names
   the reverted line, the named test goes red, and every other test in the
   same `tests/test_<area>.py` passes (`counterfactual-*.log`, stamped).
4. Slice A only: the benchmark before and after is logged; no malicious
   sample is lost; the false-alarm change is reported.
5. The done-when audit returns SHOWN for bullets 1 to 4 (as they apply).

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
