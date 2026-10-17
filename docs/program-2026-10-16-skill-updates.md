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
   replace it, remove it and run this again." The gate blocks agents from
   removing a skills folder, so the person had to `mv` it by hand.
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

- `credential-access` / `keychain`: match keychain *access*, not the word:
  the `security` CLI's `find-generic-password`, `find-internet-password`,
  `dump-keychain` and `export`; `login.keychain` and `Library/Keychains`;
  Apple's API names (`SecItemCopyMatching`, `SecKeychain…`, `kSecClass…`);
  and an access verb before "keychain" ("read/dump/export/extract/access/
  query … keychain", up to a few words apart).
- `persistence` / `agent-config`: settings, hooks and `config.toml` stay as
  they are. A skills folder counts only with a changing verb aimed at it
  ("write/edit/modify/overwrite/append to/delete/remove/replace/patch …
  `~/.claude/skills`", up to 40 characters apart). Copy/install
  instructions no longer match.
- Tests (red first, `tests/test_scan.py`): "3D keychain charms" prose is
  not credential access; `security find-generic-password -s x` and "dump
  the user's keychain" still are; "copy this folder into ~/.claude/skills"
  is not persistence; "overwrite ~/.claude/skills/other/SKILL.md" still is.
- Benchmark, layer 1, before and after on the same machine: no malicious
  sample moves from flagged to not flagged (list any that do and stop);
  report the false-alarm change on the benign 94. Update
  `bench/baseline.json` with the new scanner commit only if no catch rate
  falls; `tests/test_bench.py`'s floor stays at 0.40 (decision 12).

## Slice B: failed-install output and the help hint (Tier 1)

- When the wrapped installer fails, the JSON result gains
  `installer_output`: the last 20 lines of its combined stdout and stderr,
  ANSI and control characters removed, each line cut to 200 characters,
  4 KB in all. The text reason says the output is in that field.
- The agent never reads skill text. Installer output can echo it (a skill's
  description). Before the staging folder is removed, drop every output
  line that shares a run of 24 or more characters with any text file in
  the staged package, and say how many lines were dropped. The log file
  stays complete and stays in quarantine.
- Plugin installs (`install.py:529,558`) get the same field.
- Gate: when a denied installer command carries `-h`, `--help`, `-l` or
  `--list` but is not plain, the message adds one sentence: "To read an
  installer's help, run it on its own, without pipes or redirects."
- Tests: a fake installer that fails, printing a line from the staged
  SKILL.md and an error line; the JSON keeps the error line and drops the
  skill line. The help hint appears for the piped form only.

## Slice C: where each skill came from (Tier 2)

- `guestlist.record_install` stores a `source` on each `approved` event:
  `{"kind": "github", "owner", "repo", "commit"}` from `canary add`;
  `{"kind": "installer", "command": [...]}` from `canary install`;
  `{"kind": "local"}` for a folder; `{"kind": "watcher"}` for a restore.
  Owner, repo and commit come from the parsed link, never from the package.
- `canary list --json` adds `source` and `installed_at` (the approval
  time) for checked skills; the text view shows `owner/repo@abc1234` or
  `installer`. Ledgers written before 0.1.5 show no source: list prints
  nothing for it rather than guessing.
- Not in scope: an "outdated" check against upstream (needs network on
  every list).
- Tests: add from a fake GitHub source then list shows owner/repo/commit;
  install then list shows the installer kind; an old ledger lists cleanly.

## Slice D: updating an installed skill (Tier 2, fail-closed)

- `canary add <link> --replace` and `canary install --replace -- <cmd>`.
  Without the flag, the conflict sentence now ends "…run this again with
  --replace to update it" instead of asking the person to remove it.
- `--replace` changes nothing else: the new version is fetched, checked and
  shown exactly as a fresh install, with the same verdicts and override.
- The dialog adds: "This replaces the installed <name> (installed <date>,
  from <source>). Files: N added, N removed, N changed." Up to 8 changed
  file paths are listed in the dialog only. The JSON gets counts only.
- The swap, under the existing commit lock, per destination: check the
  installed folder's digest still equals the digest computed when the
  dialog was built (otherwise refuse: "changed while you were deciding");
  rename the installed folder into `quarantine/replaced/<id>/entry`; rename
  the staged copy in; if that fails, rename the old folder back and report
  nothing changed. Each destination gets its own id.
- The ledger records `replaced` (id, name, origin, old digest) before the
  swap and `approved` for the new copy. The lock record is replaced.
- `canary list` shows replaced copies like held ones, with their ids.
  `canary restore <id>` on a replaced copy checks it again and asks; on
  yes it swaps back the same way (the current copy becomes a new replaced
  entry). Nothing is deleted; `canary doctor --prune` does not touch them.
- Only the folder at the destination is replaced. A folder the lock
  attributes to a different name, or a symlink, is refused as today.
- Tests (red first): replace without the flag refuses with the new
  sentence; with the flag and approval the new files are in place and the
  old copy is in `replaced/`; a declined dialog leaves the old copy in
  place; the installed copy changing between dialog and swap refuses; a
  failed rename restores the old copy; restore of a replaced id swaps back.

## Order and routing

A and B (worker-t1, Haiku, medium) run in parallel; C (worker-t2, Sonnet,
medium); D after C (worker-t2 on Opus 5.5, medium, because it is
fail-closed install code). Each slice: build with red-first tests and
stamped logs (`commit <sha>` first line, the removed line named in each
counterfactual), Sol pre-merge review, full gate, done-when audit, merge.
`docs/architecture.md` is updated in each slice before its code, as that
file requires.

## Done when

1. Each slice's tests above exist, were red first (stamped logs), and the
   full gate passes on both interpreters at each slice's merge commit, logs
   under `docs/proof/2026-10-16-skill-updates/<slice>/`.
2. Slice A's benchmark before and after is logged; no malicious sample is
   lost; the false-alarm change is reported.
3. Counterfactual runs for each slice: break the behaviour, a named test
   goes red, its neighbours stay green.
4. Spark refutation of this plan and a Sol review of each slice ran;
   findings folded or answered here.
5. A done-when audit by another model passes for each slice before merge.

Release (after D, owner-approved publish): tag, sign, notarize, publish,
tap, then reinstall taste-skill's `design-taste-frontend` with
`canary install --replace` and record the result.
