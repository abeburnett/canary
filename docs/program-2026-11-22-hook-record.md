# Program: record what the hook stops, and show a total

Owner decisions: all four made (2026-11-22). Section 0.1 lists them.

Status: design, refuted twice and folded. The first refutation returned
REWORK (12 findings), the second PROCEED-WITH-FIXES (14 findings); all
are folded and answered in section 10. No code written. Base: `main` at `e4df96a` (0.1.6 released, tag
`v0.1.6` at `9472a1b`). Two slices, built in order: both change
`canary/guestlist.py` and `tests/test_guestlist.py`, so slice 2 branches
from `main` after slice 1 merges. Each builds in a short-lived worktree
branched from `main` and merges when bullets 1 to 5 of its "Done when"
list are shown. The coordinator writes the start commit into each worker's
contract, and the worker checks it with `git merge-base --is-ancestor
<commit> HEAD` before editing. Gate: `python3 -m unittest discover -s
tests` on `python3.10` and `/usr/bin/python3`. Builder: an Opus worker at
`high` for slice 1, because it changes the hook, which fails closed; a
Sonnet worker at `medium` can build slice 2. This document is the whole
contract; the builder finds each site by name, not by line number.

Source: item 3 of the 2026-11-15 review's verdict
(`docs/review-2026-11-15-keep-or-scrap.md`, section 3), listed under
"Later" in `docs/program-2026-11-15-quiet-holds.md` section 11.

## 0. The idea in one paragraph

The review could not answer "has SkillCanary ever stopped anything real?"
from what SkillCanary records. The hook refuses or redirects a tool call
and writes nothing, so its work leaves no trace. And 94% of the ledger is
arrivals and removals of skills inside repositories, written each time a
session starts in another folder, which buries the records that matter.
This program makes two changes. Slice 1: the hook appends one short record
each time it refuses, redirects or rewrites a call, with a fixed kind code
and no text from the call; and `canary list` ends with a total of what the
check and the hook did. Slice 2: a scan stops writing `arrived` and
`removed` records for repository skills it cannot see, which also stops a
scan in one folder from erasing the approvals of skills in another.

### 0.1 Owner decisions this program needs

1. **Refuter.** Decided 2026-11-22: Spark 1.3 Contributor at `max`,
   through `refute-plan`.
2. **Repository approvals persist.** Decided 2026-11-22: yes, as
   recommended, with the consequence below. Today a scan from another folder
   erases them (section 0.2). Recommendation: yes, an approval of a
   repository skill lasts until a scan sees the skill changed, or sees its
   folder gone (section 2). One consequence in user roots: known paths
   are real paths, so a user skill reached through a link whose target
   lives elsewhere keeps its record after it is unlinked, while the
   target exists. Today it is recorded `removed`. It is not listed
   either way.
3. **The total's wording** (section 3). Decided 2026-11-22: the section 3
   sentences as they stand after the second refutation. Recommendation: the sentences in
   section 3, which say "not installed" rather than "you declined",
   because the ledger records `refused` for a no, for no answer and for a
   failed copy alike. The hook's count of installs covers installer
   commands and new skill folders written by a file tool; its other
   refusals (SkillCanary's records, its watcher, a quarantined package, a
   skill's own text, a call it could not read) get a separate sentence.
   The refutation changed these sentences, so the owner confirms the
   section 3 text, not the earlier draft.
4. **`this-mac.log` on a public repository.** Decided 2026-11-22: the
   owner chose a summary. `abeburnett/canary` is public, and `c3a14f0`
   pushed a log that listed every skill on this Mac with its home path.
   `e4df96a` replaced it with the held sections only; the full list stays
   in `c3a14f0`'s history, which is not rewritten. This program's owner
   check saves the total paragraph only (section 8, after the bullets).

### 0.2 Verified against the tree at `e4df96a` and this Mac's ledger

Read while writing (file:function), and counted from
`~/Library/Application Support/Canary/ledger.jsonl` on 2026-11-22
(11,201 lines):

- `canary/cli.py:_hook` calls `gate.decide`, then writes the adapter's
  answer. It writes no ledger record. Its docstring says a crash fails
  open, but the code sets `reason = gate.UNREADABLE` on any exception and
  denies; `gate.decide` does the same (`except Exception: return
  UNREADABLE`). The hook fails closed. The docstring is wrong; slice 1
  corrects it.
- `canary/gate.py:decide` returns `None` (allow), a `Rewrite` (Claude Code
  only, for a supported installer), or one of these strings: `REDIRECT`
  (with an optional `HELP_HINT`), `INSTALL_INSTEAD` formatted with the
  command, `OWN_TEXT` formatted with the arguments, `QUARANTINED`,
  `WATCHER`, `RECORD`, `NEW_SKILL`, `UNREADABLE`. `INSTALL_INSTEAD`,
  `OWN_TEXT` and `Rewrite.command` carry text from the call, which can
  carry a token.
- `canary/guestlist.py:_append` opens the ledger with `O_APPEND |
  O_NOFOLLOW` and writes one line per event; callers hold `_Lock`, an
  `flock` that blocks. `_events` skips a line that is not JSON.
- `canary/guestlist.py:scan` lists skills under `user_roots(home) +
  repo_roots(cwd)` as one set. A path it has no state for gets `arrived`;
  a known path not in that set gets `removed`, whatever root it was under.
- Ledger split by where the skill lives: 10,510 events (94%) are
  `arrived` and `removed` for skills inside repositories, across 16
  repositories. 50 repository skills were approved, and a later scan from
  another folder wrote `removed` for all 50, which `_state` turns into
  "no record"; when the person returns, the skill arrives again as
  unchecked.
- Three approvals and seven other events are for paths outside both user
  roots and any repository skills folder (an app bundle and the plugin
  cache). Not established: what wrote them. Section 2 gives them the rule
  for unlisted paths; finding their writer is in section 9.
- `checked` is written once per check, in the same `_append` call as its
  outcome (`record_install`: `checked` then one `approved` per folder;
  `record_decision`: `checked` then one outcome), so it is the unit for
  "installs checked": 184 checks. 152 ended in an approval (117
  through `canary add` or `canary install`, 35 through the watcher's
  dialog); 8 of those were approved after an UNSAFE verdict (1 through
  `canary add` or `canary install`, 7 through the watcher). 32 were not
  installed (`refused` 28, `declined` 3, `not_installed` 1). Verdicts: 103
  LIKELY_SAFE, 45 NEEDS_REVIEW, 36 UNSAFE. The review counted 32 UNSAFE and
  24 refused on 2026-11-15; the ledger has grown since.
- `approved` is per folder: 160 `approved` events for those 152 checks.
- The watcher's `_keep_refused` appends a second `refused` or `declined`
  with `"replay": true` when a remembered no keeps a hold. It is a mark,
  not a new no. This Mac's ledger has none yet, so the counts above stand.
- `_append` writes a batch through a buffered text file object
  (`os.fdopen(fd, "a")`). A batch larger than the buffer reaches the file
  in more than one `write`, split wherever the buffer fills, possibly
  mid-line. Every caller holds `_Lock`, so today no other writer lands
  between those writes. A writer that skipped the lock could split a line
  of someone else's batch and damage it.
- `refused` is written by `canary/add.py` when the person says no to an
  UNSAFE skill and when nobody answers, and by `canary/replace.py` when a
  copy fails (`add.SourceError` or `OSError`) as well as on a no.

## 1. Slice 1: the hook's record, and the total

### 1.1 A kind code for each decision

A new `gate.decide_kind(call, home, roots, canary_bin, can_rewrite=False)`
returns a pair `(reason, kind)`. `reason` is exactly what `decide` returns
today: `None`, a `Rewrite`, or a plain `str`. `gate.decide` becomes
`return decide_kind(...)[0]` with the same signature, so its callers and
tests do not change.

The reason stays a plain `str` on purpose. Both adapters' `deny` reject
anything else (`type(reason) is not str` in `canary/hosts/claude.py` and
`canary/hosts/codex.py`) and answer with their generic fallback, so a
`str` subclass would turn every deny into the fallback text. `Rewrite`
stays a one-field frozen dataclass; tests build it positionally. Neither
adapter changes. `kind` is `None` when `reason` is `None`. The kinds:

| Kind | Returned for |
|---|---|
| `installer_redirect` | `REDIRECT`, with or without `HELP_HINT` |
| `installer_instead` | `INSTALL_INSTEAD` |
| `installer_rewrite` | a `Rewrite` |
| `new_skill` | `NEW_SKILL` |
| `quarantine` | `QUARANTINED` |
| `watcher` | `WATCHER` |
| `record` | `RECORD` |
| `own_text` | `OWN_TEXT` |
| `unreadable` | `UNREADABLE`, from `decide` or from `_hook` |

Each `return` in `decide`'s body becomes a pair at the site that chose
the reason; its `except Exception` returns `(UNREADABLE, "unreadable")`.
Nothing parses the message to find the kind.

### 1.2 The record

One JSON line, appended to the ledger:

```json
{"at": "2026-11-23T10:00:00Z", "event": "hook", "host": "claude", "kind": "installer_rewrite"}
```

- `host` is `claude` or `codex` when `_hook` was called with `--host`
  and that value; anything else, including a missing `--host`, is
  `unknown`.
- The record has no `skill`, `name`, `command`, `cwd`, path or reason
  text. `_state` skips any event without a `skill` field, so readers from
  0.1.6 and earlier ignore it.
- An allowed call writes nothing.

### 1.3 Where the write sits in `_hook`

The answer is fixed first, then recorded, then written. The shape, with
today's start-up block unchanged and not recorded (if `gate` cannot be
imported, `guestlist` likely cannot either):

```python
def _hook(args):
    host = ...                                   # as today
    try:                                         # start-up block, as today
        ...
    except BaseException:
        ...                                      # as today; no record
    answer, kind = None, None                    # answer: (out, code) for a rewrite
    try:
        if host is None:
            raise ValueError("unknown host")
        ...                                      # envelope, parse, roots: as today
        reason, kind = gate.decide_kind(call, home, roots, CANARY_BIN,
                                        can_rewrite=can_rewrite)
        if isinstance(reason, gate.Rewrite):
            answer = adapter.rewrite(payload["tool_input"], reason.command)
    except BaseException:
        reason, kind, answer = gate.UNREADABLE, "unreadable", None
    if reason is None:
        return 0                                 # allow: nothing below runs
    try:
        from canary import guestlist             # lazy: the allow path never imports it
        guestlist.note_hook(os.path.expanduser("~"),
                            host if host in ("claude", "codex") else "unknown", kind)
    except BaseException:
        pass
    if answer is not None:
        out, code = answer
        sys.stdout.write(out)
        return code
    out, code = adapter.deny(reason)             # as today
    sys.stdout.write(out)
    sys.stderr.write(reason + "\n")
    return code
```

`adapter.rewrite` is still called inside the deciding `try`, as today, so
an exception there still becomes an `UNREADABLE` deny, and its record says
`unreadable`, not `installer_rewrite`. The record block is a separate
`try`, so a failed write never turns an allow or a rewrite into
`UNREADABLE`.

The rule: **a record failure never changes the decision, in either
direction, and never adds output.**

The allow path gains no import, file access or system call beyond what
it does today (reading stdin, parsing, resolving the skills folders).

### 1.4 How `note_hook` writes

- It opens `ledger.lock` with `O_RDWR | O_NOFOLLOW` and no `O_CREAT`,
  and takes `fcntl.flock(fd, LOCK_EX | LOCK_NB)`. If the lock is held (a
  scan or a record is being written), it drops the record and returns: a
  hook never waits on a scan. Holding the lock keeps its line out of the
  middle of another writer's batch (section 0.2).
- Holding the lock, it opens the ledger with `O_WRONLY | O_APPEND |
  O_NOFOLLOW` and no `O_CREAT`, writes the line with one `os.write`, and
  closes both. A missing ledger, lock file or Support folder means setup
  never ran; the record is dropped.
- It reads nothing from the ledger.
- A dropped record makes the hook totals a lower bound of what the hook
  did, so section 3 words them as what the hook recorded, "at least".

### 1.5 The total in `canary list`

`guestlist.scan` computes `totals` from the events it already read under
its lock and puts them in the report; `guestlist.render_text` appends the
section 3 paragraph as the very last lines of `canary list` text, after
the held and replaced sections. Nothing reads the ledger a second time.
`canary list --json` gains an additive `totals` object under the
same schema, `canary.list/1`:

```json
"totals": {"since": "2026-10-02", "checked": 184, "installed": 152,
           "installed_after_unsafe": 8, "not_installed": 32,
           "hook_since": "2026-11-23", "hook_installs": 3,
           "hook_installs_rewritten": 2, "hook_other": 5}
```

- Pairing. Read the ledger in file order and skip every `hook` event and
  every event with `"replay": true`. Also skip every `approved` event
  whose `origin` has a `same_as` field: the watcher writes those for a
  remembered yes with no `checked`, because no check ran
  (`watcher.py`, quiet-holds section 2.2), and they would otherwise land
  in an earlier check of the same name. A check is a `checked` event; its
  outcome is the run of events after it, up to the next `checked`, that
  have the same `name` and an `event` of `approved`, `refused`, `declined`
  or `not_installed`. Other events in that run (`arrived`, `changed` and
  so on, written by other scans) are skipped, not outcomes.
- `checked` counts checks. `installed` counts checks with at least one
  `approved` in their outcome, once per check, not per folder.
  `installed_after_unsafe` counts those where any of those `approved`
  events carries `override`. `not_installed` counts checks whose outcome
  is `refused`, `declined` or `not_installed`. A check with no outcome
  counts in `checked` only.
- `since` is the date (`YYYY-MM-DD`, UTC) of the first `checked` event, or
  `null` when there is none.
- `hook_installs` counts `hook` records with kinds `installer_redirect`,
  `installer_instead`, `installer_rewrite` and `new_skill`;
  `hook_installs_rewritten` is the `installer_rewrite` share. `hook_other`
  counts every other kind. `hook_since` is the first `hook` record's date,
  or `null`.
- A rewritten installer that then runs `canary install` appears twice: once
  as a hook record and once as a check. The text says so (section 3).
- The session-start notice does not change.

## 2. Slice 2: repository skills

`guestlist.scan` lists user roots and repository roots separately: it
calls `_skills(user_roots(home))` and `_skills(repo_roots(cwd))` and keeps
two sets. `_skills` itself does not change. A real path found in both (a
repository skill linked into a user root) is a user skill.

- A skill under a user root: unchanged. `arrived`, `changed` and
  `removed` as today. The one exception is a known path that is not
  itself directly in a listed root (a real path reached through a link);
  it follows the unlisted-path rule below (owner decision 2).
- A skill under a repository root of the current folder, with no record:
  no event. It is listed as unchecked, as today.
- A skill under a repository root, with a record (approved or trusted):
  `changed` when its content changes, as today.
- A known path that the scan did not find, and that sits directly in a
  root the scan listed (its parent folder is that root): `removed`, as
  today.
- Any other known path the scan did not find: `removed` only when the
  folder is gone (`os.path.lexists(path)` is false). While it exists, no
  event. So a scan in one folder leaves the approvals in another alone,
  and an approval whose repository was deleted is still recorded
  `removed` the next time any scan runs. This rule also covers the
  approvals outside user and repository roots (section 0.2): they persist
  while their folder exists, and are recorded `removed` once it is gone.
  The scan does not fingerprint these paths, so it records no `changed`
  for them; the next scan that lists their root does. Owner decision 2
  names this rule's one consequence for user roots (a linked skill whose
  target lives elsewhere).

"Repository skill" means a path the scan found in the repository set and
not in the user set. The scan does not classify by path prefix.

Repository skills never baseline: the only `first_look` caller,
`canary/setup.py`, passes no `cwd`.

Existing ledger lines are not rewritten. The 10,510 old repository events
stay; the 50 erased approvals stay erased.

The quiet-holds sweep and the remembered yes (`guestlist.covering`) read
approvals by path. A repository approval that now persists could name a
path that is gone or changed. The refuter checks that every automatic
install or drop still compares bytes with the folder at its place at that
moment (`docs/program-2026-11-15-quiet-holds.md` section 0); if one does
not, this slice stops until the spec says how it does. The refutation
checked this: the watcher's automatic install and drop act only on places
directly in watched user roots (`watcher.py`), re-digest the approval's
folder (`_approved`) and compare trees (`same_tree`), so a persisted
repository approval cannot trigger either. Slice 2's `premerge-review`
brief asks the reviewer to confirm it still holds at the final commit.

## 3. Sentences, exact

The paragraph at the end of `canary list` text, filled from `totals`
(the numbers here are examples):

> Since 2026-10-02, SkillCanary checked 184 installs: 152 were installed,
> 8 of them after an unsafe verdict, and 32 were not installed.

When there is at least one `hook` record:

> Since 2026-11-23, the hook has recorded stopping at least 3 attempts to
> install or create a skill without the check, and sending 2 of them
> through the check instead; any that ran are also counted above. It has
> also recorded refusing at least 5 other tool calls: ones that touched
> SkillCanary's own files or watcher, read a quarantined package or a
> skill's text meant for you, or could not be checked.

When there is none, the second paragraph is:

> The hook has not recorded stopping anything since it started recording.

No sentence states or implies a catch rate (decision 12 of
`docs/program-2026-10-17-replace.md`). These lines print every number as
numerals, because they are filled from counts.

## 4. Failure behaviour

- A failed or dropped `note_hook` (any exception, a full disk, a missing
  ledger, a held lock): no record, the same answer, the same exit code,
  one answer on stdout.
- A damaged `hook` line: skipped by `_events`, as any damaged line.
- A ledger with no `checked` events: the first sentence reads "SkillCanary
  has not checked an install yet."

## 5. Interfaces, docs first

- `canary/cli.py` `USAGE` and `docs/` text for `canary list` mention the
  total paragraph, in the same slice.
- `docs/` text that says the hook leaves no record, if any, changes in the
  same slice.
- The `_hook` docstring says the hook fails closed.

## 6. Tests, red first

Each slice adds at most three scenarios to the existing suites that own
the behaviour (the hook tests for slice 1, the guest-list tests for slice
2). Each scenario fails at the slice's start commit on an assertion or on
the missing interface.

Slice 1:

1. A denied installer call whose command carries a fake token writes
   exactly one `hook` record with kind `installer_redirect`, and the token
   appears nowhere in the ledger. An allowed call writes nothing. The
   fixture runs `guestlist.scan` once first, so the Support folder,
   `ledger.lock` and the ledger exist (`note_hook` creates neither).
2. Run in process: the test calls `cli._hook` with `sys.stdin`,
   `sys.stdout` and `sys.stderr` replaced and `guestlist.note_hook`
   patched to raise (the subprocess harness in `tests/test_gate.py`
   cannot be patched). A deny keeps its exit code, stdout and
   stderr; a rewrite keeps its exit code and stdout; an allow exits 0
   with empty stdout and stderr, as today.
3. `canary list` on a fixture ledger prints the section 3 sentences with
   the fixture's numbers, and `--json` carries the same `totals`. The
   fixture holds a `hook` line between a `checked` and its `approved`, a
   check approved into two folders (counted once), and a `"replay": true`
   `refused` (not counted).

Slice 2:

1. A repository skill approved, then a scan from another folder: the
   approval is still there (fails today: the scan writes `removed`).
2. Two scans of a folder with an unrecorded repository skill write no
   `arrived` event.
3. A recorded repository skill deleted while its root is not listed (a
   scan from another folder) is recorded `removed`; while it exists, the
   same scan writes nothing for it.

## 7. Scope cuts

- No change to the session-start notice.
- No rewrite or compaction of existing ledger lines.
- No record of allowed calls, and no command text in any record.
- No change to what the hook allows or denies.
- The approvals outside user and repository roots (section 0.2) follow
  section 2's rule for unlisted paths; this program does not find what
  wrote them.

## 8. Done when

Logs live in `docs/proof/2026-11-22-hook-record/slice-1/` and `slice-2/`,
stamped as in the quiet-holds program (first line `commit <full sha>`,
second the interpreter's `--version`). For each slice:

1. `red.log`: each new scenario fails at the slice's start commit with the
   tests applied, on an assertion or on the missing interface.
2. `gate-python3.10.log` and `gate-usr-bin-python3.log`: the full gate
   passes at the slice's final commit on both interpreters, tree clean.
   The final commit is a manifest commit. `scripts/action.py:scanner_manifest`
   checks every file under `canary/` against `scanner/manifest.json`, so a
   change there fails the `tests/test_action.py` `CanaryActionTests` cases
   until the manifest is rewritten. The builder commits the slice's last
   code change (the source commit), runs `scripts/update-manifest.py
   <source commit>`, and commits `scanner/manifest.json` alone, as
   `a55073b` did for 0.1.5. A later change under `bin/` or `canary/`, such
   as a fold from bullet 4, repeats those steps before the gate logs.
3. Slice 1 only, `latency.log`: the hook's wall time on this Mac for one
   allowed call and one denied installer call, at the start commit and at
   the final commit. Each set is 3 discarded warm-up runs, then 20 timed
   runs; the log records the median and the slowest. Conditions: on mains
   power, no gate or build running, both commits measured in the same
   sitting. The allowed call's median is no slower by more than 5 ms; the
   denied call's by no more than 20 ms. A breach is measured once more;
   if it holds, the slice does not merge until the spec says what to do.
4. A pre-merge review (`premerge-review`) returns MERGE, after any fold.
5. A done-when audit by a different model than the builder returns PASS.

One owner check sits outside bullets 1 to 5 and does not gate the merge,
because it needs the new version installed, which is the owner's release
step. After the release that carries slice 1, the owner runs `canary
list` on this Mac and confirms the total paragraph is there. The agent
saves only that paragraph, not the skill list, in `slice-1/this-mac.log`.

## 9. Later

- Show the total in the session-start notice, if the owner wants it there.
- Find what wrote the approvals outside user and repository roots.

## 10. Where each refutation finding is answered

The refutation ran on 2026-11-22 against this document at `e3827db`.
Verdict: REWORK, twelve findings. Each was checked against the tree at
`e3827db` before it was folded; every cited line matched. The refuter's
full text is in the owner's review cache, outside this repository, under
`20261122-160925-refute-program-2026-11-22-hook-record`.

| # | Severity | Finding | Checked against | Answer |
|---|---|---|---|---|
| 1 | blocks | A `str` subclass for the reason turns every deny into the adapters' fallback | `canary/hosts/claude.py:deny`, `canary/hosts/codex.py:deny` (`type(reason) is not str`) | Accepted. Section 1.1: `decide_kind` returns `(reason, kind)`; the reason stays a plain `str`; no adapter changes |
| 2 | blocks | The slices share `guestlist.py` and its tests, so "either order" means a merge conflict | `canary/guestlist.py:scan`, `tests/test_guestlist.py` | Accepted. Header: slice 2 branches from `main` after slice 1 merges |
| 3 | blocks | The gate cannot pass: no manifest step | `scripts/action.py:bundled_files`, `scanner_manifest` | Accepted. Section 8, bullet 2 copies the quiet-holds manifest steps |
| 4 | blocks | The merge waits on an owner check that needs a release | Section 8, old bullet 6 | Accepted. The owner check sits after bullets 1 to 5 and does not gate the merge |
| 5 | wrong-if-built | Totals have no pairing rule, and replayed marks count a no twice | `guestlist.py:record_install`, `record_decision`; `watcher.py:_keep_refused` | Accepted. Section 1.5 defines pairing, skips `hook` and `replay` lines, and defines `since`; section 6 test 3 pins it. The rule, run read-only on this Mac's ledger, gives section 0.2's counts exactly (184, 152, 8, 32), with no check lacking an outcome and no outcome lacking a check. Also found: `_append` can split a large batch mid-line, so `note_hook` takes the lock without waiting (section 1.4) |
| 6 | wrong-if-built | Section 3 says "install commands" and "SkillCanary's own files", but the kinds include `new_skill`, `own_text` and `unreadable` | `gate.py` `NEW_SKILL`, `OWN_TEXT`, `UNREADABLE` | Accepted. Section 3 sentences reworded; owner decision 3 asks for confirmation of the new text |
| 7 | wrong-if-built | Sections 2 and 7 disagree on paths under no listed root, and a deleted repository leaves its approvals forever | `guestlist.py:repo_roots` drops folders that do not exist | Accepted. Section 2: an unlisted known path is `removed` once its folder is gone, which covers deleted repositories and the out-of-root approvals; section 7 and decision 2 follow |
| 8 | wrong-if-built | Test 2 says an allow writes an answer; it writes nothing | `cli.py:_hook` returns 0 silently | Accepted. Section 6, slice 1 test 2 |
| 9 | wrong-if-built | The `_hook` restructure is unspecified: rewrite exceptions, host value, lazy import | `cli.py:_hook` | Accepted. Section 1.3 gives the shape; `adapter.rewrite` stays inside the deciding `try`; host mapping in section 1.2; `guestlist` imported only on a non-allow |
| 10 | cleanup | A required `kind` field breaks positional `Rewrite(...)` | `gate.py:Rewrite`; `tests/test_gate.py` | Accepted, by finding 1's answer: `Rewrite` does not change |
| 11 | cleanup | The latency check has no warm-up, conditions or consequence | Section 8, bullet 3 | Accepted. Warm-up, conditions, one re-measure, and a breach blocks the merge |
| 12 | cleanup | Section 2 hides the `_skills` change and leaves `first_look` open | `guestlist.py:_skills`, `setup.py` (`scan(home, first_look=True)`) | Accepted. Section 2: two `_skills` calls, `_skills` unchanged; repository skills never baseline |

The refuter also confirmed: the fail-closed finding in section 0.2, the
old-reader claim in section 1.2, and the byte comparison that section 2
asked it to check.

### Second refutation

It ran on 2026-11-22 against this document at `6c3cfdb`. Verdict:
PROCEED-WITH-FIXES, fourteen findings. Each was checked against the tree
at `6c3cfdb` before it was folded; every cited line matched. Full text in
the owner's review cache under the newest
`refute-program-2026-11-22-hook-record` folder. The refuter also ran the
section 1.5 pairing rule on this Mac's ledger and got 184/152/8/32.

| # | Severity | Finding | Answer |
|---|---|---|---|
| 1 | blocks | Test 2 cannot patch `note_hook` in the subprocess harness (`tests/test_gate.py:hook`) | Section 6, test 2 runs `cli._hook` in process |
| 2 | wrong-if-built | A fresh fixture has no `ledger.lock`, so `note_hook` drops the record and test 1 fails on correct code | Section 6, test 1 runs a scan first |
| 3 | wrong-if-built | Dropped records make "stopped 3" a lower bound, not a count | Section 3 says "has recorded stopping at least"; section 1.4 follows |
| 4 | wrong-if-built | The other-calls sentence omits the quarantined package | Section 3 adds it |
| 5 | wrong-if-built | A rewrite leaves the decision to the person's permission rules (`hosts/claude.py:rewrite`), so not every rewrite is "counted above" | Section 3: "any that ran are also counted above" |
| 6 | wrong-if-built | The watcher's remembered-yes approval has no `checked` and would inflate an earlier check | Section 1.5 skips `approved` with `origin.same_as` |
| 7 | wrong-if-built | Section 2 says user roots are unchanged, but decision 2's linked-skill consequence changes them | Section 2 names the exception |
| 8 | cleanup | The paragraph would print before the replaced section | Section 1.5: the very last lines |
| 9 | cleanup | No function named for the totals | Section 1.5: `scan` computes, `render_text` prints |
| 10 | cleanup | "The builder confirms" has no artifact | Section 2: the slice 2 `premerge-review` brief asks for it |
| 11 | cleanup | The `first_look`-with-`cwd` clause has no caller | Cut |
| 12 | cleanup | The allow path already reads stdin and resolves folders | Section 1.3: "beyond what it does today" |
| 13 | cleanup | "(0.1.7)" names an unreleased version | Dropped |
| 14 | cleanup | "Before the code" cannot be checked | Section 5: "in the same slice" |
