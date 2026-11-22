# Program: record what the hook stops, and show a total

Owner decisions: one of four made (2026-11-22, item 4). Section 0.1 lists
all four, each open one with a recommendation.

Status: design. Not refuted, no code written. Base: `main` at `e4df96a`
(0.1.6 released, tag `v0.1.6` at `9472a1b`). Two slices that touch
different files and can build in either order; each builds in a
short-lived worktree branched from `main` and merges when its "Done when"
list is shown. The coordinator writes the start commit into each worker's
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

1. **Refuter.** Recommendation: Spark 1.3 Contributor at `max` through
   `refute-plan`, as for the last two programs.
2. **Repository approvals persist.** Today a scan from another folder
   erases them (section 0.2). Recommendation: yes, an approval of a
   repository skill lasts until the skill changes or a scan sees it gone.
3. **The total's wording** (section 3). Recommendation: the sentences in
   section 3, which say "not installed" rather than "you declined",
   because the ledger records `refused` for a no, for no answer and for a
   failed copy alike. Hook refusals that are not installs (reading the
   quarantine, naming the watcher, `canary explain`) are counted in a
   separate sentence, not as installs stopped.
4. **`this-mac.log` on a public repository.** Decided 2026-11-22: the
   owner chose a summary. `abeburnett/canary` is public, and `c3a14f0`
   pushed a log that listed every skill on this Mac with its home path.
   `e4df96a` replaced it with the held sections only; the full list stays
   in `c3a14f0`'s history, which is not rewritten. This program's owner
   check saves the total paragraph only (section 8, bullet 6).

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
  cache). Not established: what wrote them. Section 10 keeps them out of
  scope.
- `checked` is written once per check, beside its outcome, so it is the
  unit for "installs checked": 184 checks. 152 ended in an approval (117
  through `canary add` or `canary install`, 35 through the watcher's
  dialog); 8 of those were approved after an UNSAFE verdict (1 through
  `canary add` or `canary install`, 7 through the watcher). 32 were not
  installed (`refused` 28, `declined` 3, `not_installed` 1). Verdicts: 103
  LIKELY_SAFE, 45 NEEDS_REVIEW, 36 UNSAFE. The review counted 32 UNSAFE and
  24 refused on 2026-11-15; the ledger has grown since.
- `approved` is per folder: 160 `approved` events for those 152 checks.
- `refused` is written by `canary/add.py` when the person says no to an
  UNSAFE skill and when nobody answers, and by `canary/replace.py` when a
  copy fails (`add.SourceError` or `OSError`) as well as on a no.

## 1. Slice 1: the hook's record, and the total

### 1.1 A kind code for each decision

`gate.decide` returns a `gate.Denial`, a `str` subclass with a `kind`
attribute, in place of each plain deny string. Its text is unchanged, so
every caller and test that compares or prints the reason works as before.
`Rewrite` gains a `kind` field with the value `installer_rewrite`. `None`
stays `None`. The kinds:

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

The kind comes from the site that chose the reason. Nothing parses the
message to find it.

### 1.2 The record

One JSON line, appended to the ledger:

```json
{"at": "2026-11-23T10:00:00Z", "event": "hook", "host": "claude", "kind": "installer_rewrite"}
```

- `host` is `claude`, `codex` or `unknown`.
- The record has no `skill`, `name`, `command`, `cwd`, path or reason
  text. `_state` skips any event without a `skill` field, so readers from
  0.1.6 and earlier ignore it.
- An allowed call writes nothing.

### 1.3 Where the write sits in `_hook`

The decision is fixed first, then recorded, then answered:

1. `_hook` computes the decision exactly as today, including the
   `UNREADABLE` fallback.
2. If the decision is not `None`, `_hook` calls a new
   `guestlist.note_hook(home, host, kind)` inside its own `try: ...
   except BaseException: pass`. This block is separate from the one that
   computes the decision, so a failed write never turns an allow or a
   rewrite into `UNREADABLE`.
3. `_hook` writes the answer once, as today. The rewrite path records
   before it writes and returns, like the deny path.

The rule: **a record failure never changes the decision, in either
direction, and never adds output.**

The allow path gains no import, no file access and no system call.

### 1.4 How `note_hook` writes

- It opens the ledger with `O_WRONLY | O_APPEND | O_NOFOLLOW` and no
  `O_CREAT`, writes the line with one `os.write`, and closes. A missing
  ledger or Support folder means setup never ran; the record is dropped.
- It does not take `_Lock`. The lock blocks, and a hook must not wait on
  a scan. One `write` of one short line to a file opened with `O_APPEND`
  lands whole at the end on macOS; if a line is ever damaged, `_events`
  skips it.
- It reads nothing from the ledger.

### 1.5 The total in `canary list`

`canary list` text ends with the paragraph in section 3, after the held
section. `canary list --json` gains an additive `totals` object under the
same schema, `canary.list/1`:

```json
"totals": {"since": "2026-10-02", "checked": 184, "installed": 152,
           "installed_after_unsafe": 8, "not_installed": 32,
           "hook_since": "2026-11-23", "hook_installs": 3,
           "hook_installs_rewritten": 2, "hook_other": 5}
```

- `checked` counts `checked` events. `installed` counts checks whose
  outcome is an approval, once per check, not per folder.
  `installed_after_unsafe` counts those whose approvals carry `override`.
  `not_installed` counts `refused`, `declined` and `not_installed`.
- `hook_installs` counts `hook` records with kinds `installer_redirect`,
  `installer_instead`, `installer_rewrite` and `new_skill`;
  `hook_installs_rewritten` is the `installer_rewrite` share. `hook_other`
  counts every other kind. `hook_since` is the first `hook` record's date,
  or `null`.
- A rewritten installer that then runs `canary install` appears twice: once
  as a hook record and once as a check. The text says so (section 3).
- The session-start notice does not change.

## 2. Slice 2: repository skills

`guestlist.scan` lists user roots and repository roots separately:

- A skill under a user root: unchanged. `arrived`, `changed` and
  `removed` as today.
- A skill under a repository root of the current folder, with no record:
  no event. It is listed as unchecked, as today.
- A skill under a repository root, with a record (approved or trusted):
  `changed` when its content changes, as today.
- A known path that the scan did not find: `removed` only when the path is
  inside a root the scan listed, user or repository, and the path is gone
  from it. A path under a root the scan did not list gets no event, so a
  scan in one folder leaves the approvals in another alone.

"Repository skill" means a path the scan found under a root that
`repo_roots(cwd)` returned and `user_roots(home)` did not. The scan knows
the root of each path it lists; it does not classify by path prefix.

Existing ledger lines are not rewritten. The 10,510 old repository events
stay; the 50 erased approvals stay erased.

The quiet-holds sweep and the remembered yes (`guestlist.covering`) read
approvals by path. A repository approval that now persists could name a
path that is gone or changed. The refuter checks that every automatic
install or drop still compares bytes with the folder at its place at that
moment (`docs/program-2026-11-15-quiet-holds.md` section 0); if one does
not, this slice stops until the spec says how it does.

## 3. Sentences, exact

The paragraph at the end of `canary list` text, filled from `totals`
(the numbers here are examples):

> Since 2026-10-02, SkillCanary checked 184 installs: 152 were installed,
> 8 of them after an unsafe verdict, and 32 were not installed.

When there is at least one `hook` record:

> Since 2026-11-23, the hook stopped 3 install commands that skipped the
> check, and sent 2 of them through the check instead (they are also
> counted above). It refused 5 other tool calls on SkillCanary's own files.

When there is none, the second paragraph is:

> The hook has not stopped anything since it started recording (0.1.7).

No sentence states or implies a catch rate (decision 12 of
`docs/program-2026-10-17-replace.md`). These lines print every number as
numerals, because they are filled from counts.

## 4. Failure behaviour

- A failed `note_hook` (any exception, a full disk, a missing ledger):
  no record, the same answer, the same exit code, one answer on stdout.
- A damaged `hook` line: skipped by `_events`, as any damaged line.
- A ledger with no `checked` events: the first sentence reads "SkillCanary
  has not checked an install yet."

## 5. Interfaces, docs first

- `canary/cli.py` `USAGE` and `docs/` text for `canary list` mention the
  total paragraph. Update them before the code.
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
   appears nowhere in the ledger. An allowed call writes nothing.
2. With `note_hook` made to raise: a deny stays the same deny, a rewrite
   stays the same rewrite, an allow stays an allow, and stdout holds one
   answer each time.
3. `canary list` on a fixture ledger prints the section 3 sentences with
   the fixture's numbers, and `--json` carries the same `totals`.

Slice 2:

1. A repository skill approved, then a scan from another folder: the
   approval is still there (fails today: the scan writes `removed`).
2. Two scans of a folder with an unrecorded repository skill write no
   `arrived` event.
3. A recorded repository skill deleted from a root the scan lists is
   recorded `removed`.

## 7. Scope cuts

- No change to the session-start notice.
- No rewrite or compaction of existing ledger lines.
- No record of allowed calls, and no command text in any record.
- No change to what the hook allows or denies.
- The approvals outside user and repository roots (section 0.2) keep
  today's behaviour.

## 8. Done when

Logs live in `docs/proof/2026-11-22-hook-record/slice-1/` and `slice-2/`,
stamped as in the quiet-holds program (first line `commit <full sha>`,
second the interpreter's `--version`). For each slice:

1. `red.log`: each new scenario fails at the slice's start commit with the
   tests applied, on an assertion or on the missing interface.
2. `gate-python3.10.log` and `gate-usr-bin-python3.log`: the full gate
   passes at the slice's final commit, tree clean.
3. Slice 1 only, `latency.log`: the hook's wall time on this Mac, median of
   20 runs each, for one allowed call and one denied installer call, at the
   start commit and at the final commit. The allowed call is no slower by
   more than 5 ms; the denied call by no more than 20 ms.
4. A pre-merge review (`premerge-review`) returns MERGE, after any fold.
5. A done-when audit by a different model than the builder returns PASS.
6. Owner check, after the release that carries slice 1: the owner runs
   `canary list` on this Mac and confirms the total paragraph is there.
   The agent saves only that paragraph, not the skill list, in
   `slice-1/this-mac.log`.

## 9. Later

- Show the total in the session-start notice, if the owner wants it there.
- Find what wrote the approvals outside user and repository roots, and
  decide whether a scan should ever erase them.
