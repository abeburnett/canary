# Program 2026-10-17: replacing an installed skill (`--replace`)

Status: design, written for refutation. Branch `program/2026-10-17-replace`,
based on `main` at `1465c3b` (slices A to C of program 2026-10-16 merged).
Gate: `python3 -m unittest discover -s tests` on `python3.10` and
`/usr/bin/python3`. Builder: an Opus worker at `high` (fail-closed install
code; owner routing rule). This document is the whole contract; the builder
finds each site by name, not by line number.

Five earlier specifications of this feature were refuted (section 9 maps
every finding). The design below is smaller than any of them: one
file-level primitive, *set aside*, used twice, and the existing fresh-install
commit path left as it is.

## 0. The idea in one paragraph

`canary add <link> --replace` and `canary install --replace -- <installer>`
set the old copies aside into a store under the quarantine, then run the
*unchanged* fresh-install commit path (`add.record_install` →
`add._install` → `add._finish`), and on any failure put the old copies back.
`canary restore <id>` does the same thing with the roles swapped: it sets
aside whatever is at the destinations now (into a new group), puts the old
copies back, and undoes itself on failure. Nothing is deleted; nothing is
ever left with a destination empty unless the process died, and then
`canary restore <id>` is the one recovery path. The new copy is fetched,
checked, approved and recorded exactly like a fresh install; the old copy's
content is never approved by a replace, only by a restore, which checks it
again and asks.

Verified against the tree at `1465c3b` while writing (file:function):

- `canary/add.py:add` holds `_Commit` across re-read, `choose_key`,
  `record_install`, `_install` and `_finish`; approval is recorded before
  the files appear; staging is beside each destination
  (`.canary-staging-<run id>-<name>` in the destination's parent).
- `canary/guestlist.py:record_install` takes `guestlist._Lock` itself.
  `canary/watcher.py:_record` takes it to append events directly.
- `canary/watcher.py:hold` renames a folder *or a link* into
  `quarantine/held/<id>/entry` after writing `hold.json`;
  `watcher._resolved` reads a held link's target relative to its origin;
  `watcher.put_back` records approval, then renames back only when the
  origin is free.
- `canary/watcher.py:_approved` leaves an entry alone only when the ledger's
  state for its real path is `checked` with the same approved digest or
  `yours` with the same digest; anything else (including `unchecked`) is
  held.
- `canary/guestlist.py:_state` ignores events whose kind it does not know,
  and ignores extra keys on the kinds it knows.
- `canary/gate.py:decide` denies agent file tools under the whole
  quarantine root and shell commands naming it, so a store under the
  quarantine is out of an agent's reach.
- `canary/install.py:_skills` learns names only after `_snapshot_and_check`,
  and its first `conflict_reason` call passes no names.

## 1. Behaviour, in the order the code runs

### 1.1 `canary add <source> --replace`

Locks: none until step 8. Ledger events: none until step 9. Lock-file writes:
none until step 11.

1. **Parse and fetch** (`add.add`, unchanged): hosts, `_read_lock`,
   `_unpack` into `quarantine/<run id>/package`, `tree_digest`,
   `classify.check`. `replace=True` is a keyword of `add.add`; the CLI sets
   it from `--replace`.
2. **Destinations and places** (unchanged): one destination per host,
   `places_of(destinations)`.
3. **The replace plan** (`replace.plan(lock, name, destinations, roots,
   home, support)`, new module `canary/replace.py`). It returns
   `(reason, plan)`; `reason` is a refusal sentence (section 2) or `None`.
   The plan is a dict:
   - `existing`: `[(destination, "folder" | "link")]` for every destination
     where `os.path.lexists` is true, in destination order;
   - `records`: `{key: record}` for every live lock record whose
     `record_name` equals `name` and whose `record_places` intersect the
     new places (every key form; `plan_key` returns only the first blocker,
     so this is a separate loop over `lock["skills"]`). Paths are compared
     as `(os.path.realpath(os.path.dirname(p)), os.path.basename(p))`,
     the normalisation `places_of` uses: a differently spelled home still
     matches, and a link is never collapsed onto its target folder;
   - `paths`: the sorted `existing` destinations (the dialog and the
     re-plan compare on this and on `sorted(records)`).
   The plan refuses (section 2) when: a destination is a link whose
   resolved target is not another destination of this run; a destination
   exists but is neither a link nor a folder holding `SKILL.md`; a live
   record of another name lists a destination; a record in `records` has a
   live path outside `destinations`; or the store and an existing
   destination's parent are on different devices
   (`os.stat(parent).st_dev != os.stat(store).st_dev`, store created with
   `os.makedirs(mode=0o700, exist_ok=True)` first). When nothing exists and
   `records` is empty, the plan is empty and the run is a fresh install
   with the flag ignored; the dialog is the ordinary one.
   Without `--replace`, `conflict_reason` runs as today with the new
   sentences (section 2).
4. **Writability** (unchanged): an unwritable parent refuses before asking.
5. **The dialog** (`add.dialog_text`): with a non-empty plan the summary
   carries `replacing = {"paths": [shortened existing destinations],
   "recorded": "<date>" | None}` and the dialog gets one more block, after
   `Into:`:
   ```
   This replaces the installed <name> at <paths> (recorded <date>).
   The copy there now is set aside, not deleted; canary restore puts it back.
   ```
   `(recorded <date>)` uses the newest `installed_at` among `records`;
   with no record the parenthesis reads `(not installed by SkillCanary)`.
   Verdicts, override and the typed name are exactly the fresh install's.
   A decline, no answer, or an unsafe refusal records the decision
   (`record_decision`) and returns as today; nothing has moved.
6. **Take `add._Commit`** (flock on `~/.agents/.canary-lock.json.lock`),
   held through step 13. `guestlist._Lock` is never held by this code
   except inside `guestlist.record_install` and
   `guestlist.record_events` (new; section 1.5), each of which takes and
   releases it itself.
7. **Re-plan** (`replace.plan` again on the re-read lock). Any refusal
   refuses now. If `plan["paths"]` or `sorted(plan["records"])` differ from
   the pre-dialog plan: refuse with the "changed while you were deciding"
   sentence. Nothing has moved. (Without `--replace`: `conflict_reason`
   and `choose_key` as today.)
8. **Capture the old ledger states** (`replace.ledger_states(support,
   paths)`): `guestlist._state(guestlist._events(support))` read without
   the ledger lock (as `watcher._approved` does), one entry per existing
   destination's real path: `{status, digest, approved, override, origin,
   since}` or `None`. These feed the undo (step 10) and the group record.
9. **Set aside** (`replace.set_aside(support, name, "canary add", plan,
   states)` → group id, or `None` for an empty plan):
   1. `id = time.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)`
      (the `watcher.HOLD_ID` format); `os.makedirs(store/<id>, mode=0o700)`.
   2. Write `replaced.json` (section 3) **before any rename**.
   3. For each `existing` destination in order: `os.rename(dest,
      store/<id>/entry-<n>)`. A link moves as a link, exactly as
      `watcher.hold` moves one.
   4. If a rename fails: rename back every entry already moved. When every
      one went back, remove the group folder (`os.unlink(replaced.json)`
      then `os.rmdir`, which refuses while any `entry-*` remains; never
      `shutil.rmtree` on a group); when one could not go back, keep the
      group, and the raised `OSError` carries the paths left so the
      caller's reason names them and the id (the undo-incomplete
      sentence). `add.add` then refuses with the set-aside sentence; no
      ledger event and no lock write has happened, so the lock and the
      ledger are as before.
   Ledger: nothing yet. Lock file: nothing yet. Death after 9.2: an empty
   group with a record; `canary list` shows it with `kept: []`, and
   `canary restore` refuses it with the "nothing left in the store"
   sentence; it is harmless and the person may delete the folder. Death
   after a rename in 9.3: some destinations empty, their old copies in the
   store, ledger state untouched. Recovery: `canary restore <id>` puts
   back the kept members whose origins are empty (section 4); the watcher
   leaves a put-back `checked` or `yours` copy alone because the ledger
   still says so.
10. **The new record's key.** Delete the old keys from the in-memory lock
    (`for key in plan["records"]: del lock["skills"][key]`). With exactly
    one old record, the new record reuses its key (so a `name@hash` key
    stays what it was and a restore writes the old record back under it).
    With none, or with several (a bare and a hashed key both live for this
    name), `key = choose_key(lock, name, places)`: the existing rule, with
    the old keys gone and the destinations empty. `None` refuses with the
    "Another install got there first" sentence after
    `replace.put_back_files(support, group)` (section 1.4): file moves
    only, no ledger write, because no approval has been recorded yet.
11. **Record approval** (unchanged): `_record(guestlist.record_install, …,
    source=snapshot, origin=…)` appends `checked` and one `approved` per
    destination with the snapshot's digest. Death after: approval for paths
    that are empty; the next scan records `removed`; the old copies are in
    the store. Recovery: `canary restore <id>` (it records its own
    approval before the move, so the stale one does no harm).
12. **Install** (`add._install`, unchanged): stage beside each destination,
    confirm the tree digest, rename in. On `None`:
    `replace.undo(home, support, group, states, name)` (section 1.4) puts
    the old copies back and returns the paths it could not put back; the
    reasons get `_install`'s sentence plus the undo sentence. Death inside
    `_install`: staging folders beside the destinations (the watcher holds
    them later, as for a fresh install today), some destinations filled
    with unrecorded new copies, the rest empty, old copies in the store.
    Recovery: `canary restore <id>` sets aside whatever is at each origin
    into a new group and puts the old copies back.
13. **Lock write** (`add._finish`, two additions): the new record gets
    `"replaced": "<group id>"` when a group exists; the old keys were
    deleted in step 10, so the write removes them. On `OSError` the
    existing code removes the new copies; then `replace.undo` puts the old
    copies back and the reasons get both sentences. Death before the write:
    the lock still holds the old records, which now look live (their paths
    hold the new copies), with no `replaced` field. `canary list` shows
    the new copies as `checked` (the ledger is right), and `canary restore
    <id>` still works (it sets aside whatever is at the origins). `canary
    doctor` does not report this; accepted.
14. **Record the replace** (`replace.record_replaced(support, group, how)`
    through `add._record`, so a ledger failure never undoes an install):
    one event per member (section 1.5). Death before: no event; the ledger
    is still correct about every path.
15. Release `_Commit`; remove `quarantine/<run id>` (unchanged `finally`).
    The result carries `"replaced": {"id": "<group id>", "paths": [...]}`.

### 1.2 `canary install --replace -- <installer>`

`install.install(argv, replace=True)`.

1. `installers.kind` as today. With `--replace`, a `plugin` or
   `marketplace` command raises `InstallError` (exit 2) with the sentences
   in section 2, before any staging or run.
2. `_skills`: staging, the installer run, `_appeared`, the failure checks,
   `_landed`, the folder-name check, `link_plan`, `taken`, `places`: all
   unchanged. The first `conflict_reason(lock, [], places, taken, home)`
   (destinations only, before names) is **skipped** when `replace` is
   true; the plan runs once names are known.
3. `_snapshot_and_check` as today (one classifier call per skill).
4. With `--replace`, refusals once names and destinations are known, with
   nothing recorded (no `record_decision`) and the installer not run again:
   more than one name in `names`; any path in `taken` whose
   `os.path.realpath(os.path.dirname(p))` (the normalisation of 1.1 step 3,
   which never collapses a link onto its target) is not in
   `guestlist.user_roots(home)` (a project destination); then
   `replace.plan(lock, name, taken, roots, home, support)` with its own
   refusals. The destinations of an install are `taken`: the real folder
   and every link the installer made between its skills, so an npx layout
   (`~/.agents/skills/x` plus the link `~/.claude/skills/x`) is replaced
   as a unit and recreated as a unit.
5. The dialog (`install.dialog_text`) gets the same block as `canary add`,
   placed after `Into:`, from an `items[0]["replacing"]` field.
6. Under `add._Commit`: re-plan and compare (refuse on difference), capture
   states, `replace.set_aside(..., "canary install", ...)`, delete the old
   keys, `choose_key`, the existing `record_install` loop, the existing
   install loop (folders then links), the lock record with
   `"replaced": "<group id>"`, `add._write_lock`. The existing `except
   (OSError, add.SourceError)` branch, after removing what it copied, calls
   `replace.undo` and adds the undo sentence. Then `record_replaced`
   through `add._record`. Crash points and recovery are as in 1.1.

### 1.3 Without the flag

`_blocked_sentence` and `conflict_reason` keep their shape and change their
last sentence (section 2). Nothing else changes.

### 1.4 Undo (`replace.undo`) and `replace.put_back_files`

`replace.put_back_files(support, group)` is the file-only half: it renames
each kept entry back to its origin, removes the group folder when every
entry went back (`os.unlink` of the record, then `os.rmdir`, which refuses
while any entry remains), and returns the paths left in the store. It
writes nothing to the ledger. Step 10 of 1.1 uses it alone, because no
approval exists yet to compensate.

`replace.undo(home, support, group, states, name)` runs under `_Commit`
after `_install` or the lock write failed (an approval for the new digest
is in the ledger) and the existing code has removed the new copies it put
in place. In this order:

1. **Compensating ledger events first**, through `add._record(
   guestlist.record_events, support, events)`, one per member, chosen
   from the state captured in step 8, all with `"how": "replace undo"`:
   - `checked`: `{"event": "approved", "how": "replace undo", "name",
     "skill": path, "digest": <old approved digest>, "override": true
     when it was, "origin": <old origin> when there was one}`, followed by
     `{"event": "changed", "skill": path, "name", "digest": <old current
     digest>}` when the old copy had drifted from its approval;
   - `yours`: `{"event": "trusted", "how": "replace undo", "name", "skill":
     path, "digest": <old digest>}`;
   - `unchecked` or no state: `{"event": "arrived", "how": "replace undo",
     "name", "skill": path, "digest": <old digest, or
     guestlist.digest(entry) when there was none>}`.
   A link member gets no event (its target member gets one).
   The events are written before the files reappear, the same rule as
   every install: the watcher reads the ledger after an entry settles.
2. **`put_back_files`**: each entry back to its origin. An origin that is
   no longer empty (something raced in) or a rename that fails leaves that
   entry in the store; the others still go back.
3. Return the paths left in the store; the caller's reason names them and
   the group id. No code path deletes an entry.

Every rename of an entry (set-aside, put-back, restore) goes through
`replace._rename(src, dst)`, a one-line wrapper over `os.rename`, and every
device read through `replace._device(path)` (`os.stat(path).st_dev`); both
exist as test seams, so no test patches the global `os` module for them.

Residual, stated in the architecture text: at Guard, an old copy that was
`unchecked` or had no ledger state comes back as a new arrival when a
watcher look fell inside the gap (its `seen` set changes only when `step`
runs), and the watcher may then hold it and ask the person; nothing is
deleted. A `checked` or `yours` copy is left alone because its state is
restored first.

### 1.5 Ledger and lock-file writes, exact shapes

New helper `guestlist.record_events(support, events)`: takes `_Lock`,
`_append`, raises `OSError`. `watcher._record` becomes a wrapper that
swallows the error, as it does now. Nothing calls `record_install` or
`record_events` while holding `_Lock`; `replace.py` never enters `_Lock`.
`add._Commit` (a different flock file) is held around both; that nesting is
safe, and a test guards the other one (section 6, test 13). Lock order,
fixed: `_Commit` is taken before `_Lock`, never the reverse. The watcher
and `guestlist.scan` take only `_Lock`; `setup.prune_records` takes only
`_Commit`; `add.add`, `install._skills` and `replace.restore` take
`_Commit` and, inside it, `_Lock` through the two helpers only.

Events written by a replace, in order of appearance:

```
{"at": …, "event": "checked", "name": "<name>", "verdict": "…"}                  record_install, unchanged
{"at": …, "event": "approved", "how": "canary add" | "canary install",
 "name": "<name>", "skill": "<destination real path>", "digest": "sha256:…",
 "origin": {…}, "override": true}                                              record_install, unchanged, one per destination
{"at": …, "event": "replaced", "id": "<group id>", "name": "<name>",
 "skill": "<origin>", "kind": "folder" | "link", "how": "canary add" | "canary install" | "restore"}   one per member, after the lock write
```

Events written by a restore (section 4): one `record_install` call per
kept folder member, so `checked` and `approved` once each per member
(`checked × n`, `approved × n` for n folder members), each with that
member's own verdict and `override`, `"how": "restore"` and the old origin
(or `{"kind": "watcher"}`); then `replaced` for the new group's members
with `"how": "restore"`; then `{"at": …, "event": "restored", "id": "<old
group id>"}`.

`_state` treats `replaced` as unknown and ignores it; `restored` has no
`skill` and is skipped, as the watcher's is today.

Lock record, written by `_finish` (add) or the install loop, fields as
today plus one:

```json
{"<key>": {"name": "…", "places": […], "source": "…", "owner": "…", "repo": "…",
           "ref": "…", "commit": "…", "path": "…", "package_digest": "sha256:…",
           "verdict": "…", "installed": […], "installed_at": "…",
           "replaced": "20261017T101500Z-9f3c2a1b"}}
```

`replaced` names the group that holds the copies this record replaced. A
restore writes the old record back (section 4) with `replaced` set to the
group holding the copy it displaced, and removes the displaced copy's
record. The schema string stays `canary.lock/1`.

## 2. Refusals, exact sentences

Without the flag (`add._blocked_sentence`, `add.conflict_reason`):

- `A skill named <name> is already installed at <paths> (recorded <date>). Nothing was installed. To replace it, run this again with --replace.`
- `<path> already exists. Nothing was installed. To replace it, run this again with --replace.`

With the flag, before the dialog and again under `_Commit`, nothing
recorded and nothing moved (`replace.plan`):

- Different name: `<path> is recorded as the skill <other> (recorded <date>); --replace replaces only a skill of the same name. Nothing was installed.`
- Old record elsewhere (the `--host` subset case, and an installer whose
  destinations do not cover the old record): `A skill named <name> is installed at <all live paths>; this run would replace only <this run's paths among them>, so it replaced nothing. Replace all of them in one run.`
- A link elsewhere: `<path> is a link to a folder this install would not replace, so SkillCanary did not replace it. Nothing was installed.`
- Not a skill: `<path> exists but holds no SKILL.md, so SkillCanary does not know what it is and left it alone. Nothing was installed.`
- Different disk: `SkillCanary keeps replaced copies under <store>, which is on a different disk from <path>, so it cannot set the old copy aside. Nothing was installed.`
  (on restore: `Still set aside: SkillCanary keeps replaced copies under <store>, which is on a different disk from <path>, so it cannot set the copy that is there now aside. canary list shows where it is.`)

With the flag, `canary install` only, after the check, nothing recorded:

- More than one name: `This install would add <n> skills; --replace works for one skill at a time. Nothing was installed.`
- A project destination: `--replace works only in your own skills folders (~/.claude/skills, ~/.agents/skills), not in a project. Nothing was installed.`

With the flag, at `install.install` entry (`InstallError`, exit 2):

- Plugin: `--replace applies to skills only. To update a plugin, run: canary install -- claude plugin update <plugin id>`
- Marketplace: `--replace applies to skills only; a marketplace add has nothing to replace.`

Under `_Commit` only:

- Changed while deciding: `What is installed as <name> changed while you were deciding; nothing was changed. Run this again.`
- Set-aside failure: `SkillCanary could not set the earlier copy of <name> aside, so nothing was changed.`

After a failed install or lock write (added to the existing sentence):

- Undo complete: `The earlier copy is back in place.`
- Undo incomplete: `SkillCanary could not put the earlier copy of <name> back at <paths>; it is kept as <group id>. canary restore <group id> tries again.`
- Restore undo incomplete (section 4.6): `Still set aside: SkillCanary could not move it back, and could not put the copy that was there back at <paths>; that copy is kept as <G2 id>. canary list shows where it is.`

Outcomes and exit codes are unchanged: every refusal above is
`not_installed` (exit 10) except the two `InstallError`s (exit 2).

## 3. The store for old copies

Path: `~/Library/Application Support/Canary/quarantine/replaced/<id>/`,
mode 0700, where `<id>` matches `watcher.HOLD_ID`
(`\d{8}T\d{6}Z-[0-9a-f]{8}`). Under the quarantine, so the gate denies
agents' file tools there and shell commands that name it (`gate.decide`,
rules 6 and the quarantine text pattern); `add.add`'s `finally` removes
only `quarantine/<run id>`, and the watcher reads only `quarantine/held`.

Contents: `replaced.json` and `entry-<n>` for each member (a folder, or a
link exactly as it was). The record, written before any rename:

```json
{"schema": "canary.replaced/1",
 "id": "20261017T101500Z-9f3c2a1b",
 "name": "design-taste-frontend",
 "at": "2026-10-17T10:15:00Z",
 "how": "canary add",
 "members": [
   {"entry": "entry-0", "origin": "/Users/abe/.agents/skills/design-taste-frontend", "kind": "folder"},
   {"entry": "entry-1", "origin": "/Users/abe/.claude/skills/design-taste-frontend", "kind": "link"}],
 "states": {"/Users/abe/.agents/skills/design-taste-frontend":
             {"status": "checked", "digest": "sha256:…", "approved": "sha256:…",
              "override": false, "origin": {"kind": "installer"}, "since": "2026-10-01T09:00:00Z"}},
 "records": {"design-taste-frontend": {"...": "the lock record exactly as it was"}}}
```

`states` holds the ledger state of each folder member's real path at
set-aside time (`null` when there was none); `records` holds every lock
record the replace removed (`{}` for an untracked folder). `how` is
`canary add`, `canary install` or `restore`.

Listing (`replace.groups(support, roots)`), read from the store like
`watcher.held` reads holds, never from the ledger: a group counts when its
folder name matches `HOLD_ID`, `replaced.json` parses with `schema`,
`id` equal to the folder name, a `name` that `add.NAME.fullmatch` accepts
(so the restore dialog's phrase is never blank), `at` and a `members` list
whose every `origin` is a string whose `dirname` is in `roots`. Each listed group
is `{"id", "name", "paths": [origins], "kept": [origins whose entry
lexists], "at", "how", "restore": "canary restore <id>"}`, oldest first.
`canary list --json` adds `"replaced": [...]` to `canary.list/1` (an
additive field); the text output adds, after the held section:

```
Set aside by a replace (nothing is deleted):
  <name>  replaced <date>  <paths>  to restore: canary restore <id>
```

`session_line` does not count them: a replaced copy is the person's own
decision, not something waiting on them. The watcher's `held()`,
`_review_loop`, `review`, `step` and `session_line` are not touched and
never see the store.

Older SkillCanary versions: nothing before this program reads
`quarantine/replaced/`; `_state` ignores `replaced` events and the `how`
values; the lock field `replaced` is additive and `record_paths`,
`is_live`, `plan_key` and `old_records` ignore unknown fields. A rollback
leaves the store in place, restorable only by a version that knows it.

Retention: nothing is pruned. Each replace keeps one group; `canary doctor
--prune` does not touch the store (it edits only the lock file). The
person can delete a group folder by hand; agents cannot (the quarantine
rule). A later program may add a prune with a dialog. Said in the
architecture text.

## 4. `canary restore <id>` for a replaced group

`watcher.restore(held_id, …)` branches: an id in `watcher.held(...)` takes
the existing path unchanged; else an id in `replace.groups(...)` calls
`replace.restore(id, home, support, ask, backend, model)`; else
`ValueError("SkillCanary is not holding or keeping anything with that id; canary list shows what it has.")`.
`cli._restore` prints `line or "Put back where it was."` on `(True, line)`
and the reason on `(False, reason)`; exit codes 0 and 10 as today.

Steps:

1. Load the group (validated as in section 3). Members whose entry does
   not exist are not restorable; if none is kept: `(False, "Still set aside: nothing of it is left in SkillCanary's store.")`.
2. For each kept folder member: `add._copy_local(entry, temp)` and
   `classify.check` (one classifier call per folder; a `canary add` group
   has two identical folders and costs two). `SourceError`/`OSError`:
   `(False, "Still set aside: it holds links or special files SkillCanary will not copy. canary list shows where it is.")`
   and `record_decision(home, name, "UNSAFE", "refused", support=support)`,
   as `watcher.review` does. Links are not checked; the plan
   guaranteed each link's target is another member.
3. One dialog (`replace.dialog_text`), worst verdict of the members,
   through `add.ask`; `UNSAFE` adds the text field with the name as the
   phrase (`name` is a validated `NAME`, never blank):
   ```
   Put back the earlier <name> you replaced on <date>?

   SkillCanary checked that earlier copy again: <no problems found | needs your judgment | UNSAFE>.

   <recommendation text>

   <headline, unless generic>

   What SkillCanary found:
   <risks and quoted lines, as the watcher's dialog>

   What it can do:
   - It <capability>.

   Folders: <origins, shortened with ~>

   Install puts it back. The copy there now is set aside the same way, so you can switch again. Cancel keeps it set aside; nothing is deleted.
   The folder names come from the packages, not from SkillCanary.<So do the file names and quoted lines.>

   <override sentence when UNSAFE>
   ```
   Cancel: `(False, "Still set aside: you chose not to put it back. canary list shows where it is.")`; no answer: `(False, "Still set aside: nobody answered the SkillCanary dialog. canary list shows where it is.")`; `UNSAFE` without the typed name: the same two, and `record_decision(... "refused")`.
4. Under `add._Commit`:
   1. Re-load the group; refuse if a kept entry vanished (step 1's
      sentence).
   2. `replace.current_plan(lock, origins, roots, home, support)` →
      `(reason, plan)`, a separate function from `replace.plan` with no
      name rule: `existing` is each origin that `lexists`, which must be a
      link whose target is another origin of this group or a folder with
      `SKILL.md`; else `(False, "Still set aside: something SkillCanary does not move is at <path>. canary list shows where it is.")`.
      `records` is every lock record, **live or not**, any name, whose
      `record_paths` include an origin (paths compared as in 1.1 step 3);
      a record left behind by a death after 4.4 lists empty origins and is
      dead, and must still be found. Every path of every such record must
      be among the origins; else `(False, "Still set aside: the copy at <path> is also installed at <others>; replace all of them in one run first. canary list shows where it is.")`.
      Same-device preflight through `replace._device` for each existing
      origin; else the different-disk sentence in `Still set aside:` form
      (section 2). Then the keys for 4.7 are decided now, before any move:
      delete `records`' keys from the in-memory lock; for each record in
      the old group's `records`, its key is its stored key when that key is
      absent or holds a dead record, else `choose_key(lock, name,
      record_places(record))`; `None` refuses with
      `(False, "Still set aside: another install got there first. canary list shows where it is.")`.
   3. Capture the current ledger states for the origins (as 1.1 step 8).
   4. `replace.set_aside(support, name, "restore", current plan, states)`
      → new group `G2`, or `None` when every origin is empty. Failure:
      `(False, "Still set aside: SkillCanary could not move the copy that is there now. canary list shows where it is.")`.
   5. Approval first: for each kept folder member,
      `guestlist.record_install(home, [origin], name, <that member's own
      verdict>, support=support, source=<its temp copy>, how="restore",
      override=(<that member's verdict> == "UNSAFE"),
      origin=<states[origin]["origin"] from the old group when its status
      was checked and it had one, else {"kind": "watcher"}>)`. One call per
      folder member, so the ledger gets `checked` and `approved` once per
      member, each with its own digest, verdict and override (the dialog
      asked with the worst verdict; the record keeps each member's).
   6. `os.rename(entry, origin)` for each kept member. On a failure:
      rename back the members already moved into the old group, append
      compensating events for the current copies (1.4, from the states of
      4.3), then `put_back_files(support, G2)`. When every `G2` entry went
      back (and `G2` is gone):
      `(False, "Still set aside: SkillCanary could not move it back. canary list shows where it is.")`;
      else the restore-undo-incomplete sentence of section 2 with the
      paths left and the `G2` id.
   7. Lock: the keys found in 4.2 are already deleted in memory (their
      records go into `G2`'s `records`, dead ones included); write each
      record from the old group's `records` back under the key decided in
      4.2 (its own key whenever that key was free) with `"replaced":
      "<G2 id>"` when `G2` exists (the field is dropped when it does not).
      An untracked original had no record and gets none. `add._write_lock`.
      On `OSError`: the files stay as moved (the ledger is right about
      them), the old group folder is kept, and the line says
      `Put back where it was, but SkillCanary could not update its lock file; its record of this skill is stale until the next replace or restore.`
      with `(True, line)`. A later `--replace` or restore corrects the
      lock by path, since both read what is at the destinations.
   8. `record_replaced(support, G2, "restore")` when `G2` exists, then
      `{"event": "restored", "id": <old group id>}`, both through
      `add._record`.
   9. Remove the old group's folder: `os.unlink` of `replaced.json`, then
      `os.rmdir`, which refuses while any entry remains; never
      `shutil.rmtree` (unlike `watcher.put_back`, which may `rmtree` an
      emptied hold).
5. `(True, "Put back where it was; the copy that was there is set aside as <G2 id>.")`, or `(True, None)` when nothing was there.

Death points: after 4.4, before 4.6: the origins are empty, both groups
complete, and the lock still holds the displaced record (dead now). A
second `canary restore <old id>` finds that record in 4.2 (live or not),
moves it into the new group's `records` (that group has no entries, since
the origins are empty), puts the old copies back and writes the old
record; the first `G2` stays listed and restorable. After 4.6, before
4.7: files right, lock stale (the displaced record still present and now
pointing at the old copy); `canary list` is right (ledger); a later
`--replace` or restore finds that record by path and corrects the lock.
Accepted and said.

Recovery after a replace that died mid-way (1.1, steps 9 to 13) is this
same command: `kept` members whose origin is empty go back without a
`G2` member for that origin; origins holding an unrecorded new copy are
set aside into `G2` like any other folder with a `SKILL.md`.

## 5. Interfaces, docs first

### 5.1 CLI and USAGE (`canary/cli.py`)

```
       canary add <github-link-or-folder> [--replace] [--host claude|codex]... [--json | --text]
         [--backend <name>] [--model <id>] [--timeout <seconds>]
       canary install [--replace] [--json | --text] [--backend <name>] [--model <id>]
         [--timeout <seconds>] -- <installer command>
       canary restore <held-id-or-replaced-id>
```

`_add`: `--replace` joins the allowed flags (`flags - {"--json", "--text",
"--replace"}`) and is passed as `replace="--replace" in flags`. `_install`:
the same for `options`. No flag approves anything; `--replace` only
changes what happens to a copy already there, and the dialog says so.

### 5.2 JSON fields

- `canary.add/1`: `"replaced": {"id": "<group id>", "paths": ["~/.claude/skills/<name>", …]}`
  on `installed` when a group was created; absent otherwise. `render_text`
  adds `  Replaced: <paths> (set aside as <id>; canary restore <id> puts it back)`.
- `canary.install/1`: the same field and text line.
- `canary.list/1`: `"replaced": [{"id", "name", "paths", "kept", "at", "how", "restore"}]`.
- Lock record: `"replaced": "<group id>"`.
- Ledger: `replaced` and `restored` events, and `"how": "replace undo"` on
  `approved`, `trusted` and `arrived`, as in 1.5.

### 5.3 `docs/architecture.md` text (edited before the code)

Replace the paragraph ending `… to replace an installed skill, the person
removes its folder and adds it again.` (the `canary add` section) with:

> The installed name is the frontmatter `name` if it matches
> `^[a-z0-9][a-z0-9-]{0,63}$`, else the folder name if that matches, else the
> add is refused. An existing folder of that name is never overwritten
> silently: without `--replace` the add is refused; with it, the copy there
> is set aside first (below, "Replacing an installed skill").

Replace the two refusal sentences in **Refusals** with the section 2
sentences (`To replace it, run this again with --replace.`).

Add, after **Refusals** in the `canary add` section:

> **Replacing an installed skill: `--replace`** (program 2026-10-17). With
> `--replace`, `canary add` and `canary install` update a skill that is
> already installed under the same name, in one step. The new copy is
> fetched, checked, approved and recorded exactly as a fresh install; the
> dialog adds `This replaces the installed <name> at <paths> (recorded
> <date>). The copy there now is set aside, not deleted; canary restore puts
> it back.` Under the commit lock, the copies at the destinations (a real
> folder holding a `SKILL.md`, or a link to another destination of the same
> run) are renamed into `quarantine/replaced/<id>/entry-<n>` next to
> `replaced.json`, which names the group, each member's origin and kind,
> the ledger state and the lock records it replaced; the record is written
> before any rename. Only then is approval recorded and the new copy staged
> and renamed in, as for any install; the lock record carries `"replaced":
> "<id>"` and the old records are removed from the lock. If the install
> fails, the old copies go back: the ledger first gets a compensating event
> (`approved`, `trusted` or `arrived`, with `how: replace undo`) restoring
> each path's earlier status, then the entries are renamed back. A copy
> SkillCanary had never approved may therefore return as a new arrival
> that the watcher at Guard holds and asks about; nothing is deleted. The
> replace refuses, before the dialog and again under the lock, when the
> same name is also installed in a folder this run would not replace, when a
> destination belongs to a record of another name, when a destination is a
> link to somewhere outside the run, when it holds no `SKILL.md`, when the
> store is on another disk, when a `canary install` would add more than one
> skill or would write to a project, and for plugin and marketplace
> commands; the sentences are fixed in `canary/replace.py`. The store is
> never pruned; `canary doctor --prune` does not touch it.

Add to the guest list section, after the `canary list` bullet:

> - `canary list` also lists what a replace set aside, read from the store
>   (`quarantine/replaced/`), as `replaced: [{"id", "name", "paths", "kept",
>   "at", "how", "restore"}]` and a text section `Set aside by a replace`.
>   The session-start notice does not count them.

Replace the `canary restore` sentence in the watcher section's heading
and add at its end:

> `canary restore <id>` also takes a replaced group's id: it checks the
> earlier copy again (both layers), asks the person with `Put back the
> earlier <name> you replaced on <date>?`, and on their yes, under the
> commit lock, sets aside whatever is at the origins now into a new group
> (so a restore can be undone the same way), records approval for the
> earlier copy, renames it back, writes its old lock record back and
> removes the displaced one. Every refusal is one `Still set aside: …`
> line. A replace or restore that died between its steps leaves the old
> copies in the store and some origins empty; `canary restore <id>` is the
> recovery for every such state.

Replace item 5 of **How people get Canary and use it**:

> 5. **Replacing:** `canary add <link> --replace` (or `canary install
>    --replace -- …`) updates an installed skill. The new copy is checked
>    and approved like any other; the earlier copy is set aside and `canary
>    restore <id>` brings it back.

`skills/canary/SKILL.md` gains one sentence under the install guidance:
`When they want to update a skill that is already installed, run the same
command with --replace; the earlier copy is kept and canary restore <id>
brings it back.` (No text anywhere names a `canary update` command; the
pin test in `tests/test_add.py` checks that.)

## 6. Tests, red first

Each test names the seam it uses to inject a fault. New tests live in
`tests/test_replace.py` unless named otherwise; they reuse `test_add.Env`,
`test_install.Mac` and `test_watcher.Mac`.

1. `test_add`, pins changed: the two sentences without the flag, for a
   recorded skill (both hosts) and an untracked folder (`tests/test_add.py`
   lines 516–519, 526–527, 531–533, 575–577; `tests/test_install.py` 470–473,
   488–489, 507–509). No seam.
2. Replace with a yes, recorded old copy at both hosts (`Env.write_lock`
   with a live record): both destinations hold the new `SKILL.md`; the old
   copies are at `quarantine/replaced/<id>/entry-0` and `entry-1`;
   `replaced.json` has the section 3 shape with that record under
   `records`; the lock has one record, `replaced == id`, old key gone;
   ledger order is `checked`, `approved` ×2 (new digest), `replaced` ×2;
   `result["replaced"] == {"id", "paths"}`; `render_text` has the line.
3. HireReach: an untracked folder at `~/.agents/skills/x` plus a relative
   link `~/.claude/skills/x -> ../../.agents/skills/x` (as
   `FAKE_SKILLS_CLI` writes them), no lock record, ledger state `yours`
   (first look taken): `canary add --replace` sets aside the folder and the
   link (`kind` folder/link), installs two real folders, `records == {}`;
   then restore (test 17) puts the folder and the link back and the link
   resolves to the old folder.
4. A no leaves everything: no store folder, no ledger `approved`, lock
   unchanged, old folder's bytes unchanged. UNSAFE new copy without the
   typed name: `refused`, same checks.
5. The dialog block: `add.dialog_text(summary)` contains the two lines
   exactly with `(recorded 2026-10-05)`, and `(not installed by
   SkillCanary)` for an untracked folder; `install.dialog_text` the same.
6. Refusals before the dialog (`approve.seen == []`, nothing moved, no
   store folder, `record_decision` written as for any conflict): `--host
   claude` against a two-host record (subset sentence); a different-name
   record listing the destination; a link to a folder outside the
   destinations; a folder without `SKILL.md`; a plain file at the
   destination.
7. Different disk: seam `unittest.mock.patch.object(replace, "_device")`
   returning a different number for paths under the store; the sentence,
   nothing moved; the same seam on a restore gives the `Still set aside:`
   form.
8. Changed while deciding: the approver creates the second destination
   (or writes a lock record) during the dialog; the under-lock re-plan
   refuses with the sentence; the first destination's old copy is still in
   place; no store folder.
9. Second rename-in fails: seam `patch.object(add.os, "rename")` wrapping
   the real `os.rename` and raising `OSError` on the second call whose
   target is a destination. Both destinations hold the old bytes; no store
   folder; the lock is unchanged; the last ledger events for each path are
   the compensating ones (`approved` with the old digest and `how: replace
   undo` for a checked old copy; `arrived` for an untracked one) and they
   precede nothing else; outcome `not_installed` with both sentences; a
   `Watcher.step` over the settle window afterwards holds nothing for the
   checked old copy.
10. Undo rename-back fails too: the seam of test 9 plus
    `patch.object(replace, "_rename")` raising on the rename whose target
    is the second origin; outcome `not_installed`; the
    reason names the path and the group id; the store keeps the group with
    `kept == [that origin]`; `canary list` lists it; `canary restore <id>`
    then puts it back (no `G2`, the origin is empty).
11. Lock write fails after the install: seam `patch.object(add.os,
    "replace", side_effect=OSError)` (as the existing lock-failure test):
    new copies removed, old copies back, compensating events present, lock
    file untouched.
12. The process dies after set-aside: seam `patch.object(add, "_install",
    side_effect=RuntimeError)`; `assertRaises(RuntimeError)`; destinations
    empty, entries kept, lock unchanged, ledger has the new `approved` only;
    `canary restore <id>` puts both back, no `G2`, and the watcher's next
    `step` holds nothing (the old state was `checked`).
13. Ledger lock never re-entered: seam a wrapper on
    `guestlist._Lock.__enter__` counting depth per thread and failing the
    test above 1, installed for a whole replace, a failed replace with undo,
    and a restore.
14. The watcher and the notice: after a replace, `Watcher.step` over the
    settle window returns `[]`, `watcher.held()` is `[]`, and
    `guestlist.session_line(scan(...))` is `None`; `scan()["replaced"]`
    has one group with `restore == "canary restore <id>"`.
15. `canary install --replace` over an npx layout installed earlier by
    `canary install` (`test_install.ONE`): both entries set aside, the new
    folder and link in place, the link resolving to the new folder, one
    lock record with `replaced`; the installer ran once (`mac.runs()`).
16. `canary install --replace` refusals: two names (spec with two skills):
    the sentence, installer ran once, nothing recorded, no store folder; a
    project install (`PROJECT_ADD`): the sentence; `claude plugin install`
    and `claude plugin marketplace add` with `replace=True`: `InstallError`
    with the sentences and `mac.runs() == []`.
17. Restore with a yes (group from test 2): old copies back at both
    origins; the new copies in `G2` with the new lock record under `G2`'s
    `records`; the lock has the old record back under its old key
    (`name@hash` in a variant of the test where the old record sat under a
    hashed key) with `replaced == G2`; ledger order: `checked`, `approved`,
    `checked`, `approved` (one pair per folder member, `how: restore`, old
    origin carried), `replaced` ×2 (`how: restore`), `restored`;
    `canary list` lists `G2` only; the watcher's next `step` holds nothing.
18. Restore when both origins are empty: no `G2`; `(True, None)`; the
    old record back without `replaced`.
19. Restore refusals: a plain file at an origin (sentence, nothing moved);
    a current record spanning a path outside the origins (sentence); a no
    and no answer (sentences, `record_decision` for the unsafe case); an
    unknown id (`ValueError` sentence); a group whose entries were removed
    by hand (`nothing of it is left`).
20. Restore rename fails on the second member: seam
    `patch.object(replace, "_rename")` raising on the second old entry's
    move; the current copies are back at their origins, the old group
    intact, no `G2`, compensating events for the current copies,
    `(False, "Still set aside: SkillCanary could not move it back. …")`.
    A variant also raises on the `G2` put-back: the restore-undo-incomplete
    sentence with the path and the `G2` id, and `G2` kept with that entry.
21. Restore of an UNSAFE old copy needs the typed name: `ask` is called
    with `confirm == name`; `False` keeps it set aside.
22. Restore checks every folder member: a two-folder group whose members
    were diverged by hand after the replace gets two classifier calls and
    two `approved` events with different digests (seam: count calls through
    `patch.object(replace.classify, "check", wraps=...)`).
23. `cli`: `_add(["x", "--replace"])` and `_install(["--replace", "--",
    …])` pass `replace=True` (seam `patch.object(add, "add")` and
    `patch.object(install, "install")`, asserting kwargs); `--replace` on
    `canary scan` is a usage error; `USAGE` names it; `_restore` prints the
    returned line.
24. Older data: a lock record with `replaced` and a ledger with `replaced`,
    `restored` and `how: replace undo` events: `guestlist.scan` lists the
    skill as `checked`, `add.plan_key` and `setup.old_records` behave as
    before, and `watcher.held()` ignores the store.
25. Nothing at the destinations with `--replace`: a fresh install, no
    group, no `replaced` field, the ordinary dialog.
26. Partial presence: the old copy at one host only, `canary add` to both:
    one member, two new copies, the dialog names one path.
27. The pin `test_nothing_the_tool_says_points_to_a_command_it_does_not_have`
    stays green after the docs change (no new test; named so the builder
    runs it first).
28. The process dies between the record write and the first rename: seam
    `patch.object(replace, "_rename", side_effect=RuntimeError)` on a
    replace; `assertRaises(RuntimeError)`; the group folder holds
    `replaced.json` and no entry; both destinations still hold the old
    copies; no ledger event, lock unchanged; `canary list` lists the group
    with `kept == []`; `canary restore <id>` answers "nothing of it is left".
29. `choose_key` returns `None` under the lock (two old records deleted,
    then the lock re-read by a racing writer; seam
    `patch.object(add, "choose_key", return_value=None)`): the old copies
    are back, no group folder, no ledger event at all, the "Another install
    got there first" sentence.
30. Restore after a death between 4.4 and 4.6 (seam: `patch.object(replace,
    "_rename")` raising `RuntimeError` on the first old entry's move, then a
    second restore without the seam): the second restore finds the dead
    displaced record, the old copies return, the lock holds the old record
    only, and the first `G2` is still listed.

Red first: tests 2–26 and 28–30 fail at `1465c3b` with the tests applied, on an
assertion or on the missing interface (`TypeError` for `replace=`,
`AttributeError` for `canary.replace`); test 1 fails on its assertion.

## 7. Done when

Logs live in `docs/proof/2026-10-17-replace/`. A log is stamped when its
first line is `commit <full sha>` and its second the interpreter's
`--version`.

1. `red.log`: every test in section 6 fails at `1465c3b` with the tests
   applied, on an assertion or on the missing interface (`TypeError`,
   `AttributeError`); pins (test 1, 27) are listed as pins where they
   cannot be red.
2. `gate-python3.10.log` and `gate-usr-bin-python3.log`: the full gate
   passes at the final commit on both interpreters, stamped.
3. Counterfactuals, full suite, each in `counterfactual-<letter>.log`
   naming the reverted line and the tests that went red; other reds listed
   and explained. The known collateral: any edit under `canary/` turns the
   11 `tests/test_action.py` `CanaryActionTests` cases red through
   `scanner/manifest.json`'s integrity check (`scripts/action.py`), as the
   2026-10-16 audit recorded. At least:
   a. `replace.undo` appends no compensating events → tests 9 and 11
      (their ledger assertions, and test 9's watcher step, which then
      holds the put-back copy);
   b. `set_aside` writes `replaced.json` after the renames → test 28 (the
      group has no record and is unlisted);
   c. the under-lock re-plan is skipped → test 8;
   d. the subset refusal is dropped → test 6;
   e. the link-elsewhere refusal is dropped → test 6;
   f. `record_install` runs before `set_aside` → test 12 (ledger order)
      and 9;
   g. `restore` records approval after the rename → test 17 (ledger order)
      and the watcher step in 17;
   h. `session_line` counts replaced groups → test 14;
   i. the different-device preflight is dropped → test 7;
   j. the `InstallError` for plugins is dropped → test 16;
   k. the old sentence is restored → test 1;
   l. step 10 uses `undo` instead of `put_back_files` → test 29 (a ledger
      event appears);
   m. `current_plan` matches live records only → test 30.
4. A Sol pre-merge review (`~/workspace/scripts/premerge-review`) before
   the full gate, findings folded or answered here.
5. The done-when audit (milestone-auditor, Fable 5.1, `high`, done-when-
   audit skill prompt; fallback an Opus read-only reviewer with the same
   prompt) returns SHOWN for bullets 1 to 3.
6. Merge to `main`, push, tag with the next version after 0.1.5 is cut.

Process: this document is refuted by Spark 1.3 Contributor through
`refute-plan` before any code; findings are folded into sections 1 to 6
and answered in section 9.

## 8. How the design handles each recurring failure area

| Area | Handling | Where |
|---|---|---|
| Lock nesting | `_Commit` held across the commit; `guestlist._Lock` only inside `record_install` and the new `record_events`; `replace.py` never enters it; test 13 fails on re-entry | 1.5; `guestlist.record_events`, `watcher._record` |
| Staging across volumes; the watcher and staged or moved folders | Staging unchanged (beside the destination, same volume); the only cross-tree move is the set-aside rename, preflighted by `st_dev` before the dialog and undone on failure; the watcher never sees the store (outside its roots) and leaves the new copy alone because approval precedes it, as today | 1.1 steps 3, 9, 11, 12; `replace.plan`, `set_aside` |
| Symlinked destinations (npx layout) | A link at a destination is set aside as an entry, as `watcher.hold` does, and put back as `watcher.put_back` does; its target must be another destination of the run, else refused; no digest of links anywhere | 1.1 step 3, 1.2 step 4, section 2 |
| Which lock record and key is the old one | Every live same-name record overlapping the new places, each required to lie within the destinations; one old record lends its key to the new record, several are deleted and `choose_key` decides; records kept in the group and written back under their own key when it is free, else `choose_key`; a restore finds the displaced record whether live or dead | 1.1 steps 3, 10; 4.2, 4.7 |
| Crash and undo ordering | No ledger or lock write before every set-aside rename is done; approval before files, as today; compensating events before the rename-back; one recovery path (`canary restore`) for every death point, each named | 1.1 (every step), 1.4, section 4 |
| Restore of a multi-destination group | One group, `entry-<n>` per member; restore moves every kept member, checks every folder member, and sets aside whatever is at the origins into one new group; all or nothing with undo | section 4 |
| Approval before move | Unchanged for the new copy (`record_install` then `_install`); the restore records approval before its rename; undo records the compensating state before its rename | 1.1 steps 11–12, 1.4, 4.5–4.6 |
| `--host` subset | Refused when an old record has a live path outside this run's destinations; untracked folders are replaced only where this run installs, and the dialog names those paths | section 2 |
| Marketplace and plugin commands | `InstallError` at `install.install` entry, before any run | 1.2 step 1 |
| Untracked folders | Set aside with `records == {}`; the dialog says `not installed by SkillCanary`; restore puts them back and writes no record; an undo makes them `arrived`, which the watcher at Guard then holds (stated residual) | 1.1, 1.4, section 4 |
| Counts in the dialog | Cut: the dialog names the paths and the recorded date; `canary explain` shows the new copy's text; a diff would need its own attacker-text rules | 1.1 step 5 |
| Retention | Nothing pruned; the store is under the quarantine, where agents are denied; the person deletes by hand; a prune with a dialog is future work | section 3 |

## 9. Where each refutation finding is answered

Findings on slices A to C of program 2026-10-16 are marked *A–C, merged*
(folded there, already on `main`). Verdicts: V1
`20261016-180726`, V2 `20261016-181117`, V3 `20261016-181635`, V4
`20261016-184152`, V5 `20261016-184632`.

**V1.** 1 `--replace` in USAGE, flag sets and signatures: 5.1. 2, 3: A–C,
merged. 4 store, listing, id format, `_state`, restore routing: sections 3,
4 (`HOLD_ID` format; `_state` ignores the events; `restore` branches). 5
which digest: no digest of old copies is taken at all; the new copy's
`tree_digest` check is the existing one (1.1 step 12). 6, 7, 9: A–C,
merged. 8 ordering: D starts after A–C merged, which it does (`1465c3b`).
10 done-when checkable: section 7. 11 premises: this document makes no
claim about the gate blocking removal. 12 counts: cut (section 8).

**V2.** 1 remover premise: not claimed. 2, 3, 4, 5, 6, 7: A–C, merged. 8
replace scope and atomicity: same-name records only, all destinations as
one unit, old copies back on any failure, approval for bytes not on disk
compensated before the rename-back (1.1, 1.4). 9 replaced holds nag and
restore half-specified: separate store, `session_line` untouched, restore
events, lock update and dialog in sections 3 and 4. 10 pins: test 1 and 5.3.
11 red definition: section 7 bullet 1 allows the missing interface. 12 log
names and stamp: section 7 header.

**V3.** 1 restore routing: `held` first, then `groups`, then `ValueError`
(section 4). 2 origin through restore: `states[origin]["origin"]` carried
back (4.5). 3 multi-destination restore: one group (section 4). 4 project
destinations: refused (section 2). 5 links: set aside as entries, no
digest, target must be another destination (section 8). 6 conflict
sentences: section 2, no "remove". 7: A–C, merged. 8 untracked folder:
`records == {}`, key by `choose_key`, restore writes none (sections 1, 4).
9 pins: test 1 lists `tests/test_install.py:488–489`. 10: A–C, merged. 11
multi-skill install: refused (section 2). 12 counts: cut. 13 restore with
the destination missing: no refusal; an empty origin gets its copy back
with no `G2` member (section 4). 14, 15, 16: A–C, merged. 17 undo failure:
reports the paths left and the group id; emptied groups removed (1.4).

**V4.** 1 order: D after A–C merged; serial. 2 one slot per entry:
`entry-<n>` per member in one group (section 3). 3 links in lock records:
not needed; links are detected with `os.path.islink` at the destination
(1.1 step 3). 4 staging and ledger window: staging unchanged beside the
destination; no ledger write before the set-aside completes; `_Commit`
held throughout; `_Lock` never held across moves (1.1, 1.5). 5
`SourceError` from `tree_digest`: no digest of old copies; the new copy's
check is the existing one; the restore's `_copy_local` failure has its own
sentence (4.2). 6 record keys: `records` keyed by lock key, `states` per
origin, members with origins (section 3); the old keys are the `records`
keys, and the new key is in the lock record's `replaced` pairing (1.1 step
10, 4.2). 7 refusal timing in `_skills`: after
`_snapshot_and_check`, nothing recorded, no re-run (1.2 step 4). 8
`held()` and `session_line`: untouched; the listing is its own field
(section 3). 9 stale pointers: this document names sites by function; the
pins are listed by current line in test 1. 10 restore dialog and group
rules: section 4 (exact dialog; all or nothing; empty origins go back; no
link digest). 11, 12: A–C, merged, and section 7 bullet 5 names the
fallback auditor. 13 rollback residual: section 3, "Older SkillCanary
versions".

**V5.** 1 `_Lock` deadlock: `record_install` and `record_events` take it
themselves; nothing holds it across them; test 13 (1.5). 2 staging and
`EXDEV`: staging unchanged; set-aside preflighted by `st_dev` before the
dialog, before any approval (1.1 steps 3, 9). 3 merge target: this program
has one branch and merges to `main` when done (section 7). 4 `origin` key
collision: `members[].origin` is the path; `states[].origin` is the ledger
dict; the ledger event uses `skill` for the path (sections 1.5, 3). 5 lock
keys: every live same-name overlapping record is old; each must lie within
the destinations; restore removes every current record listing an origin
and writes the old ones back through `choose_key` (1.1 step 3, 4.7). 6
compensating approval shape: 1.4 names the event dicts; the old verdict is
not needed because `approved` carries the digest, override and origin and
no `checked` event is replayed. 7 uncovered cases: nothing to replace is a
fresh install (1.1 step 3); `--host` subset refused (section 2);
marketplace refused (section 2). 8 in-lock recheck: the re-plan under
`_Commit` with a refusal on any difference (1.1 step 7). 9 untracked
folder qualification: by path only (the destination exists and holds a
`SKILL.md`); the old `SKILL.md` is never parsed (1.1 step 3). 10 counts:
cut. 11 record write order and shapes: `replaced.json` before any rename;
event dicts in 1.5; undo failure reason in section 2. 12 scope of
untouched watcher code and docs-first: section 3 names what is untouched;
5.3 gives the architecture, USAGE and line formats. 13 counterfactual
scope and the rename seam: section 7 bullet 3 and tests 9, 10, 20. 14
retention and lock-write failure: section 3; 1.1 step 13 and 4.7.

**V6** (`20261016-224439`, on this document at `b148f9a`; REWORK, all ten
local). 1 step-10 failure with no approval yet: `put_back_files`, file
moves only (1.1 step 10, 1.4). 2 `replace.current_plan` named with its
rules, and the `Still set aside:` different-disk sentence (4.2, section
2). 3 `checked × n`, `approved × n`, per-member verdict and override (1.5,
4.5, test 17). 4 keys preserved: one old record lends its key, several go
through `choose_key`, restore writes back under the stored key when free,
`None` refused before any move (1.1 step 10, 4.2, 4.7, tests 17, 29). 5
restore matches records listing an origin live or dead (4.2, 4.7, the
death table, test 30). 6 counterfactual (a) → tests 9, 11 with a watcher
step; (b) → test 28, the kill between record and rename (section 7). 7
`replace._device` and `replace._rename` seams (1.4, test 7). 8
`record_decision(… "UNSAFE", "refused")`; `NAME.fullmatch` in group
validation (4.2, section 3). 9 the restore-undo-incomplete sentence with
paths and the `G2` id (section 2, 4.6, test 20). 10 `unlink` + `rmdir`
in 4.9; the `(realpath(dirname), basename)` normalisation in 1.2 step 4.

## 10. Scope cuts, in one place

Refused with a sentence rather than designed: dialog counts; project
destinations; installs adding more than one skill; plugins and
marketplaces; a link to anywhere but another destination of the same run;
a destination without a `SKILL.md`; a store on another disk; a same-name
record that this run would only partly replace; a restore whose current
copy is also recorded elsewhere. Not done: pruning the store; a `doctor`
check for a lock left stale by a death between the file moves and the
lock write.
