# Program: quiet holds (ask once per hold, decide once per content)

Owner decisions (2026-11-15). The owner accepted all three recommendations:

1. **Refuter.** Spark 1.3 Contributor at `max`, through `refute-plan`.
2. **Older approvals are not remembered answers.** An approval made before
   this version, or through `canary add` or `canary install`, does not count
   as a remembered answer (section 2.2). Those dialogs never said that an
   answer covers other copies, so the seven "install anyway" approvals
   already on this Mac do not become standing approvals.
3. **A refused hold leaves the session-start notice.** It stays in `canary
   list` with a note (section 2.6).

Status: design, written for refutation. Base: `main` at `94a2f80` (0.1.5
released). Two slices; each builds in a short-lived worktree branched from
`main` and merges when its "Done when" list is shown. Slice 1 starts from
the commit on `main` that carries this document, whose code is identical to
`94a2f80`; slice 2 starts from the merge of slice 1. The coordinator writes
the start commit into each worker's contract, and the worker checks it with
`git merge-base --is-ancestor <commit> HEAD` before editing. Gate:
`python3 -m unittest discover -s tests` on `python3.10` and
`/usr/bin/python3`. Builder: an Opus worker at `high` (fail-closed install
code; owner routing rule). This document is the whole contract; the builder
finds each site by name, not by line number.

## 0. The idea in one paragraph

The watcher holds a skill that arrives without SkillCanary's check and asks
the person about it. Today it asks about every hold again at every restart,
it asks even when the hold can never go back because another copy has taken
its place, nothing ends a hold except putting it back, and each copy of the
same skill gets its own question. On this Mac that left eight holds that
can never be put back and are asked about at every restart (section 4).
This program makes two changes. Slice 1: the watcher asks about a hold once,
when it makes the hold, and never at a restart; it deletes a held copy
without asking when the same bytes are already installed and approved at
the hold's place; and a new command, `canary drop <held-id>`, lets the
person delete any other hold. Slice 2: the person's answer in the held-skill
dialog covers every copy with exactly the same content, so a second copy is
put back or kept held without a second question. Every deletion writes its
ledger record first. Every automatic deletion and every automatic install
needs a byte-for-byte match with a copy that is installed and approved at
that moment; anything else falls back to today's behaviour, which is to
keep the hold and ask.

Verified against the tree at `94a2f80` while writing (file:function):

- `canary/watcher.py:Watcher._review_loop` puts the id of every hold on the
  review queue when the watcher starts, then calls `Watcher.review` for each
  queue item. Its comment says "the next restart asks again".
- `canary/watcher.py:Watcher.review` copies the held entry, runs
  `classify.check` and asks the person before anything looks at the hold's
  place. Only `Watcher.put_back`, which runs after a yes, tests
  `os.path.lexists(origin)` and returns `STILL_TAKEN`.
- `canary/watcher.py:Watcher.hold` names each hold with a time stamp and
  four random bytes, moves the entry to `quarantine/held/<id>/entry` beside
  `hold.json` (`name`, `origin`, `at`), records a `held` event and puts the
  id on the review queue. Two arrivals at one place make two holds.
- `canary/watcher.py:held` lists holds from the quarantine folder, never
  from the ledger. It skips a slot with no `entry`, an id that does not
  match `HOLD_ID`, and an `origin` that is not directly in a watched folder.
- Nothing in `canary/` deletes a hold. `put_back` removes the slot only
  after it has moved the entry back. `canary/cli.py:_restore` and
  `canary/watcher.py:restore` are the only command for a hold.
- `canary/watcher.py:Watcher.step` leaves a new entry alone when
  `_approved(path, self.support)` is true. `_approved` reads the ledger. A
  name is treated as new only when it is absent from `self.seen[root]`,
  which `step` resets to the folder's listing at every look.
- `canary/watcher.py:Watcher.put_back` compares the held entry with the
  checked copy by `guestlist.digest`, records the approval through
  `guestlist.record_install` (`how="watcher"`, `origin={"kind":
  "watcher"}`), and then renames the entry to its place. An `OSError`
  returns `STILL_NOT_MOVED`.
- `canary/guestlist.py:digest` follows links inside a skill, leaves `.git`
  out, and stops after 5,000 files or 64 MB (`MAX_ENTRIES`, `MAX_BYTES`).
  `canary/add.py:tree_digest` covers every file's bytes, path and program
  bit and every directory, with no limit and no skipped folder, and raises
  `SourceError` on a link or a special file.
- `canary/watcher.py:_record` swallows `OSError` ("a failure to write it
  never stops a hold"). `canary/guestlist.py:record_events` raises it.
- `canary/guestlist.py:record_decision` writes a `checked` event and a
  `declined`, `refused` or `not_installed` event that carry the skill's name
  and nothing that identifies its content or its hold.
- `canary/guestlist.py:_state` ignores an event without a string `skill`
  and an event kind it does not know, so new event kinds and new keys do
  not change any skill's status, in this version or an older one.
- `canary/guestlist.py:scan` returns each hold as `{"id", "name",
  "origin", "since", "restore"}`. `render_text` prints the header
  `Held by SkillCanary (arrived without its check; nothing is deleted):`.
  `session_line` counts every hold as `held for your decision`.
- `canary/gate.py:decide` allows a plain `canary` command (`_is_canary`), so
  an agent can run `canary restore` today and `canary drop` after this
  program. Only the person's answer in SkillCanary's dialog acts.
- `canary/add.py:ask` returns `True` only for the yes button (and the typed
  name when `confirm` is given), `False` for Cancel and for the yes button
  with a name that does not match, and `None` for no screen, no
  `osascript`, a timeout or an error.
- `docs/architecture.md`, "The guest list", says the ledger is a report, not
  proof: a shell command or other software running as the person can change
  it.

Terms, each used with one meaning throughout:

- **Hold**: one slot `quarantine/held/<id>/` with its `hold.json` and its
  `entry`. The **held copy** is the `entry`.
- **Place**: the path the held copy came from (`origin` in `hold.json`). A
  place is **taken** when `os.path.lexists(origin)` is true, and **free**
  otherwise.
- **Fingerprint**: `guestlist.digest` of the held copy. It is fast and it
  is what the ledger stores, but it leaves out `.git` and stops at the size
  limits, so this program never deletes or installs on a fingerprint alone.
- **Exact copy**: two real folders (neither is a link) whose
  `add.tree_digest` values are equal. A `SourceError` or an `OSError` while
  reading either one means they are not an exact copy.
- **Approved**: `watcher._approved(path, support)` is true now, which means
  the ledger has the path as checked or yours and its content has not
  changed since.
- **Drop**: delete a held copy after writing a ledger record of it.
- **Put back**: move a held copy to its place after recording its approval.
- **Answer**: the person's yes or no in SkillCanary's dialog. Silence, a
  timeout and a missing screen are not an answer.
- **The sweep**: one pass over the holds that drops or puts back what the
  rules allow and never shows a dialog (section 1.2).

## 1. Slice 1: ask once, and give every hold a way to end

### 1.1 When the watcher asks

`Watcher._review_loop` becomes two public methods and a loop:

- `Watcher.begin()` runs one sweep. It puts no hold on the review queue.
- `Watcher.handle(item)` handles one queue item: the sweep sentinel
  `watcher.SWEEP`, or a hold id. It catches every exception, as the loop
  does today, so a failure leaves the hold held.
- `_review_loop` calls `begin()`, then `handle(self.reviews.get())` forever.

`Watcher.hold` is unchanged: it puts the new hold's id on the queue. So the
watcher asks about a hold once, when it makes the hold, and never at a
restart. A skill that arrives while the watcher is stopped is still held
and asked about when the watcher starts, because `Watcher.step` finds it
through `watcher-seen.json` and calls `hold`.

The cost: a hold whose question was lost is never asked about again
automatically. That happens when the watcher stops between the hold and the
dialog, or when nobody answers. The hold stays in `canary list` and in the
session-start notice, and `canary restore <id>` asks again.

`handle(hold id)` does these steps in order and stops at the first that
applies:

1. The hold is gone (`held` no longer lists it): nothing.
2. The held copy is a link: `Watcher.review`, which refuses a taken place
   first (section 1.3) and otherwise checks and asks as today. A link gets
   no automatic drop and no automatic put-back in either slice.
3. An older hold from the same place is an exact copy of this one: drop
   this one (`how: "same as waiting hold"`, section 1.4), notify, and stop.
   The older hold stays held and listed. The watcher asked about it when it
   made it, so it does not ask again. The notification: `SkillCanary deleted
   a second held copy of {name}: it is the same as the copy it is already
   holding. canary list shows where it is.` If the drop's ledger record
   fails, both holds stay and the watcher asks nothing.
4. The place is taken: apply the sweep's rule for a taken place (section
   1.2) to this hold. No question either way. If the hold stays, notify:
   `SkillCanary is holding {name}, which arrived in {folder} without its
   check. Its place is taken now, so SkillCanary did not ask about it.
   canary list shows where it is.`
5. `Watcher.review(hold id)`. After a put-back, run the sweep.

Step 3 keeps two holds from one place when their content differs. Dropping
either would delete the only copy of that content without the person's
answer. This is narrower than "one hold per place": it is one hold per
place and content.

### 1.2 The sweep

`Watcher.sweep()` runs only on the review thread, so two automatic actions
never run at once in one watcher. It runs in three situations:

- at start, from `begin()`;
- when `Watcher.step` leaves a new entry alone because it is approved
  (`step` puts `watcher.SWEEP` on the review queue), which covers installs
  by `canary add`, `canary install` and `canary restore`;
- after `handle` puts a hold back.

The sweep makes one pass over `held(self.support, self.roots)`, oldest
first, and skips a hold whose held copy is a link. For a hold whose place is
taken it applies one rule:

> Drop the hold when the place is a real folder, the place is approved, and
> the held copy is an exact copy of the folder at the place. Record `how:
> "same as installed"` and `same_as`: the place.

Any other hold whose place is taken stays held and listed. In slice 1 the
sweep does nothing for a hold whose place is free.

The way back for a hold dropped by this rule is the installed folder, which
held the same bytes when the sweep compared them. The comparison and the
drop are not one atomic step: a change to the installed folder after the
comparison is reported by the guest list as `changed since approval`.

The sweep also removes a slot that holds a `dropped` entry and no `entry`,
which a drop leaves behind when it stops between its rename and its
removal (section 1.4).

A sweep that dropped something sends one notification: `SkillCanary deleted
{n} held copy that matches a skill you already installed: {names}. canary
list shows what is still held.` (`copies` and `skills` when n is not one).
A sweep that changes nothing does nothing else. An error on one hold is
caught and the pass goes on with the next hold.

### 1.3 `canary restore` when the place is taken

`Watcher.review` returns `(False, STILL_TAKEN)` when the hold's place is
taken, before it copies, checks or asks. `canary restore <id>` uses
`review`, so it prints the unchanged `STILL_TAKEN` line and exits 10
without a dialog. `put_back` keeps its own test, for a place that is taken
while the person decides. No `STILL_*` sentence changes.

### 1.4 The drop, step by step

One function, `watcher._drop_hold(support, h, how, same_as=None)`, does
every drop: the person's, the sweep's and step 3's.

1. Build the record: `{"at", "event": "dropped", "id", "name", "origin",
   "digest", "how"}` plus `same_as` when given. `digest` is the held copy's
   fingerprint, or `null` when the held copy is a link or cannot be read.
2. `guestlist.record_events(support, [record])`. An `OSError` propagates and
   nothing is removed. The drop must not use `watcher._record`, which
   swallows the error.
3. `os.rename(<slot>/entry, <slot>/dropped)`. This is the commit point.
   `held` stops listing the hold, and `put_back`'s own rename of `entry`
   now fails, so exactly one of a drop and a put-back wins. If the rename
   fails, append `{"at", "event": "drop_failed", "id"}` through
   `watcher._record` and return false: the hold stays.
4. `shutil.rmtree(<slot>, ignore_errors=True)`. A held link is removed as a
   link; its target is never touched.

A stop between steps 2 and 3 leaves a `dropped` record for a hold that is
still held and listed; nothing was deleted, and a later drop writes a
second record. A stop between steps 3 and 4 leaves a slot the next sweep
removes.

No Trash and no kept store. A held copy has not passed its check, and a
copy moved outside the quarantine would be readable by agents, which the
quarantine exists to prevent.

### 1.5 `canary drop <held-id>`

`watcher.drop(held_id, home=None, support=None, ask=None)` returns
`(dropped, line)`, and `cli._drop(args)` mirrors `cli._restore`.

- An id that `held` does not list and that is a replaced group's id raises
  `ValueError(NOT_A_HOLD.format(id=held_id))`. Any other unknown id raises
  `ValueError(replace.NOT_KEEPING)`. `cli._drop` prints `canary: <message>`
  and exits 2, as `cli._restore` does.
- It asks the person. The default `ask` is `lambda text, verdict:
  add.ask(text, verdict, yes="Delete")`, called with `"NEEDS_REVIEW"`, the
  shape `guestlist.trust` uses for "Mark as mine". The dialog text is in
  section 3.
- Yes: `_drop_hold(support, h, "person")`, then `(True, DROPPED)`, exit 0.
  A failed rename returns `(False, STILL_GONE)` when the held copy is no
  longer there and `(False, STILL_NOT_DROPPED)` otherwise, exit 10.
- No: `(False, STILL_KEPT)`, exit 10. Silence or no dialog:
  `(False, STILL_SILENT)`, exit 10.
- A ledger failure: `cli._drop` prints `canary: <strerror>; it stays held.`
  and exits 1.

An agent can run the command. Only the person's yes in the dialog deletes.
The person's drop has a record and the person's answer but no way back
other than installing the skill again from where it came; the dialog says
so.

### 1.6 Where a hold shows

`guestlist.scan` adds `drop` (`canary drop <id>`) and `taken` (true or
false) to each hold. `render_text` prints:

```
Held by SkillCanary (arrived without its check):
  <name>  from <place>  held since <YYYY-MM-DD>  (its place is taken)
    to check it again and install it: canary restore <id>
    to delete the held copy: canary drop <id>
```

`held since` is `at[:10]` and is left out when `hold.json` has no `at`.
`(its place is taken)` and the `canary restore` line appear only when they
apply: a taken place has the note and no restore line. `session_line` is
unchanged in slice 1 and counts every hold.

## 2. Slice 2: one answer covers every exact copy

### 2.1 What the dialog says

`watcher.dialog_text` replaces its `Install puts it back…` line with the
two lines in section 3. They tell the person that the answer covers every
copy with exactly the same content, now and later. Only answers given in
this dialog are remembered, because only this dialog says so.

### 2.2 A remembered yes

`guestlist.record_install` gains `covers=None`; with `covers="content"`
each `approved` event carries `"covers": "content"`. `Watcher.put_back`
passes it. `guestlist._state` carries `covers` into the skill's state, and
a later `approved` event without it removes it.

A held copy is put back without a question only when all of these hold:

1. the held copy is a real folder and its place is free;
2. some path P in the ledger has status checked with `covers`, and P's
   approved fingerprint equals the held copy's fingerprint (a fast filter,
   through the new `guestlist.covering(events, fingerprint)`);
3. P is directly in a watched folder and is approved now;
4. the held copy is an exact copy of P.

So nothing reaches a skills folder this way unless the same bytes are
already installed, approved and unchanged in another one.

The put-back writes, in this order:

1. through `guestlist.record_events`, an `approved` event for the place:
   `{"at", "event": "approved", "how": "watcher", "name", "skill":
   os.path.realpath(origin), "digest": <P's approved fingerprint>,
   "covers": "content", "origin": {"kind": "watcher", "same_as": P}}`, plus
   `"override": true` when P has it. No `checked` event, because no check
   ran. An `OSError` stops here: nothing moves and the hold stays.
2. `os.rename(entry, origin)`. An `OSError` leaves the hold held, with an
   approval for a path that is not there, which the next scan records as
   removed. `put_back` has the same order and the same result today.
3. `shutil.rmtree(<slot>, ignore_errors=True)` and, through
   `watcher._record`, `{"at", "event": "restored", "id", "replay": true}`.

Then it notifies: `SkillCanary put {name} back in {folder}: it has the same
content as a skill you chose to install.` The skill lists as `installed
anyway` when P does, and as `restored`.

Decision (owner decision 2): an approval without `covers` is not a
remembered yes. That is every approval from `canary add` and `canary
install`, and every approval made before this version. The cost is one more
question when content approved that way arrives in another folder. A skill
with status yours is never a remembered yes.

### 2.3 A remembered no

`guestlist.record_decision` gains `digest=None` and `id=None` and writes
them on the `declined` or `refused` event. `Watcher.review` passes the
checked copy's fingerprint and the hold's id only when the person answered
no (`answer is False`) and the held copy is not a link. An unsafe verdict
with no answer still records `refused`, as today, but with no `digest`, so
silence is never remembered.

For an unsafe verdict the dialog asks the person to type the folder name.
`add.ask` returns `False` both for Cancel and for the yes button with a name
that does not match, so the watcher cannot tell the two apart; today
`Watcher.review` reports both as `STILL_CANCELLED`. Decision: both are a
remembered no. The cost is that a mistyped name is remembered as a no for
every copy of that content. To make that visible, after `False` on an
unsafe verdict the watcher notifies: `SkillCanary did not install {name}:
the dialog was cancelled, or the folder name was not typed exactly. It
stays held. canary restore {id} asks again.` A yes there ends the
remembered no. Telling the two apart needs a change to `add.ask`, which the
check also uses; that change is cut from this program (section 10).

`guestlist.refused(events, fingerprint)` is true when the latest event that
carries that `digest`, among `approved`, `declined` and `refused`, is a
`declined` or a `refused`. A later approval of the same content ends the
refusal, whichever command gave it.

A hold whose fingerprint is refused stays held with no check and no dialog.
The watcher writes, through `watcher._record`, `{"at", "event": <the kind
of the remembered event>, "name", "id", "digest", "replay": true}` once per
hold, and notifies once per content per run: `SkillCanary is holding
{name}, which arrived in {folder}: it has the same content as a skill you
chose not to install. canary list shows where it is.`

The fingerprint is enough here because a wrong match only withholds a
question; it never installs or deletes. `canary restore <id>` always checks
and asks again, and a yes there is a later approval.

### 2.4 The order in `handle` and in the sweep

`Watcher` gains `asked`, a set of fingerprints it has asked about in this
run. `handle(hold id)` keeps steps 1 to 4 of section 1.1 and replaces step
5 with:

5. The fingerprint is refused (2.3): the hold stays, with no question.
6. A remembered yes applies (2.2): put the hold back, then run the sweep.
7. The fingerprint is in `asked`: the hold stays, with no question, and one
   notification per content per run: `SkillCanary is holding {name}, which
   arrived in {folder}: it has the same content as a skill it already asked
   you about. canary list shows where it is.`
8. Add the fingerprint to `asked`, then `Watcher.review(hold id)`. After a
   put-back, run the sweep.

A fingerprint that cannot be read skips steps 5 to 7.

The sweep, for a hold whose place is free, applies steps 5 and 6 and
nothing else: it never asks. Holds are taken oldest first, so a hold that
becomes droppable because the same pass put an older hold back at its place
is dropped later in that pass.

Three copies that arrive together get one question. `handle` asks about
the first. On a yes, `put_back` records the covering approval and the
sweep puts the other two back as exact copies. On a no, step 5 keeps the
other two held. On silence, step 7 keeps them held.

### 2.5 What stops a remembered yes from approving changed content

- The exact-copy test. A difference anywhere, including under `.git` and
  past the fingerprint's size limits, or any read error, means the hold is
  checked and asked about.
- The installed copy must be approved at that moment. Changing it or
  removing it ends the memory. Removing every installed copy of a skill is
  how the person takes a remembered yes back.
- The comparison and the rename are not one atomic step. `put_back` has the
  same gap today between its fingerprint comparison and its rename. The held
  copy sits in the quarantine, which the hook keeps agents out of, and a
  change after the move is reported as `changed since approval`.
- The watcher does not look at a put-back copy again: `Watcher.step` sees a
  name as new only when it was absent at an earlier look, and it leaves an
  approved entry alone. The three points above are the whole defence.

A remembered yes trusts the ledger exactly as much as `Watcher.step` does
today: `step` already leaves alone any entry the ledger approves. This
program adds no new trust in the ledger.

### 2.6 Where a refused hold shows

Decision (owner decision 3): `guestlist.scan` marks a hold `refused` when
the ledger has a `declined` or `refused` event with that hold's `id` and a
`digest`, and that fingerprint is still refused. `render_text` adds `(you
chose not to install it)` to its line. `session_line` counts only the holds
that are not refused, so a refused hold is in `canary list` and not in the
session-start notice. The reminder in every session is given up for holds
the person has already answered.

## 3. Sentences, exact

New constants in `canary/watcher.py`, beside the `STILL_*` lines:

- `STILL_KEPT = "Still held: you chose not to delete it." + SUFFIX`
- `STILL_NOT_DROPPED = "Still held: SkillCanary could not delete it." + SUFFIX`
- `DROPPED = "Deleted the held copy of {name}."`
- `NOT_A_HOLD = "canary drop deletes a held skill only; canary restore {id} puts a replaced copy back."`

The `canary drop` dialog (`watcher.drop_text(h, home)`):

```
Delete the held copy of this skill?

Folder name: <name>
Arrived in <folder> on <YYYY-MM-DD>.
<Another copy is in its place now. | Its place is free.>

Delete removes the copy SkillCanary is holding. This cannot be undone: to
get it back, install the skill again from where it came. Nothing in your
skills folders changes.
Cancel keeps it held.
The folder name comes from whoever put it there, not from SkillCanary.
```

The held-skill dialog (`watcher.dialog_text`). Slice 1 replaces `Install
puts it back where it was. Cancel keeps it held; nothing is deleted.` with
the first line; slice 2 adds the second:

```
Install puts it back where it was. Cancel keeps it held and deletes nothing.
Your answer covers every copy with exactly the same content that arrives in your skills folders, now or later: SkillCanary will not ask about it again.
```

The notifications are quoted where they are used (1.1, 1.2, 2.2, 2.3, 2.4). The
list lines are in 1.6 and 2.6.

## 4. The eight holds already on this Mac

`canary list` on 2026-11-15 showed eight holds. Each one's place is taken
by another copy of the skill, which the watcher put back afterwards and
recorded as approved. For six of the eight, that other copy arrived before
the held one.

| Hold id | Skill | Place | Arrived |
|---|---|---|---|
| `20261007T003205Z-ec791cb3` | hyperframes-cli | `~/.agents/skills` | 2026-10-07 |
| `20261010T053330Z-ceb38961` | hyperframes-cli | `~/.claude/skills` | 2026-10-10 |
| `20261010T053330Z-3a6bbc5c` | media-use | `~/.claude/skills` | 2026-10-10 |
| `20261010T053331Z-c4408326` | media-use | `~/.agents/skills` | 2026-10-10 |
| `20261013T065006Z-684a17d3` | make-ugc | `~/.claude/skills` | 2026-10-13 |
| `20261013T070644Z-3c9cc233` | treg | `~/.agents/skills` | 2026-10-13 |
| `20261013T070644Z-99c2baec` | treg | `~/.claude/skills` | 2026-10-13 |
| `20261013T070644Z-e9e2403b` | treg | `~/.codex/skills` | 2026-10-13 |

There is no migration code. When the new version's watcher starts,
`begin()` runs the sweep:

- A hold whose held copy is an exact copy of the approved folder at its
  place is dropped, with a `dropped` record and no question.
- Every other hold stays. `canary list` shows it with `(its place is
  taken)` and its `canary drop` command. The watcher does not ask about it,
  at this start or any later one. `canary restore <id>` refuses it with
  `STILL_TAKEN` and no dialog. The person ends it with `canary drop <id>`,
  one dialog per hold.

Not established: how many of the eight are exact copies of the installed
folder. The hook refuses an agent that reads the quarantine, so I did not
compare them. The two installed copies of hyperframes-cli differ from each
other, so each held copy can match only the folder at its own place.

The refusals already in the ledger for these holds carry no `id` and no
`digest`, so slice 2 does not mark any of the eight as refused. Each one
that the sweep keeps is counted in the session-start notice until the
person drops it.

## 5. Failure behaviour

This is fail-closed code: on any error the hold stays held and listed, and
nothing is installed. Every path:

| What fails | What happens | Where |
|---|---|---|
| A held copy or an installed folder cannot be read, or holds a link or a special file | It is not an exact copy: no automatic drop and no automatic put-back | Terms; 1.2, 2.2 |
| The ledger write before an automatic drop | Nothing is removed; the hold stays; the sweep goes on with the next hold | 1.4 step 2 |
| The ledger write before the person's drop | Nothing is removed; `canary drop` exits 1 with `it stays held` | 1.5 |
| The rename that commits a drop | A `drop_failed` event when it can be written; the hold stays, or `STILL_GONE` when a put-back won | 1.4 step 3 |
| The removal after the rename, or a stop between them | The slot keeps a `dropped` entry and is not listed; the next sweep removes it | 1.2, 1.4 |
| A stop between the record and the rename | A `dropped` record for a hold that is still held and listed; nothing was deleted | 1.4 |
| The dialog cannot show, times out or is closed | No answer: nothing is deleted and nothing is put back | 1.5 |
| The person presses the yes button with a folder name that does not match | Nothing is installed; it is recorded as a no and, in slice 2, remembered; a notification says so and names `canary restore` | 2.3 |
| An exception anywhere in `handle` | Caught; the hold stays held and listed | 1.1 |
| The watcher stops before it asks | The hold is not asked about again automatically; it is listed and counted in the notice | 1.1 |
| The place is taken | No check and no question; `STILL_TAKEN` from `canary restore` | 1.3 |
| An unknown id, or a replaced group's id, given to `canary drop` | Exit 2 with a sentence; nothing changes | 1.5 |
| The ledger cannot be read when the watcher looks for a remembered answer | No remembered answer: the hold is checked and asked about | 2.2, 2.3 |
| The approval record before an automatic put-back | Nothing moves; the hold stays | 2.2 step 1 |
| The rename of an automatic put-back | The hold stays; the approval names a path that is not there, and the next scan records it as removed (as `put_back` today) | 2.2 step 2 |
| The record of a no | The no is not remembered in a later run; `asked` stops a second question in this run | 2.3, 2.4 |
| The record that marks a hold as refused | The hold stays held; it is not marked and is counted in the notice | 2.3, 2.6 |
| The installed copy changed or was removed | No remembered yes: the hold is checked and asked about | 2.5 |
| Two contents share a fingerprint | Installs and deletions are decided by the exact-copy test; a refusal match only withholds a question | 2.3, 2.5 |

Nothing is deleted without a record written first. A copy the sweep or
`handle` drops also has a way back: the installed folder or the older hold
it was an exact copy of. A copy the person drops has a record and the
person's answer in a dialog that says it cannot be undone.

## 6. Interfaces, docs first

The builder edits the documents in 6.3 before the code of each slice.

### 6.1 CLI and `USAGE` (`canary/cli.py`)

Slice 1 adds the line `canary drop <held-id>` to `USAGE` after the `canary
restore` line, `cli._drop`, and the `drop` branch in the command dispatch
beside `restore`. `canary/gate.py` does not change. `frontdoor.SKILL_TEXT`
and `plugins/codex/skills/canary/SKILL.md` do not change.

### 6.2 JSON and ledger fields

- `canary list --json`, each entry of `held`: slice 1 adds `"drop"` and
  `"taken"`; slice 2 adds `"refused"`. The schema name stays
  `canary.list/1`; the fields are additions.
- Ledger, slice 1: `dropped` and `drop_failed` (1.4).
- Ledger, slice 2: `covers` and `origin.same_as` on `approved` (2.2);
  `digest`, `id` and `replay` on `declined` and `refused` (2.3); `replay`
  on `restored` (2.2).

### 6.3 Text that promises "nothing is deleted"

| Where | Today | After |
|---|---|---|
| `canary/watcher.py`, module docstring | "Nothing is deleted." | The watcher deletes a held copy only when the same content is installed and approved at its place, or when the person says so with `canary drop`; each deletion is recorded first. |
| `canary/watcher.py:Watcher._review_loop`, comment | "the next restart asks again" | A held skill stays held; `canary list` shows it. |
| `canary/watcher.py:dialog_text` | "Cancel keeps it held; nothing is deleted." | Section 3 |
| `canary/guestlist.py:render_text` | `Held by SkillCanary (arrived without its check; nothing is deleted):` | Section 1.6 |
| `tests/test_watcher.py`, module docstring | "Nothing is deleted." | As the watcher docstring |
| `README.md`, the unsafe-verdict paragraph | "Cancel deletes nothing: a held skill stays held, and `canary list` shows how to restore it." | Keep it, and add: `canary drop <id>` deletes a held copy you do not want. Slice 2 adds: your answer covers every copy with exactly the same content. |
| `docs/architecture.md`, the watcher section, the paragraph that begins "Nothing is deleted." | As quoted | The text below |

Unchanged, and still true: `canary/replace.py` ("Nothing here deletes an
entry", "Cancel keeps it set aside; nothing is deleted"), the `Set aside by
a replace (nothing is deleted):` header in `render_text`, and the replace
paragraph in `docs/architecture.md`.

`docs/architecture.md`, the watcher section. The heading gains `canary drop
<id>`. Step 3's sentence about the question gains "once, when it makes the
hold". The paragraph that begins "Nothing is deleted." becomes, in slice 1:

> A hold ends in one of three ways. The person's yes puts it back. The
> watcher deletes it without asking when its place holds an approved folder
> with exactly the same bytes, or when an older hold from the same place has
> exactly the same bytes. `canary drop <id>` deletes it after the person
> says so in SkillCanary's dialog. Every deletion writes a `dropped` event
> first, and a failed write deletes nothing. The watcher asks about a hold
> once, when it makes it, and never at a restart. What is held comes from
> the quarantine folder itself, not the ledger, and a hold whose origin is
> not directly in a watched folder is ignored. `canary list` shows what is
> held, where it came from, since when, whether its place is taken, and the
> `canary restore <id>` and `canary drop <id>` commands: an agent can run
> either, but only the person's answer acts. `canary restore` refuses a hold
> whose place is taken before it checks or asks. The session-start notice
> counts held skills.

The rest of that paragraph, from "What it never holds", is unchanged. Slice
2 adds after it:

> The person's answer in the held-skill dialog covers every copy with
> exactly the same content. After a yes, a later copy is put back without a
> question when it is byte for byte the same as a folder that this dialog
> approved and that is still installed and unchanged. After a no, a later
> copy with the same fingerprint stays held without a question, `canary
> list` says the person chose not to install it, and the session-start
> notice no longer counts it. Approvals from `canary add` and `canary
> install` are not remembered this way.

`docs/architecture.md`, the guest list section: the event list gains
`dropped` and `drop_failed` (slice 1) and the slice 2 fields in 6.2; the
`canary list --json` bullet gains the `held` entry with its fields.

## 7. Tests, red first

Each test names the seam it uses to inject a fault. New tests live in
`tests/test_watcher.py` and reuse its `Mac` and `skill` helpers. Each slice
adds three behavioural scenarios, at the public boundaries `Watcher.begin`,
`Watcher.handle`, `watcher.drop`, `cli._drop`, `guestlist.scan`,
`guestlist.render_text` and `guestlist.session_line`.

Tests 2 and 3 of slice 1 each carry several cases of one behaviour: when a
held copy may be deleted. Each case is a distinct way to delete the wrong
copy or to delete without a record, which is this program's main risk. An
auditor who counts cases and not scenarios finds more than three in slice
1; that risk is the justification `TESTING.md` asks for.

### Slice 1

1. **A restart asks nothing and the hold still shows.** Hold a skill with
   `Mac(answer=None)` and handle it. Start a second `Mac(home=mac.home)`,
   call `begin()` and handle whatever is on its queue. The second watcher
   asked no question; `render_text` shows the hold with both command lines;
   `session_line` counts it. No seam.
2. **Automatic drops delete exact copies only, record first.** (a) A hold
   whose place holds an approved exact copy is dropped at `begin()`, with a
   `dropped` event (`how: "same as installed"`). (b) A hold whose installed
   copy differs only in a file under `.git` (same fingerprint, not an exact
   copy) stays. (c) A second hold from one place that is an exact copy of
   the first is dropped by `handle` (`how: "same as waiting hold"`), the
   first stays, and the watcher asks no second question about it; a second
   hold with different content is kept. (d) With
   `guestlist.record_events` patched to raise `OSError`, case (a) drops
   nothing. Seam: `mock.patch` on `guestlist.record_events`.
3. **`canary drop` deletes only on the person's yes.** `watcher.drop` with
   an injected `ask`, the seam `watcher.restore` already has. No: the hold
   stays, `STILL_KEPT`. Ledger fault (the ledger path made a directory, as
   `test_holds_survive_a_broken_ledger` does): `OSError`, nothing removed.
   Yes: the hold is gone, the ledger has `dropped` with `how: "person"`,
   `canary list` no longer shows it. `cli._drop` is called once with
   `watcher.drop` patched, as
   `test_canary_restore_prints_the_reason_or_the_success_line` does, for
   the printed line and exit codes 0, 10, 2 and 1.

Existing test changed on purpose: `test_every_restore_failure_says_why`
gains a case where the place is taken before `review` runs and asserts that
no question was asked. It is red at the base because the dialog is asked.
The `STILL_*` pins stay green because no sentence changes.

### Slice 2

1. **One answer covers every copy.** The same content arrives in three
   folders with an unsafe verdict and `Mac(answer=True)`. Handling the
   queue asks one question, with the typed name; the dialog text carries
   the covering sentence; all three are back and list as `installed
   anyway`. No seam.
2. **A no is remembered.** `Mac(answer=False)`; a skill arrives and is
   refused; the same content arrives in another folder. No second question;
   it stays held; `render_text` says the person chose not to install it;
   `session_line` does not count either hold. `watcher.restore` on the
   second hold asks again.
3. **Changed content and older approvals are asked about.** After a
   covering yes: a copy with one changed byte, and a copy that differs only
   under `.git`, are each asked about. Content approved through
   `guestlist.record_install` without `covers` (as `canary add` records it)
   and arriving elsewhere is asked about. After the approved copy is
   removed, the same content is asked about.

Existing test changed on purpose:
`test_cancel_keeps_it_held_and_canary_list_says_how_to_restore` asserts
`held for your decision` after a cancel. It changes to assert the list note
and that `session_line` does not count the refused hold.

## 8. Done when

Logs live in `docs/proof/2026-11-15-quiet-holds/slice-1/` and `slice-2/`. A
log is stamped when its first line is `commit <full sha>` and its second
the interpreter's `--version`. The list is the same for each slice, with
the slice's own tests and counterfactuals:

1. `red.log`: every new test of the slice, and each changed existing test,
   fails at the slice's start commit with the tests applied, on an
   assertion or on the missing interface (`TypeError`, `AttributeError`).
   A pin that cannot be red is listed as a pin.
2. `gate-python3.10.log` and `gate-usr-bin-python3.log`: the full gate
   passes at the slice's final commit on both interpreters, stamped.
3. Counterfactuals, full suite, each in `counterfactual-<letter>.log`
   naming the reverted line and the tests that went red; other reds listed
   and explained. Known collateral, recorded by the 2026-10-17 program: any
   edit under `canary/` turns the `tests/test_action.py` `CanaryActionTests`
   cases red through the integrity check of `scanner/manifest.json`
   (`scripts/action.py`); the builder re-verifies the count and the
   mechanism in the first log.
   Slice 1, at least:
   a. `_review_loop` queues every hold at start again → test 1;
   b. `same_tree` compares fingerprints instead of `add.tree_digest` →
      test 2 (b);
   c. the same-place rule in `handle` is removed → test 2 (c);
   d. `_drop_hold` renames before it records, or writes its record through
      `watcher._record` → test 2 (d) and test 3's ledger fault;
   e. `watcher.drop` ignores the answer → test 3;
   f. `review`'s test for a taken place is removed → the changed case in
      `test_every_restore_failure_says_why`.
   Slice 2, at least:
   g. a remembered yes no longer needs `covers` → test 3;
   h. a remembered yes compares fingerprints only → test 3 (the `.git`
      copy);
   i. a remembered yes no longer needs the installed copy to be approved →
      test 3 (the removed copy);
   j. the remembered no is removed from `handle` → test 2;
   k. `session_line` counts refused holds → test 2;
   l. `Watcher.asked` is removed → test 1 with `Mac(answer=None)` asks
      three times; the builder adds that assertion to test 1.
4. A Sol pre-merge review (`~/workspace/scripts/premerge-review`) on the
   slice's diff before the full gate, findings folded or answered in
   section 9.
5. The done-when audit (milestone-auditor through the `done-when-audit`
   skill; fallback an Opus read-only reviewer with the same prompt) returns
   SHOWN for bullets 1 to 3.
6. Merge to `main` and push. No version bump and no tag: the release is the
   owner's step.

One owner check sits outside bullets 1 to 6 and does not gate the merge,
because it needs the new version installed, which is the owner's release
step. After that install, the owner saves the output of `canary list`
before and after the new watcher's first start on this Mac in
`slice-1/this-mac.log`. That start may delete held copies, so an agent does
not run it without the owner's go-ahead.

Process: this document is refuted through `refute-plan` by Spark 1.3
Contributor at `max` (the owner's choice, 2026-11-15) before any code; findings are folded into
sections 1 to 7 and answered in section 9.

## 9. Where each refutation finding is answered

Empty until the refutation runs.

## 10. Scope cuts, in one place

- A remembered answer is keyed by content only, not by folder name or host.
- Only answers in the held-skill dialog are remembered (owner decision 2).
- A hold whose held copy is a link, and a place that is a link, get no
  automatic action. `canary restore` and `canary drop` still work.
- Holds from different places are never dropped as duplicates of each
  other; each place keeps its own hold until a rule ends it.
- `canary drop` takes one hold id. It does not take a replaced group's id,
  it has no undo, and there is no command that drops several holds at once.
- Nothing prunes old holds by age.
- No change to `canary/gate.py`, to the check, or to `frontdoor.SKILL_TEXT`.
- `add.ask` is unchanged, so Cancel and a mistyped folder name stay
  indistinguishable (section 2.3).
- No version bump, changelog entry or release.

## 11. Later

The 2026-11-15 review (`docs/review-2026-11-15-keep-or-scrap.md`) proposed
three more changes. Each needs its own program document:

- Record what the hook stops, and show the person a total, so the hook's
  value can be measured.
- Check a changed skill in the background instead of only reporting
  `changed since approval`.
- Put plugins and MCP servers on the guest list.
