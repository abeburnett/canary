# Program 2026-10-13: the person can install an unsafe skill anyway

Status: requested by the owner on 2026-10-13. Branch
`program/2026-10-13-unsafe-override`, based on `main` at `ad777cc`
(version 0.1.2). Gate: `python3 -m unittest discover -s tests`.

## Why

The owner tried to restore the skill `treg` eight times on 2026-10-13. Each
`canary restore` re-checked it, got `UNSAFE`, logged `refused` and printed
"Still held; canary list shows where." It showed no dialog and gave no
reason. He understands why treg is flagged and judges it fine, and
SkillCanary has no way to let him install it. In his words: "after they've
been advised, still approve it for installation."

## Owner decisions (2026-10-13, asked in session)

1. **Override by typing the name.** An unsafe verdict still recommends
   declining, and Cancel stays the default button. To install anyway, the
   person types the skill's name into the dialog. One click cannot
   override; the owner said on 2026-10-12 that he clicks yes by reflex.
2. **The watcher asks right away.** When the watcher holds a skill it judges
   unsafe, it shows the override dialog at once, as it already does for a
   needs-review skill. It no longer sends a notification without a question.
3. **Every flow gets the override:** `canary add`, `canary install` (skills
   and plugins), the watcher, and `canary restore`.

## Current behavior (verified at `ad777cc`)

An `UNSAFE` verdict never reaches a dialog:

- `canary/add.py:642-645`: outcome `refused`, reason "Not installed:
  SkillCanary judged it unsafe.", ledger `refused`, exit 20.
- `canary/install.py:337-340` (skills): outcome `refused`, reason "…judged
  part of it unsafe.", returned before the conflict check and the dialog.
- `canary/install.py:507-510` (plugins): the same.
- `canary/watcher.py:294-299` (`Watcher.review`, also used by `canary
  restore`): ledger `refused`, a notification, return `False`. The same
  branch handles a held entry that could not be copied (links or special
  files, `watcher.py:290-293`).
- `canary/cli.py` `_restore`: prints "Still held; canary list shows where."
  and exits 10 for every failure, with no reason.
- `add.ask(text, verdict, yes=None)` (`add.py:551`): a `review` dialog has
  Cancel as its default button and returns `True` only when the yes button
  is clicked. It has no text field.

Tests that pin the old behavior and change on purpose:
`tests/test_add.py` `test_unsafe_is_refused_without_asking`,
`tests/test_install.py` `test_an_unsafe_skill_is_refused_without_asking`,
`tests/test_watcher.py` `test_an_unsafe_skill_stays_held_without_a_question`.

## Design

### 1. The override dialog

- `add.ask` gains a keyword `confirm=None`. With `confirm` set (a string),
  the dialog is the `review` kind with a stop icon, plus a text field
  (`default answer ""`). The yes button is `Install anyway`. The AppleScript
  returns the button and the typed text; `ask` returns `True` only when the
  yes button was clicked **and** the typed text, stripped of surrounding
  whitespace and compared case-insensitively, equals `confirm`. If the yes
  button is clicked with other text, it returns `False` (a decline). Cancel
  returns `False`; no dialog, a timeout, or an error returns `None`, as now.
  Without `confirm`, `ask` behaves exactly as it does today.
- The text the person must type is the skill's name for `canary add` and
  the watcher, the plugin id (`name@marketplace`) for a plugin, and for a
  `canary install` with several skills, the name of the one unsafe skill.
  When more than one skill is unsafe, it is the phrase `install <n> unsafe
  skills`, where `<n>` is their number.
- The dialog text keeps everything the current dialogs show (the
  recommendation, which reads "decline" for `UNSAFE`; the headline; the
  risks and quoted lines within owner decision 2 of program 2026-10-12; what
  it can do; the labelled source and names). It ends with, exactly:
  `SkillCanary recommends you don't install this. To install it anyway, type
  <phrase> below and choose Install anyway.` For a multi-skill install, the
  unsafe skills are marked `  (judged unsafe)` in the list, where needs-review
  skills show `  (needs your judgment)`.
- An injected `approve` (tests) receives the same summary or item list plus
  `"confirm": <phrase>`; the flow treats only `True` as approval, as now.

### 2. The flows

- **`canary add`.** On `UNSAFE`, the flow no longer returns early. It runs
  the same conflict and writability checks, then asks with `confirm=name`.
  On `True` it installs exactly as for an approved skill. On anything else
  the outcome is `refused` (exit 20), with the existing reason "Not
  installed: SkillCanary judged it unsafe." and, for a cancel, "You chose
  not to install it anyway." or, for no answer, "Nobody answered the
  SkillCanary dialog."
- **`canary install` (skills and plugins).** The same: no early return; the
  existing single dialog asks with the confirm phrase; `refused` (exit 20)
  unless the person types it. One answer covers the whole install, as now.
- **Watcher and `canary restore`.** On `UNSAFE` with a checked copy, `review`
  asks with `confirm=h["name"]` and puts the skill back on `True`, through
  the existing `put_back` (which still requires the held entry to match the
  checked copy). The entry that could not be copied (links or special
  files) stays as it is: refused, notification, no question, because there
  is no checked copy to put back.
- **The result says it was overridden.** On an override, add and install
  results gain `"overridden": true`, keep `"verdict": "UNSAFE"` and outcome
  `installed` (exit 0). The lockfile record gets `"overridden": true`.

### 3. The record

- `guestlist.record_install` gains `override=False`. With `True`, each
  `approved` event carries `"override": true`, and the `checked` event keeps
  `verdict: UNSAFE`.
- `canary list` shows such a skill with the status `installed anyway` (the
  `changed since approval` status still wins when its contents change). JSON
  `canary list --json` carries `"status": "installed_anyway"`.
- `canary restore` says why a skill stays held. `Watcher.review` returns a
  reason the CLI prints instead of the bare "Still held" line, exactly one of:
  - `Still held: you chose not to install it.` (Cancel, or wrong text typed)
  - `Still held: nobody answered the SkillCanary dialog.` (no dialog or timeout)
  - `Still held: it holds links or special files SkillCanary will not copy.`
  - `Still held: it changed after its check.`
  - `Still held: something else is in its place now.`
  - `Still held: SkillCanary could not move it back.`
  Each ends with ` canary list shows where it is.` Exit code stays 10.

### 4. Agent-facing text

`frontdoor.SKILL_TEXT` and `skills/canary/SKILL.md` (kept identical by an
existing test) say: on `refused`, tell the person SkillCanary judged it
unsafe and they chose not to install it anyway, or did not answer; never
suggest a way around the dialog. On `installed` with `overridden`, say the
person installed it despite an unsafe verdict.

### 5. Documentation

`README.md` (lines 39-40), `docs/architecture.md` (lines 485, 532, 735, 860
and the result schema at 540-541) and the watcher section describe the
override, the typed name, and the record. `docs/architecture.md` states the
limit: anyone at the Mac's keyboard can type the name; SkillCanary records
the override but cannot judge it.

## Refutation round 1 rulings (Spark 1.3 Contributor, 2026-10-13)

These rulings are senior to the design text above wherever they differ.

1. **Restore outcome type.** `Watcher.review(held_id)` returns `(back,
   reason)`: `(True, None)` when the skill went back, else `(False,
   "<reason line>")`. `watcher.restore` returns the same tuple.
   `cli._restore` prints `Put back where it was.` and exits 0 on success, or
   prints the reason line and exits 10. `Watcher._review_loop` ignores the
   return as now. `put_back` returns `(back, reason)` as well and still
   sends its notifications only when `self.notify` is the daemon's (the CLI
   path passes a `notify` that does nothing, so restore prints but does not
   also notify). Reason lines cover every restore failure, whatever the
   verdict, including the `h is None` race (`Still held: SkillCanary is no
   longer holding it.`).
2. **The watcher's question.** `review` calls `self.ask(text, verdict,
   confirm=h["name"])` for `UNSAFE` and `self.ask(text, verdict)` otherwise.
   Every test double of `ask` (`tests/test_watcher.py`, and any other) gains
   `confirm=None`.
3. **The record reaches `canary list`.** The stored status stays `CHECKED`,
   so `watcher._approved` still recognizes overridden installs and never
   re-holds them. `_state` carries an `override` boolean from the latest
   `approved` event to `scan()`; `render_text` shows `installed anyway`
   instead of `checked` for it; JSON carries `"override": true` beside
   `"status": "checked"` (not a new status value).
4. **Architecture line 523** ("There is no `--yes`, environment override or
   typed confirmation: an agent can type into a terminal") is rewritten:
   there is still no `--yes`, environment override or terminal prompt,
   because an agent can type into a terminal; the only typed confirmation is
   in the dialog, which an agent cannot reach. The other doc anchors are
   `architecture.md` 485, 523, 736 and 861 and the result schema at 540-541.
5. **Every `record_install` call site passes `override=(verdict ==
   "UNSAFE")`:** `watcher.py` `put_back`, `add.py` (the install commit),
   `install.py` skills (per item, its own verdict) and plugins.
6. **The real path threads `confirm`.** Build order: `add.ask` and
   `DIALOG_SCRIPT` first; then `add.macos_dialog(summary)` passes
   `confirm=summary.get("confirm")`; `install._ask(approve, command, items,
   verdict, confirm=None)` passes it to `add.ask` or includes it in the
   injected approver's dict; `install.dialog_text` marks `UNSAFE` items
   `  (judged unsafe)`; the closing sentence goes into `add.dialog_text`,
   `install.dialog_text` and `watcher.dialog_text` whenever the verdict is
   `UNSAFE`.
7. **Tests granted ownership** (expected outcome only, never weakened):
   `tests/test_add.py` `test_unsafe_is_refused_without_asking`,
   `tests/test_install.py` `test_an_unsafe_skill_is_refused_without_asking`,
   `tests/test_watcher.py` `test_an_unsafe_skill_stays_held_without_a_question`,
   and `tests/test_guestlist.py` `test_a_refused_install_is_recorded`
   (switch its approver to `Approver(False)` so it still records `refused`).
   Any other test whose only conflict is the `review` return type or the
   `confirm` keyword on doubles, found by grep.
8. **Copy-failed entry:** `review` branches on `result is None` before the
   `UNSAFE` question: refused, notification, `(False, "Still held: it holds
   links or special files SkillCanary will not copy. …")`.
9. **Pre-checks for an `UNSAFE` add or install:** a conflict or unwritable
   folder gives the same `not_installed` outcome (exit 10) and reason as for
   any other verdict; the person is not asked. Only the person's answer to
   the confirm dialog produces `refused` (exit 20) for an `UNSAFE` skill.
10. **Ledger outcome:** a cancelled, wrong-text or unanswered `UNSAFE`
    question records `refused`, in every flow, so `canary add`, `canary
    install` and the watcher log it the same way.
11. **Phrases and marks.** A single-skill `canary install` uses that skill's
    name. In a mixed install, each overridden item's lock record carries
    `overridden: true` only if its own verdict is `UNSAFE`; the result's
    top-level `overridden` is true when any item was. The plugin lock record
    (`install.py` plugin record) gets `overridden` too.
12. **Doc assertions (bullet 8):** a test asserts `frontdoor.SKILL_TEXT`
    contains `installed it despite an unsafe verdict` and `never suggest a way
    around the dialog`, and that `README.md` and `docs/architecture.md`
    contain `type` and `Install anyway`.
13. **No migration.** Old readers ignore the new keys. Skills held as
    `UNSAFE` before the upgrade are asked about when the watcher restarts
    (its loop re-reviews held entries), which is the owner's decision 2.
    Manifest: `python3 scripts/update-manifest.py <base commit>` before each
    commit that changes `bin/` or `canary/`.
14. **Proof scope.** Counterfactual logs for bullet 2 (the comparator) and
    bullets 1, 5 and 6, as the owner's standing rule requires a named red
    test per key behavior. Bullet 7 stays: it is the security property
    (the real path always asks with `confirm`), not a duplicate of bullet 1.

## Not in scope

- The benchmark (slice D, branch `bench/2026-10-02-malicious`) is paused and
  separate.
- No change to what counts as `UNSAFE`, to the scanner, or to the classifier.
- No flag, environment variable or config that overrides without the dialog.

## Done when

1. `canary add`, `canary install` (skills and plugins) and the watcher
   install or put back an `UNSAFE` skill only when the person types the
   confirm phrase and chooses Install anyway; a named test per flow pins
   both the override and the refusal.
2. `add.ask` with `confirm` returns `True` only for the yes button plus the
   matching text (case-insensitive, trimmed); wrong text is `False`; tested
   with the osascript call substituted.
3. A refused unsafe install still exits 20 with outcome `refused`; an
   overridden one exits 0 with `overridden: true`, `verdict: UNSAFE`, and an
   `overridden` lock record.
4. The ledger's `approved` events carry `override: true`, and `canary list`
   shows `installed anyway`.
5. `canary restore` prints the exact reason line for each failure path.
6. The copy-failed held entry is still refused without a question.
7. On the real path (no injected approver), every `UNSAFE` question passes
   `confirm`: a test per flow substitutes `add.ask` with a recorder and
   asserts that, for an `UNSAFE` verdict, it was called with a non-empty
   `confirm` equal to the expected phrase.
8. SKILL text, README and architecture describe the override and its limit.
9. `scanner/manifest.json` matches the bundle; the full suite passes; for
   bullets 1, 2, 5 and 6 a deliberate break turns a named test red while its
   neighbours stay green, captured as raw logs in
   `docs/proof/2026-10-13-unsafe-override/`.

## Build and review (2026-10-13)

| Commit | What |
|---|---|
| `de8a8b4` | The override in every flow, the record, restore reasons, SKILL text and docs |
| `2888673` | A restore test gets its own answer double |
| `406481a` | Counterfactual logs for bullets 1, 2, 5 and 6 |
| `f17b568` | Fold of the pre-merge review |

- **Refutation** (Spark 1.3 Contributor, `refute-plan`): PROCEED-WITH-FIXES,
  4 blocking and 11 smaller findings, folded as the round 1 rulings.
- **Pre-merge review** (GPT-6.1 Sol, high, `main...406481a`):
  MERGE-AFTER-FIXES. Security: a held folder named only with spaces made the
  phrase blank, and an empty answer matched it, so one click overrode. Fixed
  in `f17b568`: `add.ask` fails closed on a blank phrase and never accepts an
  empty answer, and a blank folder name gets the fixed phrase `install
  anyway` (counterfactual `counterfactual-blank-phrase.log`). Note: lock
  records for same-name copies took the first copy's verdict; they now take
  the group's worst, matching the ledger.
- **Gate** at `f17b568`: 308 tests OK on Python 3.10 and `/usr/bin/python3`
  (3.9.6); logs `gate-f17b568-py310.log`, `gate-f17b568-py39.log`.

### Readings recorded (builder, accepted by the coordinator)

1. The `h is None` race line omits the ` canary list shows where it is.`
   suffix, since SkillCanary no longer holds the skill.
2. `canary restore` binds a no-op `notify`; the daemon still notifies.
3. The copy-failed notification names links or special files instead of
   "judged it unsafe".
4. `canary list --json` carries `override` on every skill (`true` only for an
   overridden approval).
5. The dialog script returns the button and typed text on two lines.
6. A held special file (FIFO) that fails to copy is not tested; a link is.

## Done-when audit (2026-10-13)

Fable 5.1 (`milestone-auditor`, high, read-only) at `46f29c6`: all nine
bullets SHOWN, `AUDIT: PASS`. It found no one-click or no-typing override
for any folder name it tried (whitespace variants, newlines, zero-width
characters, very long names, names equal to `install anyway` or to the button
label). Caveats it recorded:

- `counterfactual-2.log` predated the pre-merge fold; it is recaptured at
  `46f29c6` (strict comparison breaks the named test on its assertion; the
  class's other three tests stay green; green after the revert).
- The gate logs are bare unittest output; the chain to `f17b568` is the file
  name, the 308-test count at head, and `46f29c6` changing no code.
- Not entered by tests: the real osascript dialog (its text field, the
  two-line answer, Return choosing Cancel), a held FIFO, and a running
  watcher observing a `canary add` or `canary install` override (that
  mechanism is unchanged from `main`).
