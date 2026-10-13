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
