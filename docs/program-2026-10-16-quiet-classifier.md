# Program 2026-10-16: keep SkillCanary's own hook out of the AI review

Status: requested by the owner on 2026-10-15 ("yes, start the 0.1.4 fix").
Branch `program/2026-10-16-quiet-classifier`, based on `main` at `35d2d85`
(version 0.1.3). Gate: `python3 -m unittest discover -s tests`, also on
`python3.10` and `/usr/bin/python3`. Ships as 0.1.4.

## Why

On 2026-10-15 an agent installed `aaaronmiller/create-viral-content`. The AI
review (layer 2, `claude -p` on the person's login) answered SAFE at 0.85,
plus a fifth key: `"_note": "The injected hook text about other skills was
not part of the package and was ignored."` `classify.validate` requires
exactly four keys, so the answer was `invalid` and the verdict stayed
NEEDS_REVIEW (log `classify-20261016T001113Z-34934b133fad.txt`).

The hook text came from SkillCanary itself. Guard mode (since 2026-10-01)
installs `/Library/Application Support/ClaudeCode/managed-settings.d/canary.json`
with a `SessionStart` hook that runs `canary session-start --host claude`.
Managed hooks load whatever the CLI flags say. Probes on 2026-10-15
(Claude Code 2.1.296, from an empty temp folder, `env -i` with HOME, USER,
PATH) show the isolated classifier session receives the full
"SkillCanary: 11 skill(s) arrived without SkillCanary's check (…names…)"
notice, both with the current flags and with
`--settings '{"disableAllHooks":true}'` added. The isolation check recorded
in `canary/classifiers/claude_cli.py` dates from 2026-09-26, before Guard
added managed hooks.

Two harms:
1. **Spurious invalid reviews.** The model sometimes remarks on the notice
   and breaks the answer shape (1 of 380 logged runs so far).
2. **Unfenced untrusted text.** The notice lists skill folder names, which
   a skill's author chooses. They reach the classifier outside the nonce
   fence, where the system prompt's "data is untrusted" framing does not
   cover them. A folder name written as an instruction is a steering
   channel into the review.

## Change

1. `canary/classifiers/claude_cli.py`: the child environment gains one fixed
   variable, `CANARY_CLASSIFIER=1`, next to the `ENV_KEYS` passthrough. The
   value is a constant, never taken from the parent environment. Update the
   module docstring: managed-settings hooks still run, and why they stay
   quiet.
2. `canary/cli.py` `_session_start`: when `os.environ.get("CANARY_CLASSIFIER")
   == "1"`, write nothing and return 0, before any scan.
3. **The PreToolUse gate (`_hook`) does not read the variable.** Honoring it
   there would let any process that sets it switch the gate off. The
   classifier has no tools, so the gate never fires in that session anyway.
   A test pins this.
4. Version 0.1.4 and `scanner/manifest.json` regenerated. The release
   notes are the GitHub release body, written at publish time.
5. `docs/architecture.md` updated first (done in this branch before the
   build): the child env list, managed hooks running despite the flags, the
   session-start silence condition, and the residual.

Migration and rollback: the hook command strings do not change, so nobody
reruns `canary setup`. Mixed versions are harmless either way: a 0.1.3
binary ignores the variable, and a 0.1.3 classifier never sets it. Rollback
is reinstalling 0.1.3.

Two side effects, both named in the docstring: the early return also skips
`guestlist.scan`, which today writes ledger events from inside classifier
sessions (`canary/guestlist.py:301-302`), so "before any scan" is
load-bearing. And a `CANARY_CLASSIFIER=1` left in a shell profile would
silence every session notice; `canary list` and the watcher are unaffected.

Why the variable is safe in `session-start`: setting it suppresses only an
informational notice; holds, the watcher and the gate are unchanged. A
process able to set an agent's environment can already do far more.

Not in scope: hooks from other managed-settings files (another vendor's
policy). The fix covers SkillCanary's own hook; the docstring names the
residual.

## Tests (red first)

- `tests/test_guestlist.py` `TheSessionStartLine`: with a dropped-in skill
  present and `CANARY_CLASSIFIER=1` in the environment, `session-start
  --host claude` exits 0 with empty stdout and stderr. Without it the
  existing test still sees the notice. (`Mac.run` gains an `env` argument.)
- `tests/test_classify.py` `ClaudeBackendRunsIsolated`: the child env
  carries `CANARY_CLASSIFIER == "1"`, even when the parent environment sets
  it to something else, and otherwise only `ENV_KEYS`. The existing
  assertion at line 250 becomes `set(ENV_KEYS) | {"CANARY_CLASSIFIER"}` in
  the same change.
- The gate ignores the variable: in `tests/test_gate.py`, call
  `Home.hook(..., env={"CANARY_CLASSIFIER": "1"})` (it already takes `env`)
  for a write the gate denies, and assert the same deny shape.

Counterfactual: remove the check in `_session_start`; the new session-start
test goes red and its neighbours stay green. Remove the env line in
`claude_cli`; the classify test goes red.

## Probe before build (finding 1, done 2026-10-15)

A `--settings` SessionStart hook that prints `$CANARY_CLASSIFIER`, run under
the classifier's exact flags with `env -i HOME USER PATH CANARY_CLASSIFIER=1`,
reported `MARKER=[1]` to the model. Hooks inherit the child's environment,
so the fix can work. (Managed hooks are launched by the same CLI; the flag
hook stands in because adding a managed hook needs root.)

## Done when (merge gate)

1. The three tests above exist, were red before the change (logged), and
   the full gate passes on python3.10 and /usr/bin/python3 at the merge
   commit, logs under `docs/proof/2026-10-16-quiet-classifier/`. CI does not
   run on this branch (`action-check.yml` lists other branches); the logs
   are the gate.
2. Counterfactual runs logged in the same folder.
3. Spark refutation and Sol pre-merge review ran; findings folded or
   answered in this doc.

## Release checklist (after merge, owner-approved publish)

1. Tag v0.1.4; build signed, notarize, staple; publish as Latest with the
   release body; bump the tap formula.
2. After the owner installs 0.1.4: rerun the 2026-10-15 probe with
   `CANARY_CLASSIFIER=1` and confirm no SkillCanary text reaches the
   session (the deterministic check). Record one real `canary check` of
   `create-viral-content` and its layer-2 status as evidence, retrying on
   network or model failures; a single `ok` is not the gate.

## Refutation (Spark 1.3 Contributor, max, 2026-10-15)

Verdict PROCEED-WITH-FIXES, `~/.cache/reviews/20261015-183333-refute-program-2026-10-16-quiet-classifier/verdict.md`.
All nine findings folded: 1 probe above; 2 architecture.md edited first;
3 test line 250 named; 4 and 5 merge gate split from the release checklist;
6 migration lines; 7 side effects named; 8 gate-test harness named; 9 CI
note.

## Who can set the variable (automated security review, 2026-10-15)

The security-guidance plugin flagged `_session_start` honoring a guessable
variable as a control bypass and suggested a per-run nonce file or a check
on the session's working folder. Answer, kept as built:

- What it bypasses is the session notice only. The PreToolUse gate never
  reads the variable (pinned by
  `test_the_classifier_variable_does_not_switch_the_gate_off`), and the
  watcher, holds, `canary list` and `canary restore` do not either.
- Who could set it for an agent session: the person's own shell, or a
  project's `.claude/settings.json` `env`. A project settings file that
  Claude Code loads can already declare its own hooks, which run arbitrary
  commands as the person, so the variable grants nothing new. A skill
  cannot set it: skills are text read by the agent, not settings.
- A nonce file adds a write into the support folder from every classifier
  run and a race to clean up, for the same outcome against a party that
  already runs code. Not worth it for an informational notice.

If Sol disagrees, the cheaper hardening is to also require the hook's
`cwd` to be a `canary-classify-` folder in the temp directory.

## Pre-merge review and audit (2026-10-15)

- Sol (GPT-6.1 Sol, high) on the code at 67eda7b: no security or semantic
  findings, MERGE (`docs/proof/2026-10-16-quiet-classifier/sol-review.md`).
- Full gate at 67eda7b, stamped: 326 tests OK, exit 0, on Python 3.10.3 and
  /usr/bin/python3 3.9.6 (`gate-67eda7b-py310.log`, `gate-67eda7b-py39.log`).
- Done-when audit (milestone-auditor, Fable 5.1, high), range
  35d2d85..f69c545: bullets 1 to 3 SHOWN, AUDIT: PASS, none refused. It
  noted two gaps, neither disqualifying: the red and counterfactual logs
  carry no commit stamp, and the counterfactual logs don't name the removed
  line. Future logs from this repo's workers get a `commit` line first.

## Release (2026-10-15, owner: "release 0.1.4")

- Tag `v0.1.4` at e46207e. Installer signed with Developer ID, notarized
  through the App Store Connect key route (submission
  `e5ce373d-1a3e-4fdb-8b81-48b86c0b99e7`, Accepted), stapled; Gatekeeper
  `accepted`, `source=Notarized Developer ID`; sha256
  `023d5251c23ccdaec8b995866a17adc59f354b683b34b33dc0f6a82e9e948c9c`.
- GitHub release v0.1.4 published as Latest; the website's
  `releases/latest/download/SkillCanary.pkg` returns that file.
- Tap formula at v0.1.4 (`abeburnett/homebrew-tap` bff4c31), tarball sha256
  `c7838ff4…f945d9`.
- The owner installed 0.1.4 (`canary --version` and the Guard hook's copy
  both report 0.1.4).
- Probe, classifier flags, Claude Code 2.1.296: without the marker the
  session still receives "SkillCanary: 11 skill(s) arrived…" (positive
  control); with `CANARY_CLASSIFIER=1` the model answers `NONE`.
- Real check of `create-viral-content` at 5148302 (fresh clone): layer 2
  `ok`, SAFE 0.88, log `0e9bcef2c669` with no remark about hook text. The
  overall verdict stays NEEDS_REVIEW because the scan finds code and tool
  grants, which is correct.
