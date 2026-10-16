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
4. Version 0.1.4, `scanner/manifest.json` regenerated, release notes.

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
  it to something else, and otherwise only `ENV_KEYS`.
- The gate ignores the variable: a hook test that a denied write is still
  denied with `CANARY_CLASSIFIER=1` set.

Counterfactual: remove the check in `_session_start`; the new session-start
test goes red and its neighbours stay green. Remove the env line in
`claude_cli`; the classify test goes red.

## Done when

1. The three tests above exist, were red before the change (logged), and
   the full gate passes on python3.10 and /usr/bin/python3 at the merge
   commit, logs under `docs/proof/2026-10-16-quiet-classifier/`.
2. Counterfactual runs logged in the same folder.
3. Spark refutation and Sol pre-merge review ran; findings folded or
   answered in this doc.
4. After the owner installs 0.1.4, the 2026-10-15 probe (same flags plus
   `CANARY_CLASSIFIER=1`) shows no SkillCanary text in the session, and one
   real `canary check` of `create-viral-content` returns a layer-2 status of
   `ok`. Recorded here.
5. 0.1.4 tagged, signed, notarized and published as Latest; the tap formula
   points at v0.1.4.
