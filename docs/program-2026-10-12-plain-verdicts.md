# Program 2026-10-12: plain verdicts

Status: built on branch `program/2026-10-12-plain-verdicts`, based on `main`
at `222c3df`. Gate: `python3 -m unittest discover -s tests` (the gate used at
the plain-flags merge, `701a98c`); the VM e2e suite runs at release.

## Why

The owner, 2026-10-12: when he installs a skill, SkillCanary pops up, but its
findings don't tell him whether to install or decline, so he always says yes.
The same day he decided SkillCanary becomes free and open source and the paid
tier is dropped (future-think `wayfinder/tickets/06-venture-decisions.md`).

## Owner decisions

1. **Evidence line, dialog only (2026-10-12, asked in session).** The person's
   dialog may show the flagged line and its file name, clipped and labelled as
   coming from the skill. Agent output and JSON keep omitting package text.
   This narrows the 2026-10-06 rule that kept excerpts and file names out of
   dialogs.
2. **Quote limits (2026-10-12, asked in session after the done-when audit).**
   The owner keeps the limits on quoted lines: a `canary install` that flags
   more than three skills lists their risks without quotes, and any dialog
   quotes at most five risks and two lines each, with a count and a pointer
   to `canary explain` for the rest. Reason: a macOS dialog cannot scroll.
   Every finding still gets its risk sentence and the recommendation.
3. **Publication stays with the owner.** Releases, site deploys and Stripe
   changes are not part of this program; item 4 is a proposal only.

## Done when

The owner's four work items, as stated, plus the test run he asked for:

1. The README states the value proposition plainly in its first screen: what
   SkillCanary protects against, what a finding looks like, and what to do
   with it.
2. Every finding is actionable: it states the risk in plain words (for
   example "this skill can read your SSH keys") and a recommended action
   (install, install only if you trust the author, or decline), with the
   evidence line (within the quote limits of owner decision 2).
3. Detection is verified against real or fixture skills with known-bad
   patterns, and a record says which README claims hold.
4. A proposal (not executed) says how to retire the paid tier and the site's
   pricing.
5. Agent-facing output carries no package text (owner decision 1).
6. The project's tests pass on the final tree.

## Evidence

- Design and behaviour: `canary/explain.py` (`RISKS`, `DETAILS`, `recommend`,
  `evidence_lines`), the dialogs in `canary/add.py`, `canary/install.py` and
  `canary/watcher.py`; `docs/architecture.md`.
- Measurements and the claims table: `docs/proof/2026-10-12-plain-verdicts/`.
- Proposal: `docs/proposal-2026-10-12-free-and-open.md`.

## Refutation

Not run: the owner's order puts `refute-plan` before building; this program
was built from his direct request without a written plan. An automated commit
security review found a fail-open (context labels softened "decline"), fixed
in `d9c8165`. `premerge-review` (GPT-6.1 Sol, high, 2026-10-12): no security
findings; one should-fix (plugin results dropped `recommendation` and
`risks`), folded with a test in `PluginsAreCheckedThenInstalled`; verdict
MERGE-AFTER-FIXES.

Done-when audit, round 1 (milestone-auditor, Fable 5.1, high, at `cab4222`):
bullets 1 and 3-6 SHOWN; bullet 2 RE-SCOPED because the quote limits had no
owner decision. The owner then kept the limits (owner decision 2); the README
now states them.

Done-when audit, round 2 (same auditor, at `917e9cf`): all six bullets SHOWN,
`AUDIT: PASS`. Caveats it noted: `invisible-character` and
`mixed-script-word` have no test asserting the rule id fires (only that the
verdict is not `LIKELY_SAFE`), and the AI-review column of `results.csv`
cannot be reproduced from the repository alone. Gate log:
`docs/proof/2026-10-12-plain-verdicts/gate-917e9cf.log`.
