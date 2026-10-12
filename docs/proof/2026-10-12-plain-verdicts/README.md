# Claims check, 2026-10-12

This record checks each claim in the README against a run or a test. Of nine
claims, seven hold as stated, one holds only with the AI review, and one is
documented rather than tested.

## How it ran

- Code: branch `program/2026-10-12-plain-verdicts`, based on `main` at
  `222c3df`.
- Corpus: `bench/` from branch `bench/2026-10-02-malicious` at `4226f8a` (not
  merged). It holds 60 inert attack samples written for the benchmark, 10 in
  each of six categories, and 94 real skills copied at pinned commits from
  anthropics/skills, obra/superpowers and wshobson/agents.
- Both layers: `layer2.py` ran `classify._check` on every sample with the
  `claude` backend (Sonnet, on the owner's Claude Code login), four at a
  time. 153 AI reviews returned; one real skill was too large for the review.
- Pattern scan only: `l1.py` and `to_csv.py` ran `classify.check` with
  `--backend none`.
- `results.csv` has one row per sample: verdict, the AI review's verdict and
  confidence, and the recommendation with and without the review.

## Results

| Checks that ran | Attacks declined | Real skills: install / trust / decline |
|---|---|---|
| Pattern scan and AI review | 60 of 60 | 65 / 25 / 4 |
| Pattern scan only | 20 of 60 | 0 / 85 / 9 |

The four real skills declined either way are `anthropics/skills/claude-api`,
`obra/superpowers/brainstorming`, `wshobson/agents/deployment-pipeline-design`
and `wshobson/agents/file-conversion`. Three of them were already `UNSAFE`
from the pattern scan alone (upload commands, piped install scripts); the
fourth has a credential pattern, and the AI review asked for a person's
review. Without the AI review, five more real skills are declined: each has an
attack pattern, mostly in a code example, which counts because the author
writes the examples too.

## Claims

| README claim | Holds? | Evidence |
|---|---|---|
| Each question starts with a recommendation, then each risk and the line that raised it. | Yes | `tests/test_add.py` `test_the_dialog_quotes_the_line_and_the_result_does_not`, `tests/test_install.py` `test_the_dialog_quotes_the_line_while_the_snapshot_exists`, `tests/test_watcher.py` `test_the_dialog_recommends_an_action_and_quotes_the_line` |
| The example finding (SSH key line) is real output. | Yes | Rendered with `add.dialog_text` from a fixture skill on this branch, both with and without the AI review. |
| The three recommendations follow the rules in the table. | Yes | `tests/test_explain.py` `test_the_recommendation_for_each_case`, 12 cases. Counterfactual: dropping the AI review's confident pass from the decline rule turned the two "confidently passed" cases red, plus the `canary explain` layout test that depends on the same pass; the rest stayed green. |
| It flags the seven kinds of instruction listed. | Yes | One catalog rule each (`canary/catalog.py`). `tests/test_scan.py` `EveryRuleTheReadmeNamesFires` fires each of the eight rules on a plain line (counterfactual: a harmless stealth line turned only that case red); `tests/test_explain.py` `test_the_detail_names_what_the_line_reaches_for` covers SSH, cloud, keychain, Slack and launch agents. |
| Unsafe skills are not installed and nobody is asked. | Yes | `add.py` and `install.py` refuse `UNSAFE` before the dialog; the watcher notifies instead. Existing tests in `test_add.py`, `test_install.py`, `test_watcher.py`. |
| Attacks get "decline". | With the AI review only | 60 of 60 with it; 20 of 60 without it. The no-review "trust" text says the pattern scan alone misses most attacks. |
| Real skills mostly get "install" or "trust". | Yes | 90 of 94 with the review, 85 of 94 without it. Without the review, none gets "install", because an unreviewed skill is never `LIKELY_SAFE`. |
| Your agent doesn't see the skill's text. | Yes, within the documented limit | `test_the_result_carries_no_package_text`, and the `--excerpts` and `explain` terminal checks from program 2026-10-06. The accepted limit (an agent running Canary's Python directly) is in `docs/architecture.md`. |
| Guard stops agents installing skills other ways. | Documented, not rerun here | `docs/architecture.md` and SECURITY.md "Known limits"; the e2e VM suite last ran for 0.1.1. |

## A fail-open found and fixed before merge

The first version let a code fence, or a warning word such as "never" or "do
not" on the line, soften "decline" to "trust". A background security review
flagged it: the skill's author controls both, so an attacker could wrap the
payload in a fence. Context labels now never soften a recommendation, the
same rule the scanner applies to scores. With the AI review the numbers did
not change; without it, attacks declined rose from 16 to 20 of 60, and real
skills declined from 4 to 9 of 94.

## What this does not show

The attack samples were written by the same project that wrote the scanner
and its review prompt. They are plain attacks, and 60 of 60 says the review
catches those. It says nothing about an attacker who has read the prompt. The
field report (`docs/field-report/`) found no live attacks in 100 real skills,
so there is no real-world attack to test against yet.
