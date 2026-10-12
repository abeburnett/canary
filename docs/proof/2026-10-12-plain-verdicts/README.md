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
| Pattern scan only | 16 of 60 | 0 / 90 / 4 |

The four real skills declined either way are `anthropics/skills/claude-api`,
`obra/superpowers/brainstorming`, `wshobson/agents/deployment-pipeline-design`
and `wshobson/agents/file-conversion`. Three of them were already `UNSAFE`
from the pattern scan alone (upload commands, piped install scripts); the
fourth has a credential pattern outside a code example, and the AI review
asked for a person's review.

## Claims

| README claim | Holds? | Evidence |
|---|---|---|
| Each question starts with a recommendation, then each risk and the line that raised it. | Yes | `tests/test_add.py` `test_the_dialog_quotes_the_line_and_the_result_does_not`, `tests/test_install.py` `test_the_dialog_quotes_the_line_while_the_snapshot_exists`, `tests/test_watcher.py` `test_the_dialog_recommends_an_action_and_quotes_the_line` |
| The example finding (SSH key line) is real output. | Yes | Rendered with `add.dialog_text` from a fixture skill on this branch, both with and without the AI review. |
| The three recommendations follow the rules in the table. | Yes | `tests/test_explain.py` `test_the_recommendation_for_each_case`, 10 cases. Counterfactual: making `recommend` ignore the code-example and warning labels turned exactly the two matching cases red. |
| It flags the seven kinds of instruction listed. | Yes | One catalog rule each (`canary/catalog.py`). `tests/test_scan.py` `EveryRuleTheReadmeNamesFires` fires each of the eight rules on a plain line (counterfactual: a harmless stealth line turned only that case red); `tests/test_explain.py` `test_the_detail_names_what_the_line_reaches_for` covers SSH, cloud, keychain, Slack and launch agents. |
| Unsafe skills are not installed and nobody is asked. | Yes | `add.py` and `install.py` refuse `UNSAFE` before the dialog; the watcher notifies instead. Existing tests in `test_add.py`, `test_install.py`, `test_watcher.py`. |
| Attacks get "decline". | With the AI review only | 60 of 60 with it; 16 of 60 without it. The no-review "trust" text says the pattern scan alone misses most attacks. |
| Real skills mostly get "install" or "trust". | Yes | 90 of 94 either way; 4 declined (above). Without the review, none gets "install", because an unreviewed skill is never `LIKELY_SAFE`. |
| Your agent doesn't see the skill's text. | Yes, within the documented limit | `test_the_result_carries_no_package_text`, and the `--excerpts` and `explain` terminal checks from program 2026-10-06. The accepted limit (an agent running Canary's Python directly) is in `docs/architecture.md`. |
| Guard stops agents installing skills other ways. | Documented, not rerun here | `docs/architecture.md` and SECURITY.md "Known limits"; the e2e VM suite last ran for 0.1.1. |

## What this does not show

The attack samples were written by the same project that wrote the scanner
and its review prompt. They are plain attacks, and 60 of 60 says the review
catches those. It says nothing about an attacker who has read the prompt. The
field report (`docs/field-report/`) found no live attacks in 100 real skills,
so there is no real-world attack to test against yet.
