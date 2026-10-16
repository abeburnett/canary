Refutation of `docs/program-2026-10-16-quiet-classifier.md` (HEAD `29141ef`, branch `program/2026-10-16-quiet-classifier`). Read-only; no code run.

**1. blocks — Change §1 / Why ¶3: env inheritance through `claude -p` to hooks is assumed, never probed.**
What breaks: the whole fix. If Claude Code scrubs env for hook children, `CANARY_CLASSIFIER=1` never reaches `session-start` and nothing quiets.
Evidence: cited probes show hook *output* reaching the session and surviving `--settings '{"disableAllHooks":true}'` (plan lines 20–25); no probe shows a hook *reading* the classifier's env. External-software behavior, no citation.
Fix: add step 0 before Change §1 — marker var + echo-hook probe under the same flags; build only if the hook sees it.

**2. blocks — Change §§1–2: `docs/architecture.md` (frozen contract) is not updated.**
What breaks: the repo's own process gate plus two false contract statements.
Evidence: `docs/architecture.md:3-5` ("Change them only by editing this file first"); `:310-312` (child env "reduced to" the 7 keys); `:305-321` ("no … hooks", verified 2026-09-26); `:833-840` (session-start prints when unchecked/changed). Plan updates only the module docstring (line 42–44).
Fix: edit architecture.md first — env list + `CANARY_CLASSIFIER`, managed-hooks-run note, session-start silence condition, residuals.

**3. wrong-if-built — Tests ¶2: existing assertion contradicts the new behavior.**
What breaks: building as written leaves the gate red.
Evidence: `tests/test_classify.py:250` — `assertLessEqual(set(env), set(ENV_KEYS))` fails once the child carries the 8th variable. Plan adds a test asserting the opposite without naming this line.
Fix: one plan line — update `:250` to `set(ENV_KEYS) | {"CANARY_CLASSIFIER"}` in the same change.

**4. wrong-if-built — Done 4–5: circular order and a flaky single-sample gate.**
What breaks: Done 4 needs installed 0.1.4, which needs Done 5 first; and one real check asserting layer-2 `ok` proves nothing at a 1/380 base rate and flakes on network/model hiccups.
Evidence: classifier sessions run the installed root-owned binary, not branch code (`canary/hosts/claude.py:112`, `canary/cli.py:241`), so e2e proof is impossible pre-release by construction.
Fix: merge gate = Done 1–3 only; release section reordered 5→4; the deterministic probe (no SkillCanary text) is the gate, the real-check status is recorded evidence with infra-failure retries, not a single required `ok`.

**5. wrong-if-built — Change §4 ("release notes") / Done 5: undefined or out-of-scope deliverables.**
What breaks: untestable branch gate; tap work lives outside this repo.
Evidence: no CHANGELOG/releases dir in repo; `packaging/` holds only `build-pkg.sh`; no tap formula present.
Fix: define release notes as the GitHub release body written at publish time; move Done 5 to a release checklist, cut from branch scope.

**6. cleanup — Change: no migration/rollback lines (answer is easy, state it).**
Evidence: hook command strings unchanged (`canary/hosts/claude.py:118-119`, `canary/hosts/codex.py:169-172`), so no `setup` rerun; mixed versions are safe no-ops both directions (old binary ignores the var; old classifier never sets it).
Fix: add three lines — no setup rerun needed; mixed versions safe; rollback = reinstall 0.1.3.

**7. cleanup — Change §2 + safety ¶: two unnamed effects.**
(a) Early return skips `guestlist.scan`, which currently *writes* ledger events from classifier sessions (`canary/guestlist.py:301-302`, real HOME passed through) — beneficial, and makes "before any scan" load-bearing. (b) A persistent `CANARY_CLASSIFIER=1` (e.g. shell profile) silences all future notices on the new binary — low risk (`list`/watcher intact) but a new primitive.
Fix: one line each in docstring/architecture.

**8. cleanup — Tests ¶3: harness half-ready.**
Evidence: `tests/test_gate.py:34` `Home.hook` already takes `env`, but `:43` `denied()` doesn't thread it.
Fix: test calls `hook(..., env={"CANARY_CLASSIFIER": "1"})` directly and asserts the deny shape.

**9. cleanup — Done 1: CI won't run here.**
Evidence: `.github/workflows/action-check.yml:4` branches `[main, program/2026-09-26-paid-launch]`.
Fix: note manual dual-interpreter logs are the gate (already planned); don't expand the workflow in this program.

**Holds up.** The diagnosis: `validate` requires exactly four keys (`canary/classify.py:138`); Guard installs the SessionStart hook as described (`canary/hosts/claude.py:106-123`). Change §3 (gate ignores the var): classifier argv has `--tools ""`, `--max-turns 1` (`canary/classifiers/claude_cli.py:32-36`), and Canary installs only PreToolUse + SessionStart hooks (claude.py:113-119; codex.py:166-172), so silencing session-start fully quiets Canary with no tool-hook exposure. Scope to `claude_cli` is right (`codex exec` is not a backend, architecture.md:324-327). Counterfactual design is sound (new tests are the only var-setters, so neighbours stay green). `Mac.run` gaining optional `env` is compatible (`tests/test_guestlist.py:58-61`). Dual-interpreter gate matches convention (`cf0e2be`, `docs/proof/*/gate-*-py310|py39.log`); new code uses no 3.10-only syntax. Constant-overwrite (never from parent) is correctly specified.

PROCEED-WITH-FIXES
