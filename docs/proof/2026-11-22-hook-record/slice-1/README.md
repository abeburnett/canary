# Slice 1 evidence

- Builder: Opus 5.5 at high (worktree-agent-ac997f659e9023973, 28d396b..401851e; code tree d888377, manifest 419d29c).
- Pre-merge review: GPT-6.1 Sol at high, MERGE, one note: a failed install whose approval was already written counts as installed in the total (left for slice 2 or the total's wording).
- Done-when audit: Sonnet 5.5 at medium, AUDIT: PASS; bullets 1 to 4 SHOWN, no bullet refused.
- Out of scope, fixed in d888377: tests/test_setup.py ran the hook without an isolated HOME, so full-suite runs during the build wrote 5 `unreadable` hook records to the owner's real ledger (2026-11-22, 23:48 to 23:56 UTC). They are left for the owner to decide.
