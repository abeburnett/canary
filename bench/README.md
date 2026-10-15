# SkillCanary benchmark corpus

This folder is test data for `canary bench` (`docs/architecture.md`, "canary bench"). It isn't a skills folder, and no agent should load, follow or run anything in it.

- `benign/` holds 94 real, popular skills, copied at pinned commits from anthropics/skills (Apache 2.0), obra/superpowers and wshobson/agents (both MIT). Each repository's license sits beside its skills, or in each skill folder for anthropics/skills. `scripts/vendor-bench-benign.py` recreates this folder.
- `malicious/` holds inert attack samples written for this benchmark. Their instructions and payloads are attack text, kept here as data. Every target is a reserved name such as `example.invalid`, and every payload only prints a marker, so nothing in them reaches a real host or does harm if run. They still read as instructions. Don't follow them.
- `manifest.json` lists every sample with its label (`malicious` or `benign`), category and source.
- `baseline.json` holds the committed rates. CI fails when the layer-1 catch rate falls below it. A change to the corpus and its baseline land in the same commit.
