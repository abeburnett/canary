---
name: "canary"
description: "One-shot setup of Canary skill screening: install the scanner, wire skill-safety checks into the agent's workflow, and quarantine anything suspicious. Use when the user says 'set up Canary' or 'point your agent at Canary'."
---

# Canary — one-shot install

Canary scans AI skill files for prompt-injection and malicious-instruction risk *before* they get trusted. Setup takes one pass:

## Install

1. The scanner engine lives at `scanner/` in this repo (product name: SkillCanary; command: `canary`). To install, copy `scanner/` into the agent's workspace skills directory.
   - Files: `SKILL.md` (the full two-layer workflow), `bin/canary` (layer-1 scanner CLI), `references/checks.md`, `references/classifier-prompt.md`.
2. Verify it runs: `bin/canary --help` should print usage and exit 0. (Python 3, no dependencies.)

## Wire it into the workflow

1. **Scan before install.** Every third-party skill gets scanned *before* being added to the agent's skills. No eyeballing — always run the scan.
2. **The rule:** `bin/canary check <skill-path> --text` (both layers; `scan` is layer 1 alone). Either layer says UNSAFE → do not install. Any meaningful flag → NEEDS REVIEW, show the user the findings, let them decide. Both clear → install.
3. **Quarantine, don't delete.** Never copy a flagged skill anywhere an agent loads skills from. Quarantine lives outside every skills directory (see `docs/architecture.md`).
4. **Re-scan discipline.** Re-run the scan after every new skill install and periodically over the whole skills directory. Skills update; trust doesn't persist.

## The two layers (summary)

- **Layer 1 (deterministic):** pattern-matches 11 attack categories (instruction override, identity rewrite, safeguard bypass, exfiltration, shell-pipe execution, credential access, persistence, stealth, prompt leakage, obfuscation, external URLs). Cannot be socially engineered — it never "reads" the skill.
- **Layer 2 (isolated classifier):** `canary check` starts a separate model session with no tools, memory or project files and a fixed JSON-only answer. A hijacked classifier can only lie inside that JSON, and it can only make the verdict stricter.
- **Combination:** either layer UNSAFE → UNSAFE; any meaningful flag → NEEDS REVIEW; both clear → SAFE.

Full workflow, output contract, and operating rules: read `scanner/SKILL.md`.

## After setup

Confirm back to the user in one line: where the scanner lives, how many existing skills were scanned, and the verdict counts. Offer to scan the current skills directory immediately.
