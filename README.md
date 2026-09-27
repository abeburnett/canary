# Canary

**Send the canary into the skill mine first.**

AI skills are the new npm packages — and nobody is auditing them. Canary scans AI skill files for prompt-injection and malicious-instruction risk *before* you install them.

## What's here

- `bin/canary` and `canary/` — the command-line tool: `canary scan` is the deterministic layer-1 scanner. Interfaces and exit codes: [`docs/architecture.md`](docs/architecture.md).
- `scanner/` — the two-layer workflow, the check reference, the layer-2 classifier prompt, and test fixtures. `scanner/bin/jev-scan` is a deprecated alias for `canary scan`.
- `skills/canary/` — one-shot setup skill: point your agent at Canary.
- `docs/field-report/` — the 100-skill field report (2026-09-26): 71 safe / 14 review / 15 flagged, zero live attacks found. `results.csv` carries the per-skill verdicts; the full per-skill JSON output is archived separately.
- `docs/x-launch-strategy.md` — go-to-market plan.

## Quickstart

```bash
bin/canary scan path/to/skill-folder --text
```

Verdicts: LIKELY_SAFE (exit 0), NEEDS_REVIEW (exit 10), UNSAFE (exit 20). A package that runs code, or that could not be read in full, is never LIKELY_SAFE. See [`scanner/references/checks.md`](scanner/references/checks.md).

## Model

Free for individuals. Team/CI and a verified-publisher badge are on the roadmap.

## Status

Private alpha. Nothing here is published or shared without the founder's explicit approval.
