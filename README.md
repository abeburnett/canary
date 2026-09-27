# Canary

**Send the canary into the skill mine first.**

AI skills are the new npm packages — and nobody is auditing them. Canary scans AI skill files for prompt-injection and malicious-instruction risk *before* you install them.

## What's here

- `scanner/` — the detection engine (Jev): deterministic layer-1 CLI (`bin/jev-scan`), the check catalog, the isolated layer-2 classifier prompt, and test fixtures. Product name: Canary; engine name: Jev.
- `skills/canary/` — one-shot setup skill: point your agent at Canary.
- `docs/field-report/` — the 100-skill field report (2026-09-26): 71 safe / 14 review / 15 flagged, zero live attacks found. `results.csv` carries the per-skill verdicts; the full per-skill JSON output is archived separately.
- `docs/x-launch-strategy.md` — go-to-market plan.

## Quickstart

```bash
python3 scanner/bin/jev-scan path/to/SKILL.md --text
```

Verdict bands: LIKELY_SAFE (score 0–2), NEEDS_REVIEW (3–5), UNSAFE (6+).

## GitHub Action

Public repositories can run the bundled deterministic scanner in CI:

```yaml
- uses: actions/checkout@v4
- uses: abeburnett/canary@REPLACE_WITH_FULL_COMMIT_SHA
  with:
    path: skills
    fail-on: unsafe
```

Replace the placeholder with the immutable full commit SHA of the Canary
release you reviewed. See [the Action guide](docs/github-action.md) for inputs,
outputs, private-repository setup, and the scope of a `safe` result.

## Model

Free for individuals and public-repository CI. Private-repository CI requires
a Canary Team token ($19/month per team). Verified skill badges are $99/year
per skill; registry submission and badge issuance are separate steps.

## Status

Launch candidate. Marketplace listing materials are drafts until the owner
publishes them.
