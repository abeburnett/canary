# Canary

**Send the canary into the skill mine first.**

AI skills are the new npm packages — and nobody is auditing them. Canary scans AI skill files for prompt-injection and malicious-instruction risk *before* you install them.

## What's here

- `bin/canary` and `canary/` — the command-line tool: `canary scan` is the deterministic layer-1 scanner; `canary check` adds the isolated layer-2 classifier. Interfaces and exit codes: [`docs/architecture.md`](docs/architecture.md).
- `scanner/` — the two-layer workflow, the check reference, notes on the layer-2 classifier prompt, and test fixtures. `scanner/bin/jev-scan` is a deprecated alias for `canary scan`.
- `skills/canary/` — one-shot setup skill: point your agent at Canary.
- `docs/field-report/` — the 100-skill field report (2026-09-26): 71 safe / 14 review / 15 flagged, zero live attacks found. `results.csv` carries the per-skill verdicts; the full per-skill JSON output is archived separately.
- `docs/x-launch-strategy.md` — go-to-market plan.

## Quickstart

```bash
bin/canary scan path/to/skill-folder --text
```

To change a skill that SkillCanary protects, work on a draft and approve the change once:

```bash
canary edit start my-skill
```

Edit the draft folder it prints, then run `canary edit apply <draft>`. SkillCanary scans only the change and asks you in a dialog.

Verdicts: LIKELY_SAFE (exit 0), NEEDS_REVIEW (exit 10), UNSAFE (exit 20). A package that runs code, or that could not be read in full, is never LIKELY_SAFE. See [`scanner/references/checks.md`](scanner/references/checks.md).

## GitHub Action

Public repositories can run the bundled deterministic scanner in CI:

```yaml
- uses: actions/checkout@v4
- uses: abeburnett/canary@e81f825cf36abe0add5503a20ff698233d9837f9
  with:
    path: skills
    fail-on: unsafe
```

The example pins the tested launch candidate by its full commit SHA. See [the Action guide](docs/github-action.md) for inputs,
outputs, private-repository setup, and the scope of a `safe` result.

## Model

Free for individuals and public-repository CI. Private-repository CI requires
a Canary Team token ($19/month per team). Verified skill badges are $99/year
per skill; registry submission and badge issuance are separate steps.

## Status

Launch candidate. Marketplace listing materials are drafts until the owner
publishes them.

## Security

To report a vulnerability, and for what SkillCanary does and doesn't claim, see [SECURITY.md](SECURITY.md).
