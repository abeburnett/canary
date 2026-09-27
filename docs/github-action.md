# Canary GitHub Action

Canary's GitHub Action runs the deterministic layer-1 scanner bundled with
the action. It does not execute scanned files or send their contents to a
service.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | A file or directory inside `GITHUB_WORKSPACE`. Missing paths and paths or symlinks that escape the workspace are rejected. |
| `fail-on` | `unsafe` | `unsafe` fails only an unsafe verdict; `review` fails review and unsafe verdicts; `never` reports without failing on a verdict. Operational scan errors always fail. |
| `version` | `latest` | `latest` means the fixed scanner bundled in this action revision. The only other accepted value is the exact version in `scanner/manifest.json`; other versions fail rather than downloading code at runtime. |

The action emits `verdict` (`safe`, `review`, or `unsafe`) and
`layer1_verdict` (`LIKELY_SAFE`, `NEEDS_REVIEW`, or `UNSAFE`). For a directory,
the result is the worst per-file verdict. Findings report category, severity,
file, and line; Canary deliberately does not print matched skill text.

`safe` means only that this deterministic scan returned `LIKELY_SAFE`. It is
not the two-layer certification described in `scanner/SKILL.md`.

## Public repository quickstart

Create `.github/workflows/canary.yml`:

```yaml
name: Canary

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: abeburnett/canary@e81f825cf36abe0add5503a20ff698233d9837f9
        with:
          path: skills
          fail-on: unsafe
```

This example pins the tested launch candidate by its full commit SHA. A moving branch or tag is convenient, but a
commit pin prevents the action code from changing between workflow runs.

## Private repositories

Private repositories must provide `CANARY_API_TOKEN` through the step
environment:

```yaml
      - uses: abeburnett/canary@e81f825cf36abe0add5503a20ff698233d9837f9
        env:
          CANARY_API_TOKEN: ${{ secrets.CANARY_API_TOKEN }}
```

This launch version checks only that the secret is present. It does not yet
validate the token or a Team entitlement server-side. Never place the token in
`with:`, command arguments, repository files, or logs.

## Bundled calibration baseline

The manifest pins the supplied scanner from commit
`eca766b7677b6c72fdf4c8632e05f239badb83ac`, the 2026-09-26 calibrated
baseline. The Action wrapper does not change its checks or scoring rules and
verifies the bundled file's SHA-256 before every scan.
