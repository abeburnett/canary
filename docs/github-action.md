# SkillCanary GitHub Action

SkillCanary's GitHub Action runs the deterministic layer-1 scanner bundled with
the action. It does not execute scanned files or send their contents to a
service.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | A file or directory inside `GITHUB_WORKSPACE`. Missing paths and paths or symlinks that escape the workspace are rejected. |
| `fail-on` | `unsafe` | `unsafe` fails only an unsafe verdict; `review` fails review and unsafe verdicts; `never` reports without failing on a verdict. Operational scan errors always fail. |
| `version` | `latest` | `latest` means the fixed scanner bundled in this action revision. The only other accepted value is the exact version in `scanner/manifest.json`; other versions fail rather than downloading code at runtime. |

The action emits `verdict` (`safe`, `review`, or `unsafe`), `layer1_verdict`
(`LIKELY_SAFE`, `NEEDS_REVIEW`, or `UNSAFE`) and `coverage_complete`
(`true` or `false`).

Each skill folder under `path` (a directory holding `SKILL.md`) is scanned as
one package, so findings spread across a skill's files are totalled together.
When `path` holds no skill folder, the whole path is one package. The overall
verdict is the strictest package verdict. A package that runs code (scripts,
hooks, MCP configuration, tool grants) is `NEEDS_REVIEW` by design: a person
approves it once.

If any file could not be read (binary, too large, a link inside the package),
the scan cannot pass: the step fails unless `fail-on` is `never`. When `path`
has no skill folder, point it at the folder you mean to scan; scanning a whole
repository includes `.git`, whose binary objects make coverage incomplete.

The log reports each package's verdict, score, threat categories and
capability kinds. It never prints matched skill text, and prints a package's
path only when it is plain letters, digits, `.`, `_`, `-` and `/`; any other
path appears as a hash, because file names in a pull request are
attacker-controlled.

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
      - uses: abeburnett/canary@<full-commit-sha>
        with:
          path: skills
          fail-on: unsafe
```

Replace `<full-commit-sha>` with the release commit you have reviewed. A moving branch or tag is convenient, but a
commit pin prevents the action code from changing between workflow runs.

## Private repositories

Private repositories must provide `CANARY_API_TOKEN` through the step
environment:

```yaml
      - uses: abeburnett/canary@<full-commit-sha>
        env:
          CANARY_API_TOKEN: ${{ secrets.CANARY_API_TOKEN }}
```

This launch version checks only that the secret is present. It does not yet
validate the token or a Team entitlement server-side. Never place the token in
`with:`, command arguments, repository files, or logs.

## Bundled scanner

`scanner/manifest.json` lists the SHA-256 of every file the scanner runs from
(`bin/canary` and `canary/*.py`) and the commit they came from. The Action
refuses to run if any file differs or an unlisted file appears. After changing
the scanner, run `scripts/update-manifest.py <commit>`.
