# Program 2026-09-26: the Canary gate

Branch `program/2026-09-26-canary-gate`, based on `eca766b` (the calibration
baseline). Owner decisions, 2026-09-26:

- Canary may ask for the user's password once, at setup, to install root-owned
  enforcement.
- Claude Code and Codex are both first-class, enforced hosts from the start.
  Other agents come later and are described honestly until then.
- Order: scanner, isolated classifier, `canary add` with snapshots and a
  lockfile, managed settings per host, then the tidy-up report and an
  alert-only watcher.
- Claude builds the core and the Claude Code side; Codex builds its own side
  from `docs/codex-brief.md`, against `docs/architecture.md`.

Owner decisions, later on 2026-09-26:

- Drop the name "Jev" from Canary. The product is SkillCanary; the command is
  `canary`. The rename happens during integration.
- Protection is the user's choice at setup, stated openly, with three levels:
  Scan (no password), Guard (managed hooks; password once), Lockdown (adds
  root-owned user-level skill folders; plugin updates go through
  `canary update`). Setup asks rather than defaulting silently, recommends a
  level from what it detects, and can be reversed; `canary doctor` prints the
  current level and its gaps; public claims are made per level.

Pending owner answers: pulling and replacing the live `canary-kit.zip`;
Claude integrating `program/2026-09-26-paid-launch` onto this scanner; an
independent Opus review of the payments and badge code before live payments.

## Slice 1: scanner hardening

Done when:

1. An attack line followed by a documentation token (`--yes`, `-y`,
   `example:`, `for example`, an `X_API_KEY` name) is not `LIKELY_SAFE`.
2. Each code channel is listed as a capability and makes the verdict
   `NEEDS_REVIEW` with exit 10: a script, a file under `bin/`, a
   `` !`cmd` `` line, `allowed-tools` in frontmatter, a `hooks.json`.
3. An empty package, a package with an unreadable binary, and a package with a
   symlink pointing outside it all report incomplete coverage and
   `NEEDS_REVIEW`.
4. Uppercase-literal patterns match, a phrase split across two lines matches,
   and a single zero-width character or a Cyrillic look-alike inside a word is
   caught.
5. Exit codes follow `docs/architecture.md`: the benign fixture exits 0
   `LIKELY_SAFE`, the nasty fixture exits 20 `UNSAFE`, `--help` exits 0.
6. Default output (JSON and `--text`) carries no attacker text; `--excerpts`
   shows it.
7. `--quarantine` no longer writes a copy anywhere; the old `jev-scan` entry
   point forwards to `canary scan` and refuses `--quarantine`.
8. `scanner/references/checks.md` describes the implemented catalog,
   capabilities, coverage and scoring, and records the calibration decision
   with before/after numbers from a real library.
9. The tests run with `python3 -m unittest discover -s tests` and pass; a
   deliberate break of the capability rule and of the no-dampening rule each
   turns a named test red.

Not in this slice: layer 2, `canary add`, hooks, managed settings, the
GitHub Action (owned by `program/2026-09-26-paid-launch`, which must rebase on
this scanner before publishing).
