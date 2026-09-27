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

## Slice 2: isolated classifier (`canary check`)

Done when:

1. `canary check <path>` runs layer 1, then layer 2, then the combiner, and
   exits 0, 10, 20, 2 or 3 as `docs/architecture.md` fixes.
2. Every file reaches the model inside fences carrying a per-run random nonce;
   a forged closing marker and a marker-like file name stay inside the fence
   (`UntrustedTextStaysInsideNonceFences`).
3. A backend error, prose, trailing text, an extra key, a wrong type, an
   unknown verdict, `SAFE` below confidence 0.7 and a category with markup
   each give `NEEDS_REVIEW`; one wrapping ```` ```json ```` fence is accepted.
4. Layer 2 never loosens a verdict: layer-1 `UNSAFE` plus a confident `SAFE`
   stays `UNSAFE`, and a deliberate downgrade turns that named test red.
5. Default JSON and `--text` output carry no model evidence, reasoning or
   summary; `--excerpts` shows them; the raw answer is logged with mode 0600.
6. Above 256 KiB of fenced text layer 2 does not run and the verdict is
   `NEEDS_REVIEW`; nothing is truncated.
7. With no backend the verdict is `NEEDS_REVIEW` with status `unavailable`.
8. The `claude` backend passes the isolation flags, runs in a fresh empty
   directory that is removed afterwards, and sends the skill on stdin; the
   absence of `CLAUDE.md` was verified live against a positive control and
   is recorded in `docs/architecture.md`.
9. The `anthropic_api` backend sends only the system prompt and one user
   message, with no tools; its errors never contain the key.
10. Live, through the `claude` backend: the benign fixture is `LIKELY_SAFE`
    and the nasty fixture is `UNSAFE` with a schema-valid answer.
11. `scanner/SKILL.md` and `references/classifier-prompt.md` no longer tell an
    agent to paste a skill into a subagent and no longer say "Jev"; both scan
    `LIKELY_SAFE`.
12. `python3 -m unittest discover -s tests` passes.

## Slice 3: `canary add`

Done when:

1. `canary add <link>` accepts a GitHub repository, `tree` folder or `blob`
   SKILL.md link and a local folder; it resolves the ref to a commit SHA
   before downloading, and records that SHA.
2. An archive with a symlink, hard link, device, `..` or absolute member is
   refused whole: nothing installed, nobody asked, quarantine removed
   (`HostileArchivesAreRefusedWhole`).
3. `UNSAFE` installs nothing and never calls the approver; a decline installs
   nothing and writes no lockfile; the CLI has no flag that approves
   (`OnlyThePersonInstalls`).
4. An approved install puts a real copy (no links) in each detected host's
   root and records commit and `package_digest` in
   `~/.agents/.canary-lock.json`; a package changed after its check is not
   installed; an existing skill is never overwritten
   (`ApprovedInstallsAreTheCheckedBytes`).
5. The agent-facing result carries no package text: a hostile frontmatter
   name falls back to the folder name, the dialog omits the package's
   description, and a multi-skill link reports only a count
   (`TheAgentSeesNoPackageText`).
6. Deliberate breaks of the re-digest, the link refusal and the UNSAFE rule
   each turn their named test red.
7. Live: a real GitHub link fetches, pins a SHA, checks, asks, and leaves
   nothing behind when declined. The dialog script compiles; showing it on
   screen is left to the owner or the VM lifecycle tests.
8. `python3 -m unittest discover -s tests` passes.

## Slice 4: enforcement (`canary hook`, `setup`, `doctor`)

Done when:

1. `canary hook --host claude|codex` denies writes into (or above) every
   protected location, reads of the quarantine, and installer commands, with
   the right contract per host (Claude Code: exit 2 with stderr; Codex: deny
   JSON at exit 0), and allows ordinary work, including compound commands
   that name no protected location (`tests/test_gate.py`).
2. Garbage, missing fields and internal errors deny; deliberate breaks (a
   crash exiting 3, no text screening, a Codex deny at exit 2) turn named
   tests red.
3. Live: real Claude Code with the hook blocks a Write into a project
   `.claude/skills` and allows an ordinary Write.
4. `canary setup --level guard` installs Canary and both hooks through one
   privileged script that checks its payload's SHA-256; a changed payload
   installs nothing (`tests/test_setup.py`, run for real under a temporary
   prefix).
5. Scan asks for no password; an administrator's existing Codex
   `requirements.toml` is never overwritten and becomes a printed manual
   step; going back to Scan removes only unchanged files Canary created.
6. Lockdown locks both user skill roots; `canary add` then installs only a
   copy the root-owned `canary digest` confirmed inside the administrator
   step, and a package changed before that step is not installed.
7. `canary doctor` reports a writable install, a missing hook and an
   unlocked Lockdown root as gaps, and prints the claim for the level only
   when there are none.
8. The suite passes on Python 3.10 and on macOS's `/usr/bin/python3` (3.9).

Not verified on this Mac by design: the real administrator dialog, real root
ownership, and Claude Code and Codex reading the installed managed policy.
Those belong to the VM lifecycle tests.
