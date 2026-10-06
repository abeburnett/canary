# Program 2026-10-06: plain flags and clean records

Status: approved by the owner on 2026-10-06. He approved the three proposals
from the 2026-10-05 marketing-skills install report (relayed by the "Install
marketing skills" session) and settled two questions in this session:

- **Owner decision 1 (context labels):** a hit in a code example, or on a line
  that warns against what it quotes, gets a *label only*. Its score and the
  verdict do not change. The no-dampening rule from program 2026-09-26 stands:
  attack patterns are never scored lower, because an attacker could wrap a real
  payload in a code block or a "never do this:" line.
- **Owner decision 2 (refuter):** Muse Spark 1.3 Contributor refutes this
  contract and reviews the diffs.

Branch `program/2026-10-06-plain-flags`, based on `main` at `a2c30a1`. Baseline:
`python3 -m unittest discover -s tests` runs 217 tests, OK, in 56 s.

Out of scope, by the architecture rule that package text never reaches an
agent or the dialog: excerpts or file names in the approval dialog, and any
model-written reading of a single hit.

## Why

On 2026-10-05, 50 marketing skills went in through `canary install`. Two
problems showed up:

1. **Old records blocked a reinstall.** A first install went to a scratch
   project. Its folders were deleted, but the 50 records in
   `~/.agents/.canary-lock.json` stayed. The global reinstall was refused
   twice: "Something with the same name was installed meanwhile". `canary
   list` did not show the records, no command could clear them, and the hook
   (correctly) kept the agent from editing the file. The owner had to fix the
   file by hand. The refusal in `canary add` also tells people to run `canary
   update`, which does not exist.
2. **Flags read as "holy shit, oh no — but then what?"** (the owner's words).
   The output led with "Threat patterns found (EXFILTRATION), score 3" even
   though the AI review said safe at 0.93, and every hit turned out to be
   documentation or a defensive rule. Nothing said what a rule looks for, why
   it matters, or what to do next.

A third, small one: the hook's block message for an installer mentioned in a
heredoc did not say how to write such a file.

## Current behavior (verified at `a2c30a1`)

- `canary/install.py:313-316`: inside the commit lock, refuses when any staged
  destination exists **or any staged name is a key in `lock["skills"]`**. It
  never checks whether that record's `installed` paths still exist, or where
  they are.
- `canary/add.py:511` and `:547`: the same name-only check; the messages say
  "use canary update to replace it" (no such command; `canary/cli.py` USAGE).
- The lockfile (`docs/architecture.md`, "Lockfile"; the `plugins` map is written only by `install.py:490`) is
  `{"schema": "canary.lock/1", "skills": {"<name>": {...}}, "plugins": {...}}`,
  keyed by bare name, so a project install and a global install of one name
  cannot both be recorded. Readers and writers: `add._read_lock`,
  `add._write_lock`, `add._finish`, `install.py:313-346` and `:490-495`.
  `gate.py:171` only protects the file.
- `canary list` reads the guest list, not the lockfile, so lock records never
  show there.
- `scan.scan_package` reasons: `"Threat patterns found (CATS), score N."`,
  `"Scan incomplete: …"`, `"Runs code or grants tools (…); a person must
  approve it."`, `"Nothing to scan: …"`. `classify._combine` adds the
  classifier reasons (unavailable, too large, failed or invalid, UNSAFE,
  NEEDS_REVIEW, not confident). The classifier only tightens; it never loosens
  a pattern verdict.
- `catalog.py`: attack patterns are never dampened; only `doc` patterns are,
  by `DOC_CONTEXT` on the same line.
- `--excerpts` exists on `scan` and `check` and is documented as "for a
  person's terminal, never an agent", but nothing enforces that.
- `gate.decide` allows every genuine `canary …` command (`_is_canary`) before
  any other rule.

## Design

### 1. Lock records know where they are

Refutation round 1 (Spark, 2026-10-06) replaced a "user or project scope"
design that broke for plugins, odd install locations and extra skill roots.

- **Places.** A skill record's *places* are the skills folders its installs
  sit in: for each path in `installed`, the realpath of the path's parent
  folder (the folder holding the link or folder itself, never a symlink's
  target). New records store them as `"places": [...]` (sorted) and also store
  `"name": "<name>"`, both computed once when the record is written. An older
  record has neither field: its name is its key, and its places are computed
  from its `installed` paths when it is read. Code never parses a key to find
  a name or place. The schema string stays `canary.lock/1`; the fields are
  additive. Plugin records (`lock["plugins"]`) are not changed by this design:
  their `scope` field keeps its meaning and they get no conflict check.
- **Live and dead.** An installed path is live when `os.path.exists` is true
  for it (a symlink whose target is gone is not live). A record is *live* when
  at least one of its `installed` paths is live, and *dead* otherwise,
  including when `installed` is empty or missing. Skill and plugin records
  both follow this rule.
- **Conflicts.** A new skill install conflicts with a record only when the
  record is a live skill record, its name equals the new name, and its places
  share at least one folder with the new install's places. A dead record never
  blocks. A project install and a user install of one name therefore never
  conflict. The destination check (`os.path.lexists` on every destination)
  stays exactly as it is.
- **Keys.** The new record goes under the bare name when that key is free or
  holds a dead record (which it replaces). When the bare name holds a live
  record in other places, the new record goes under
  `"<name>@<first 12 hex characters of sha256 of its places joined by newlines>"`;
  if that key holds a live record too, the install is a conflict (same name,
  same places). Dead records under other keys are left for `canary doctor`.
- **Refusals name what is in the way.** Exact strings. `<paths>` lists the
  record's live `installed` paths, shortened with `~` the way the `installed`
  output already does, joined with ` and `; `<date>` is the `YYYY-MM-DD` part
  of `installed_at` (drop ` (recorded <date>)` when it is missing or not a
  string); `<them>` is `that folder` for one path and `those folders`
  otherwise:
  - live record: `A skill named <name> is already installed at <paths>
    (recorded <date>). Nothing was installed. To replace it, remove <them>
    and run this again.`
  - a destination exists with no live record: `<path> already exists.
    Nothing was installed. To replace it, remove it and run this again.`
  - the same conditions found again inside the commit lock use the same
    strings. No output, docs or skill text mentions `canary update`, except
    the historical `docs/program-*.md` files, which stay as they are.
- **Records found by `canary doctor`.** A new function
  `setup.old_records(home)` returns the dead records as
  `[{"kind": "skill"|"plugin", "key": …, "name": …, "installed": [...]}]`,
  skills first, each group sorted by key. `setup.doctor` keeps its signature
  and its 3-tuple return (tests and `e2e/lifecycle.py` unpack it). An
  unreadable lockfile raises `add.LockError`; a missing one has no records.
- **`canary doctor`** (text) prints, after the gaps and only when there are
  old records:

  ```
  Old install records: <n> (their folders are gone)
    <name>  <first installed path, shortened, or "(no path recorded)">
  Run canary doctor --prune to remove them. It asks you first.
  ```

  `canary doctor --json` adds `"old_records"` (an empty list when there are
  none). Old records never count as gaps or change the exit code. An
  unreadable lockfile prints `canary: <LockError message>` to stderr and
  doctor otherwise runs as before.
- **`canary doctor --prune`** calls a new `setup.prune_records(home=None,
  approve=None)`. It reads the old records; with none it prints `No old
  install records.` and exits 0 without a dialog. Otherwise it calls
  `approve(text)` with the dialog text below; the default `approve` is
  `lambda text: add.ask(text, "NEEDS_REVIEW", yes="Remove records")`, so
  Cancel is the default button. On `True` it takes `add._Commit(home)`,
  re-reads the lockfile, removes only the records that are still dead,
  writes it with `add._write_lock`, and prints `Removed <n> old install
  records.` (exit 0). On `False` or `None` it prints `Nothing removed: the
  person did not agree in SkillCanary's dialog.` (exit 10). An unreadable
  lockfile prints `canary: <message>` and exits 3. `doctor` accepts exactly
  `[]`, `["--json"]` or `["--prune"]`; anything else prints usage and exits 2.
  `--prune` prints only the prune result, not the level or gaps. Dialog text
  (at most 20 lines of records, then `- and <k> more`):

  ```
  SkillCanary has <n> install records for skills or plugins whose files are gone:
  - <name> (<first installed path, shortened>)
  ...
  Removing them lets you install these names again. It does not change any
  skill or plugin on this Mac.

  The names come from the packages, not from SkillCanary.
  ```

### 2. Flags in plain language

A new pure module, `canary/explain.py`, holds every string this section adds.
All of it is Canary's own text: no package text, no model text.

- **One entry per rule.** `RULES[check_id] = (label, looks_for, why)` for
  every `check_id` in `catalog.CHECKS` and `catalog.EXTRA`, with exactly the
  text in the table below. A test asserts that the key set equals the
  catalog's ids, so a new rule cannot ship without its text.

  | check_id | label | looks for | why it matters |
  |---|---|---|---|
  | instruction-override | overriding the agent's instructions | Phrases that tell the agent to ignore or replace its instructions, such as "ignore previous instructions". | A skill that does this can take over the agent. Defensive skills sometimes quote these phrases to warn against them. |
  | identity-rewrite | giving the agent a new role | Phrases such as "you are now a…" or "adopt the persona of". | A new role can switch off the agent's usual care. Persona and role-play skills use these phrases on purpose. |
  | safeguard-bypass | skipping approvals or safety checks | Phrases that tell the agent to skip confirmation, approvals, the sandbox or hooks. | The agent could then act without asking you. Tool documentation sometimes describes such options without asking the agent to use them. |
  | exfiltration | sending data to an outside address | Commands or instructions that send data to a web address, such as a curl upload or a chat webhook. | This is how a skill could copy your files or secrets off this Mac. API documentation also shows upload commands, usually to the vendor's own address. |
  | shell-pipe | running a downloaded script | A download piped straight into a shell, such as curl … \| sh. | The script runs without anyone reading it, and it can change after the check. Install guides often show this pattern. |
  | credential-access | reaching for passwords or keys | SSH keys, cloud credentials, the keychain, .env files, or passwords together with reading or sending them. | A skill that reads credentials can misuse or leak them. Setup guides mention these files when they explain configuration. |
  | persistence | staying on after the session | Instructions to add launch agents, cron jobs or login items, or to edit agent settings or other skills. | A skill that installs itself elsewhere keeps running after you remove it. |
  | stealth | hiding actions from you | Phrases that tell the agent not to tell you what it does. | Hiding actions takes away your chance to say no. Legitimate skills rarely need it. |
  | prompt-leak | revealing the agent's prompt | Phrases that ask the agent to print its system prompt or instructions. | A leaked prompt can expose private instructions. Prompt-writing guides discuss this as an attack to defend against. |
  | obfuscation | encoded text | Long base64 text. | Encoded text can hide instructions a reader cannot see. Embedded images and keys also look like this. |
  | invisible-character | invisible characters | Zero-width, bidirectional or tag characters inside words. | Invisible characters can hide instructions or change what a word means. |
  | mixed-script-word | look-alike letters | Words that mix Latin letters with Cyrillic or Greek look-alikes. | Look-alike letters can disguise a web address or command as a familiar one. |
  | external-url | web addresses | Links to outside web pages. | Recorded only: links alone never change the verdict. |

- **Context labels (label only, owner decision 1).** Every finding in
  `scan.scan_package` gains `"context"`: `"code_example"`, `"forbidding"` or
  `null`. It is a fixed value Canary computes, so it appears in default (agent)
  output too.
  - `code_example`: the finding's line is inside a fenced code block of the
    same file, decided on the raw lines (before `scan.normalize`). An opening
    fence is a line of at most three leading spaces (no tabs), then three or
    more backticks or three or more tildes, then anything. The block closes at
    the next line of at most three leading spaces, then at least as many of the
    same character, then only whitespace. A block that never closes runs to
    the end of the file. Fence lines themselves are outside. A paragraph-pass
    finding uses its start line.
  - `forbidding`: otherwise, when the finding's line, lowercased after
    `scan.normalize`, matches
    `\b(never|do not|don't|must not|should not|refuse to|reject|watch for|look out for|beware of)\b`.
  - `null` otherwise.
  - The label never changes `severity`, `score`, `threat_verdict` or
    `verdict`. A test puts the same attack line inside and outside a code
    block, and on a "never" line, and asserts identical score and verdict; the
    existing no-dampening test stays as it is.
  - `CONTEXT[label]` text:
    - `code_example`: `Inside a code example. Examples are often documentation, but a skill can still tell the agent to run them.`
    - `forbidding`: `On a line that warns against it. Skills sometimes quote a phrase to forbid it; read the line to be sure.`
- **The headline leads with the combined judgment.**
  `explain.headline(check, confident)` takes a `canary.check/1` result and the
  classifier's confidence decision, and returns one sentence. `classify.check`
  computes `confident` once (as `_layer2` does today, with `Decimal`), passes
  it in, and stores the sentence as `result["headline"]`; the `confident` flag
  itself stays out of the output. Rules, first match wins:
  1. `verdict == "UNSAFE"` and the classifier verdict is `UNSAFE`:
     `SkillCanary judged this skill unsafe: the AI review found it unsafe.`,
     and when there are scored findings, ` The pattern scan also found <labels>.`
  2. `verdict == "UNSAFE"`: `SkillCanary judged this skill unsafe: the pattern scan found <labels>.`
  3. `verdict == "LIKELY_SAFE"`: `No problems found: the pattern scan and the AI review both passed it.`
  4. Only the pattern rules raised the verdict: classifier status `ok`,
     classifier verdict `SAFE`, `confident` true, coverage complete, no
     capability in `scan.REVIEW_CAPABILITIES`, and `threat_verdict ==
     "NEEDS_REVIEW"`:
     `The AI review judged this skill safe (<confidence, 2 decimals>). The pattern scan flagged <labels> for you to look at.`
  5. Otherwise: `This skill needs your judgment.`

  `<labels>` is the RULES labels of the checks with at least one scored finding
  (severity not `info`), deduplicated, ordered as `catalog.CHECKS` then
  `catalog.EXTRA`, joined as `a`, `a and b`, `a, b and c`, `a, b, c and d` and
  so on (commas, then `and` before the last).
- **A next step for every review reason.** `explain.next_steps(check,
  confident, flow)` returns the steps for the reasons that keep the verdict
  at `NEEDS_REVIEW`, in reason order, without duplicates, and an empty list
  for any other verdict. `flow` is `"check"` (also used by `canary add`) or
  `"install"`. `classify.check` stores the `"check"` steps as
  `result["next_steps"]`; `canary install` asks for its own. Steps are
  derived from the structured result (`scan.threat_verdict`,
  `scan.coverage`, `scan.capabilities`, `classifier.status`,
  `classifier.verdict`, `confident`), never by parsing reason strings. Exact
  text:
  - pattern hits, flow `check`: `Look at the flagged lines: run canary explain with the same link or folder in your own terminal. Install it if they are only documentation; skip it if they tell the agent to do something you did not ask for.`
  - pattern hits, flow `install`: `To look at the flagged lines first, choose Cancel, then run canary explain on the skill's GitHub link or folder in your own terminal. Install it if they are only documentation; skip it if they tell the agent to do something you did not ask for.`
  - scan incomplete (entries not read): `Some files could not be read, so the check is incomplete. Install it only if you trust where it came from.`
  - nothing to scan (no readable text): `SkillCanary found no readable text in it, so there was nothing to check. Skip it unless you know why it is empty.`
  - runs code or grants tools: `It runs code or grants tools, so it needs your approval whatever the scan found. Install it only if you trust where it came from.`
  - classifier unavailable: `To add the AI review, sign in to Claude Code or set ANTHROPIC_API_KEY or OPENAI_API_KEY, then check it again.`
  - classifier too large: `The AI review reads only skills under 256 KB. Look at the flagged lines with canary explain, or install it only if you trust where it came from.`
  - classifier failed or invalid: `Check it again. If the AI review keeps failing, decide from the pattern scan with canary explain.`
  - classifier asked for review, or said safe without enough confidence: `The AI review wants a person to look. Run canary explain with the same link or folder in your own terminal to see what it noticed.`

  A test builds one result per reason family and asserts each gets exactly its
  step, so a new review reason cannot ship without one.
- **Where the headline and steps appear.**
  - `classify.render_text`: the line after `Verdict:` is the headline; the
    existing reasons follow unchanged; then, when there are steps, a
    `What you can do:` line and the steps as `  - ` bullets.
  - `scan.render_text` (`canary scan`, pattern scan alone): unchanged except
    that a finding line with a context ends with ` [code example]` or
    ` [warns against it]`.
  - `canary add` results gain `"headline"` and `"next_steps"` (from the check).
    `canary install` keeps each checked item's `headline` and its
    install-flow steps (from `_check_all`'s results); each entry of its
    result's `skills` gains `"headline"`, and the result gains `"next_steps"`,
    the union of the items' steps in item order. `reasons` keeps its current
    content in both, so nothing that reads it breaks.
  - `add.dialog_text`: the headline is the second paragraph, after the first
    line; the capabilities and the reasons stay as they are (including the
    existing filter that drops the "Runs code or grants tools" reason); then
    `What you can do:` and the steps as `- ` lines; then the labelled source
    lines as today.
  - `install.dialog_text`: under each listed skill that is not
    `LIKELY_SAFE`, after its existing lines, one line `    <headline>`;
    after the list, `What you can do:` and the union of steps as `- ` lines;
    then `Into:`, the command and the label as today. The install dialog
    still shows no reasons.
  - The SkillCanary skill (`frontdoor.SKILL_TEXT` and `skills/canary/SKILL.md`,
    which a test keeps identical) tells agents to relay the headline, then the
    reasons and the steps; adds `explain` to the command list as a command
    for the person only ("Never run canary explain or --excerpts yourself;
    give the person the command to run in their own terminal."); and mentions
    `canary doctor --prune` for old install records.
- **Package text stays in the person's terminal.** `canary explain`, and the
  existing `--excerpts` flag on `canary scan` and `canary check`, print the
  skill's own text, so:
  - The CLI refuses them when `cli._stdout_is_terminal()` (a module function
    returning `sys.stdout.isatty()`) is false: `canary <command> shows the
    skill's own text, so it runs only in your own terminal.` on stderr, exit
    2, before any fetch or scan. There is no environment variable or flag
    that skips this. In-process tests patch the function; the subprocess test
    in `tests/test_scan.py` (`test_default_output_omits_the_payload_and_excerpts_flag_shows_it`)
    is granted ownership to run its `--excerpts` arm with standard output on
    a pseudo-terminal (`pty.openpty`), expected outcome unchanged.
  - The hook denies an agent's shell command, **before** the `_is_canary`
    allowance, when its tidied text (`installers.tidy`) matches
    `\bcanary\s+explain\b` or contains both `\bcanary\b` and
    `--excerpts\b`. A command that only mentions them is denied too, like
    the installer rule. Message, filling in the arguments when the command
    is a plain `canary explain …` that `shlex` can split (otherwise use
    `<link or folder>`): `canary explain shows the skill's own text, which is
    for the person, not an agent. Give the person this command to run in
    their own terminal: canary explain <arguments>`.
  - Accepted limit, recorded in `docs/architecture.md`: an agent that runs
    Canary's Python code directly, or assembles the command from pieces,
    gets past both checks, as with installers; the terminal check stops an
    agent's ordinary shell, and the hook stops the command by name.
- **`canary explain <link-or-folder> [--backend <name>] [--model <id>]
  [--timeout <seconds>]`**, text only, for the person.
  - Order: the terminal check; argument validation as `canary check`; then,
    for a GitHub link, `add.parse_source` and `add`'s own fetch and
    extraction into a new folder `quarantine/explain-<run id>` under the
    support folder, mode `0700`, removed in a `finally`; no new network
    code. A local folder is checked in place.
  - It runs `classify.check(path, excerpts=True, …)` and prints these
    sections in order, each omitted when empty:
    1. `Verdict: <verdict>` and the headline on the next line.
    2. For each scored check, in label order: the label as a heading line,
       `  What it looks for: …`, `  Why it matters: …`, then each finding as
       `  <path>:<line>  <excerpt repr>`, followed by `    <CONTEXT text>`
       when it has a context.
    3. `What it can do:` and the capabilities as `- It <add.PLAIN text>.`
    4. `Not read:` and each skipped entry as `- <path> (<reason>)`.
    5. `AI review: <status>`, and for status `ok`
       `, said <verdict> at confidence <0.00>`, then its findings as
       `check --excerpts --text` prints them, and its summary.
    6. `What you can do:` and the steps.
    Exit codes match `canary check`; a bad link prints `canary: <message>`
    and exits 2.
  - `canary --help` lists `canary explain <github-link-or-folder> [--backend
    <name>] [--model <id>] [--timeout <seconds>]` and `canary doctor [--json
    | --prune]`.

### 3. The hook's installer message

`gate.REDIRECT` gains one sentence at the end: `To write a file that only
mentions an installer, use your file-editing tool (Write or Edit in Claude
Code, apply_patch in Codex), not the shell.`

### The Action manifest

`scripts/action.py` refuses a bundle whose `canary/*.py` files do not match
`scanner/manifest.json`. Each slice commit that changes `bin/` or `canary/`
runs `python3 scripts/update-manifest.py <the slice's base commit>` and
commits the regenerated manifest; `tests/test_action.py` must pass.

### Documentation

`docs/architecture.md` describes the lock record fields (`name`, `places`),
live and dead records, the conflict and key rules and the refusal strings
(section "Lockfile" and the `canary add` / `canary install` steps); `canary
doctor` old records and `--prune`; the `context` field and that it never
changes a score; the `headline` and `next_steps` fields; `canary explain`,
the terminal rule for `explain` and `--excerpts`, the hook rule and its
accepted limit; and the new REDIRECT sentence. `scanner/references/checks.md`
notes the labels and that the no-dampening rule is unchanged.

## Refutation round 2 rulings

Spark round 2 (2026-10-06) checked the fold. These rulings are senior to the
design text above wherever they differ.

1. **Keys, complete.** Compute the new install's places with the same rule
   as a record's: for each destination (for `canary add`, each host
   destination; for `canary install`, every path in `taken`, folders and
   links), `os.path.realpath(os.path.dirname(path))`. Then, in order: if any
   live skill record with the same name shares a place, it is a conflict
   (this covers a live record under the bare key in the same places); else
   if the bare-name key is free or holds a dead record, use the bare name
   (replacing it); else use the hashed key
   `name + "@" + sha256("\n".join(sorted(places)).encode("utf-8")).hexdigest()[:12]`,
   replacing a dead record there too. Both the check before the dialog
   (`add.py:511`) and the checks inside the commit lock (`add.py:547`,
   `install.py:314`) use this rule and the same refusal strings.
2. **Malformed records.** A record whose `installed` is not a list, or that
   contains anything other than non-empty strings, is dead for conflicts,
   is listed by `old_records` with `installed` as `[]`, and is prunable. A
   record value that is not a dict is treated the same way. Nothing in this
   program raises on a malformed record.
3. **Install-flow steps.** For `flow == "install"`, every step that mentions
   `canary explain` uses these exact texts instead:
   - pattern hits: `To look at the flagged lines first, choose Cancel, then run canary explain on the skill's GitHub link (for npx skills add owner/repo, that is https://github.com/owner/repo) or folder in your own terminal. Install it if they are only documentation; skip it if they tell the agent to do something you did not ask for.`
   - classifier too large: `The AI review reads only skills under 256 KB. To look at the flagged lines, choose Cancel and run canary explain on the skill's GitHub link or folder in your own terminal, or install it only if you trust where it came from.`
   - classifier failed or invalid: `Try the install again. If the AI review keeps failing, choose Cancel and run canary explain on the skill's GitHub link or folder in your own terminal.`
   - classifier asked for review, or not confident: `The AI review wants a person to look. Choose Cancel and run canary explain on the skill's GitHub link or folder in your own terminal to see what it noticed.`
   The other families use the same text in both flows. `install.py` keeps
   each item's `confident` decision from its check (the same `Decimal` rule
   as `classify`), so it can call `explain.next_steps(result, confident,
   "install")`. `classify` exposes `confident` to callers without adding it
   to the JSON output (for example a private `_check(...) -> (result,
   confident)` that `check` wraps).
4. **Terminal refusals, exact.** `canary scan --excerpts shows the skill's own
   text, so it runs only in your own terminal.`, the same with `canary check
   --excerpts`, and `canary explain shows the skill's own text, so it runs
   only in your own terminal.` Unknown flags on `explain` (including
   `--json`, `--text` and `--excerpts`) print usage and exit 2; the terminal
   check comes first.
5. **Hook messages, exact.** For a command matching the explain pattern:
   `canary explain shows the skill's own text, which is for the person, not
   an agent. Give the person this command to run in their own terminal:
   canary explain <arguments>`. For the `--excerpts` pattern: `--excerpts
   shows the skill's own text, which is for the person, not an agent. Give
   the person this command to run in their own terminal: canary explain
   <arguments>`. `<arguments>` is filled only when the original command
   (not `tidy()` output) contains none of `gate.SHELL_SYNTAX` or
   `installers.COMPOUND`, `shlex.split` succeeds, and the tokens are
   `canary` (or a path ending in `/canary`), then `explain`, `scan` or
   `check`, then exactly one argument that does not start with `-` plus only
   known flags; it is that one argument, quoted with `shlex.quote`.
   Otherwise it is the literal `<link or folder>`. Both patterns are
   case-sensitive. A command that only mentions them, such as
   `git log --grep="canary explain"`, is denied, like the installer rule;
   `docs/architecture.md` records this.
6. **`classify.render_text` order:** `Canary check: …`, `Verdict: …`, the
   headline, the reasons, the `Classifier:` line and its findings and
   summary, then `What you can do:` and the steps as `  - ` lines, then a
   blank line and the scan block.
7. **`canary explain` details:** section 3 lists only capabilities with
   `add.PLAIN` text (as the dialogs do); section 5 prints the summary as
   `  Summary: <summary>`; every bullet in explain uses `- ` at the section's
   indent.
8. **Doctor wiring.** `cli._doctor` calls `setup.doctor()` unchanged, then
   `setup.old_records(home)` with `home = os.path.expanduser("~")`.
   `setup.old_records(home=None)` and `setup.prune_records(home=None,
   approve=None)` both resolve `None` to `~`. All `canary:` errors go to
   stderr. `approve` counts as yes only when it returns `True`. A record with
   no path shows `(no path recorded)` in the prune dialog too.
9. **Copy.** Paths in refusals join like labels (`a`, `a and b`, `a, b and
   c`). When the date is dropped, the sentence keeps its full stop. Use
   "folders" everywhere for what is gone (doctor and the prune dialog), and
   singular forms when n is 1: `Old install records: 1 (its folder is gone)`,
   `Removed 1 old install record.`, `SkillCanary has 1 install record for a
   skill or plugin whose folders are gone:`. `add.dialog_text`: the headline
   paragraph is followed by one blank line. The skill's command-list entry
   is exactly: `explain (for the person only: never run canary explain or
   --excerpts yourself; give the person the command to run in their own
   terminal)`.
10. **Ruleset hash.** Changing `canary/scan.py` changes
    `evidence.ruleset_sha256()` by design (`canary/evidence.py`, the comment
    on `RULESET_FILES`). Tests compute it, so they stay green; record the
    change in the slice P commit message.
11. **The hook blocks the builder too.** In this checkout's sessions the
    installed SkillCanary hook denies shell commands whose text mentions an
    installer, `canary explain` or `--excerpts`. Write test fixtures and
    files containing those words with the file tools, never with a heredoc
    or `echo`.

## Done when

1. A dead lock record never blocks `canary install` or `canary add`; a new
   install under a dead record's key replaces it. Named tests in
   `tests/test_install.py` and `tests/test_add.py` each go red when the dead
   check is removed.
2. A project install and a user install of the same name both succeed, in
   either order, and both records stay in the lockfile with their `name` and
   `places`; an older record without those fields still conflicts correctly.
3. A live conflicting record still blocks, with the exact refusal above
   naming its live paths and date. Outside the historical `docs/program-*.md`
   files, no output, docs or skill text mentions `canary update`.
4. `canary doctor` lists dead skill and plugin records in text and JSON
   without changing its exit code or `setup.doctor`'s return; `canary doctor
   --prune` removes only still-dead records after the person says yes, and
   nothing on a decline or with no dialog.
5. Every catalog check id has its RULES text, verified by a test that fails
   when a check id is added without text.
6. Findings carry `context`; the same attack line inside and outside a code
   block, and on a "never" line, gives identical score and verdict; the
   no-dampening test still goes red when dampening is allowed for attack
   patterns.
7. `canary check` results carry `headline` and `next_steps` per the rules
   above; a test per headline rule and per reason family pins the exact text.
8. The add and install dialogs show the headline(s) and `What you can do:`
   with the steps; no excerpt, file name or model text appears in them, and
   the install dialog still shows no reasons.
9. `canary explain` prints the layout above for a local folder; `explain` and
   `--excerpts` refuse without a terminal (exit 2) before any fetch or scan;
   the hook denies both by name before the canary allowance, in Claude and
   Codex payloads.
10. REDIRECT ends with the new sentence.
11. `frontdoor.SKILL_TEXT` and `skills/canary/SKILL.md` match and describe the
    headline, the steps, `canary explain` (person only) and `doctor --prune`;
    `docs/architecture.md` and `scanner/references/checks.md` describe the
    new behavior; `scanner/manifest.json` matches the bundle.
12. `python3 -m unittest discover -s tests` passes on the program branch's
    head, with the count reported; for each of bullets 1, 2, 4, 6, 7 and 9, a
    deliberate break turns a named test red while its neighbours stay green,
    captured as raw per-case logs.

## Plan

1. Refute this contract (Spark 1.3 Contributor, read-only, `max`) against the
   worktree it will run in; fold the findings. Round 1 done (10 blocking, 13
   major, folded above); round 2 checks the fold.
2. Slice L (records, bullets 1-4 and 10) then slice P (plain flags, bullets
   5-9 and 11), built by one Sonnet 5.5 worker in one disposable worktree,
   each slice its own commit after the full suite passes.
3. Spark reviews the finished diff; the builder folds; the coordinator
   re-checks the fold.
4. Full suite on the program head, then the done-when audit (an Opus subagent
   with fresh context).
5. The owner decides on push, pull request and merge.
