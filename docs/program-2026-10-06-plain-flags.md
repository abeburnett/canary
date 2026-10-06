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
- The lockfile (`docs/architecture.md`, "Lockfile") is
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

- **Scope.** A record's scope is `"user"` when every path in its `installed`
  list is inside one of `guestlist.user_roots(home)` (compare realpaths, and
  for a symlink compare the link's own location, not its target). Otherwise
  its scope is the project folder: the realpath of the parent of the skills
  folder's parent (for `/p/.agents/skills/x` that is `/p`). A record with an
  empty `installed` list, or paths in more than one scope, has scope `None`.
- **Keys.** New records are keyed by the bare name in user scope (unchanged)
  and by `"<name>@<project folder>"` in project scope. Every new record also
  stores `"name": "<name>"` and `"scope": "user"` or the project folder.
  Existing records have neither field: their name is their key, and their
  scope comes from their `installed` paths. The schema string stays
  `canary.lock/1`; the new fields are additive.
- **Live and dead.** A record is *live* when at least one of its `installed`
  paths exists (`os.path.lexists`). Otherwise it is *dead*. Plugin records
  (`lock["plugins"]`) follow the same rule.
- **Conflicts.** A new install conflicts with a record only when the record is
  live, has the same name, and has the same scope. A dead record never blocks
  an install. When the new record's key equals a dead record's key, the new
  record replaces it. Dead records under other keys are left for `canary
  doctor`. The destination check (`os.path.lexists` on every destination)
  stays exactly as it is.
- **Refusals name what is in the way.** Exact strings, with `<path>` the
  record's first live `installed` path shortened with `~` as the
  `installed` output already does, and `<date>` the record's `installed_at`
  date (`YYYY-MM-DD`; omit the parenthesis when it is missing):
  - live record: `A skill named <name> is already installed at <path>
    (recorded <date>). To replace it, remove that folder and run this again.`
  - a destination exists with no live record: `<path> already exists. To
    replace it, remove it and run this again.`
  - the same conditions found again inside the commit lock use the same
    strings. No message mentions `canary update`.
- **`canary doctor` reports dead records.** Text output gains a section after
  the gaps, only when there are dead records:

  ```
  Old install records: <n> (their folders are gone)
    <name>  <first installed path, shortened>
  Run canary doctor --prune to remove them. It asks you first.
  ```

  `--json` gains `"old_records": [{"kind": "skill"|"plugin", "key": …,
  "name": …, "installed": [...]}]` (an empty list when there are none). Old
  records do not count as gaps and do not change doctor's exit code.
- **`canary doctor --prune`** lists the dead records, asks the person in
  SkillCanary's dialog (`add.ask`, verdict `"NEEDS_REVIEW"` so Cancel is the
  default, yes button `Remove records`), and on yes removes them inside
  `add._Commit(home)` after re-reading the lockfile, removing only records
  that are still dead at that moment. Dialog text:

  ```
  SkillCanary has <n> install records for skills whose folders are gone:
  - <name>
  ...
  Removing them lets you install skills with these names again. It does not
  change any skill on this Mac.

  The names come from the packages, not from SkillCanary.
  ```

  (List at most 20 names, then `- and <k> more`.) Output: `Removed <n> old
  install records.` (exit 0), `Nothing removed: the person did not agree in
  SkillCanary's dialog.` (exit 10, for a decline or no dialog), or `No old
  install records.` (exit 0, no dialog). `doctor` accepts `[]`, `["--json"]`
  and `["--prune"]` only. The doctor function takes injectable `home` and
  `approve` parameters, as `add` and `install` already do, so tests run
  without a dialog.

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
    same file: a line whose text, after at most three leading spaces, starts
    with three or more backticks or three or more tildes opens a block, and
    the next fence line of the same character closes it. A file that never
    closes a fence keeps everything after the opener inside. The fence lines
    themselves are outside. For a finding from the paragraph pass, use its
    start line.
  - `forbidding`: otherwise, when the finding's line (lowercased, after
    `scan.normalize`) matches
    `\b(never|do not|don't|must not|should not|refuse|reject|watch for|look out for|beware of|block|flag)\b`.
  - `null` otherwise.
  - The label never changes `severity`, `score`, `threat_verdict` or
    `verdict`. A test puts the same attack line inside and outside a code
    block and asserts identical score and verdict, and the existing
    no-dampening test stays as it is.
  - `CONTEXT[label]` text:
    - `code_example`: `Inside a code example. Examples are often documentation, but a skill can still tell the agent to run them.`
    - `forbidding`: `On a line that warns against it. Skills sometimes quote a phrase to forbid it; read the line to be sure.`
- **The headline leads with the combined judgment.** `explain.headline(check)`
  takes a `canary.check/1` result and returns one sentence. `classify.check`
  stores it as `result["headline"]`. Rules, first match wins:
  1. `verdict == "UNSAFE"` and the classifier said UNSAFE:
     `SkillCanary judged this skill unsafe: the AI review found it unsafe.`
  2. `verdict == "UNSAFE"`: `SkillCanary judged this skill unsafe: the pattern scan found <labels>.`
  3. `verdict == "LIKELY_SAFE"`: `No problems found: the pattern scan and the AI review both passed it.`
  4. Only the pattern rules raised the verdict (classifier status `ok`,
     verdict `SAFE`, confident; coverage complete; no review capabilities;
     `threat_verdict == "NEEDS_REVIEW"`):
     `The AI review judged this skill safe (<confidence, 2 decimals>). The pattern scan flagged <labels> for you to look at.`
  5. Otherwise: `This skill needs your judgment. The reasons and what you can do are below.`

  `<labels>` is the RULES labels of the scored findings' checks (severity not
  `info`), deduplicated, in catalog order, joined as `a`, `a and b`, or
  `a, b and c`.
- **A next step for every review reason.** `explain.next_steps(check)` returns
  the steps for the reasons that keep the verdict at `NEEDS_REVIEW`, in reason
  order, without duplicates, and an empty list for any other verdict.
  `classify.check` stores it as `result["next_steps"]`. Steps are derived from
  the structured result (`scan.threat_verdict`, `scan.coverage`,
  `scan.capabilities`, `classifier.status`, `classifier.verdict`, the
  confidence rule), never by parsing reason strings. Exact text:
  - pattern hits: `Look at the flagged lines: run canary explain with the same link or folder in your own terminal. Install it if they are only documentation; skip it if they tell the agent to do something you did not ask for.`
  - scan incomplete or nothing to scan: `Some files could not be read, so the check is incomplete. Install it only if you trust where it came from.`
  - runs code or grants tools: `It runs code or grants tools, so it needs your approval whatever the scan found. Install it only if you trust where it came from.`
  - classifier unavailable: `To add the AI review, sign in to Claude Code or set ANTHROPIC_API_KEY or OPENAI_API_KEY, then check it again.`
  - classifier too large: `The AI review reads only skills under 256 KB. Look at the flagged lines with canary explain, or install it only if you trust where it came from.`
  - classifier failed or invalid: `Check it again. If the AI review keeps failing, decide from the pattern scan with canary explain.`
  - classifier asked for review or was not confident: `The AI review wants a person to look. Run canary explain with the same link or folder in your own terminal to see what it noticed.`

  A test builds one result per reason family and asserts each gets exactly its
  step, so a new review reason cannot ship without one.
- **Where the headline and steps appear.**
  - `classify.render_text`: the line after `Verdict:` is the headline; the
    existing reasons follow unchanged; then, when there are steps, a
    `What you can do:` line and the steps as `  - ` bullets.
  - `scan.render_text` (pattern scan alone, `canary scan`): unchanged except
    that each finding line ends with ` [code example]` or ` [warns against
    it]` when it has a context.
  - `canary add` and `canary install` results gain `"headline"` and
    `"next_steps"` (for install, each item in `skills` gains its own
    `headline`, and the top-level `next_steps` is the union in item order).
    `reasons` keeps its current content, so nothing that reads it breaks.
  - The approval dialogs (`add.dialog_text`, `install.dialog_text`) put the
    headline (for install, each skill's headline after its name) directly
    under the first line, keep the reasons, and end the Canary part with
    `What you can do:` and the steps, before the labelled package strings.
    `canary install`'s step for pattern hits also tells the person to choose
    Cancel first: the dialog uses the same step text, prefixed with
    `Choose Cancel, then `, lowercasing the step's first letter.
  - The SkillCanary skill (`frontdoor.SKILL_TEXT` and `skills/canary/SKILL.md`,
    which a test keeps identical) tells agents to relay the headline, then the
    reasons and the steps, and lists `canary explain` as a command for the
    person only: "Never run canary explain yourself; give the person the
    command to run in their own terminal."
- **`canary explain <link-or-folder> [--backend …] [--model …] [--timeout …]`**,
  for the person only.
  - It accepts what `canary add` accepts: a local folder or a GitHub link. A
    link is fetched with `add`'s own fetch code into a temporary folder that
    is removed afterwards; no new network code.
  - It runs `classify.check(path, excerpts=True, …)` with the same options and
    validation as `canary check`, and prints, in order: the headline; the
    verdict; for each scored check, its label, `What it looks for:`, `Why it
    matters:`, then each hit as `  <file>:<line>  <excerpt repr>` with the
    context text on the next line when there is one; the capabilities in the
    plain words `add.PLAIN` already has; skipped files; the AI review's
    verdict, confidence and its findings with evidence (as `check --excerpts
    --text` shows them); then `What you can do:` and the steps. Exit codes
    match `canary check`.
  - It refuses to run when standard output is not a terminal: `canary
    explain shows the skill's own text, so it runs only in your own
    terminal.`, exit 2. Tests inject the terminal check.
  - The hook denies an agent's shell command whose tidied text
    (`installers.tidy`) matches `(^|[^\w/-])canary\s+explain\b` or
    `/canary\s+explain\b`, **before** the `_is_canary` allowance, with:
    `canary explain shows the skill's own text, which is for the person, not
    an agent. Give the person this command to run in their own terminal:
    canary explain <the same link or folder>`. Like the installer rule, a
    command that only mentions it is denied too.
  - `canary --help` lists `canary explain <github-link-or-folder> [--backend
    <name>] [--model <id>] [--timeout <seconds>]` and `canary doctor [--json
    | --prune]`.

### 3. The hook's installer message

`gate.REDIRECT` gains one sentence at the end: `To write a file that only
mentions an installer, use your file tool (Write or Edit), not the shell.`
(Host-neutral wording: Codex has no tool named Write.)

### Documentation

`docs/architecture.md` describes the lock record fields, scope, key format,
live and dead records, the conflict rule and the refusal strings (section
"Lockfile" and `canary add` / `canary install` steps); `canary doctor
--prune`; the `context` field and that it never changes a score; the
`headline` and `next_steps` fields; `canary explain` and the hook rule; and
the new REDIRECT sentence. `scanner/references/checks.md` notes the labels
and that the no-dampening rule is unchanged.

## Done when

1. A dead lock record never blocks `canary install` or `canary add`; a new
   install whose key equals a dead record's key replaces it. Named tests in
   `tests/test_install.py` and `tests/test_add.py` each go red when the dead
   check is removed.
2. A project install and a user (global) install of the same name both
   succeed, in either order, and both records stay in the lockfile with
   their `name` and `scope`.
3. A live conflicting record still blocks, and the refusal is the exact
   string above, naming the path and date. No output, docs or skill text
   mentions `canary update`.
4. `canary doctor` lists dead skill and plugin records in text and JSON
   without changing the exit code; `canary doctor --prune` removes only
   still-dead records after the person says yes, and nothing on decline or
   with no dialog.
5. Every catalog check id has its RULES text, verified by a test that fails
   when a check id is added without text.
6. Findings carry `context`; the same attack line inside and outside a code
   block, and on a "never" line, gives identical score and verdict; the
   no-dampening test still goes red when dampening is allowed for attack
   patterns.
7. `canary check` results carry `headline` and `next_steps` per the rules
   above; a test per headline rule and per reason family pins the exact text.
8. The add and install dialogs show the headline and `What you can do:` with
   the steps; no excerpt, file name or model text appears in them (existing
   dialog tests stay green).
9. `canary explain` prints the layout above for a local folder, refuses
   without a terminal (exit 2), and the hook denies an agent's `canary
   explain` before the canary allowance, in Claude and Codex payloads.
10. REDIRECT ends with the new sentence.
11. `frontdoor.SKILL_TEXT` and `skills/canary/SKILL.md` match and describe the
    headline, the steps, `canary explain` (person only) and `doctor --prune`;
    `docs/architecture.md` and `scanner/references/checks.md` describe the
    new behavior.
12. `python3 -m unittest discover -s tests` passes on the program branch's
    head, with the count reported; for each of bullets 1, 2, 4, 6, 7 and 9, a
    deliberate break turns a named test red while its neighbours stay green,
    captured as raw per-case logs.

## Plan

1. Refute this contract (Spark 1.3 Contributor, read-only, `max`) against the
   worktree it will run in; fold the findings.
2. Slice L (records, bullets 1-4 and 10) then slice P (plain flags, bullets
   5-9 and 11), built by one Sonnet 5.5 worker in one disposable worktree,
   each slice its own commit after the full suite passes.
3. Spark reviews the finished diff; the builder folds; the coordinator
   re-checks the fold.
4. Full suite on the merged program head, then the done-when audit (an Opus
   subagent with fresh context).
5. The owner decides on push, pull request and merge.
