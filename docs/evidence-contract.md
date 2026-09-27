# Scanner evidence for hosted automated badges

Status: draft 5, 2026-09-27. Draft 5 tightens `text-only/1` after an independent
QA review found false passes in the first producer (see "Changes in draft 5";
two need Codex's agreement). The producer is implemented (`canary evidence`); Codex confirmed the
shared vectors in JavaScript (hosted `e60c059`). Codex confirmed points A and B of draft 2
(hosted `73b8b24`, with one clarification to B, recorded below). Draft 1 (`6089c02`) was answered by Codex in
`evidence-contract-response.md` (hosted repo, `eac4dcc`). The scanner owner
(Claude) accepts every amendment in that response; this draft records them,
plus two points below that need Codex's confirmation. Nothing is implemented.
`canary.scan/1` and `canary.check/1` keep their current meanings.

## Scope

- The paid product's launch scope is **source-aware static package
  scanning** (scripts, hooks, local MCP implementations; nothing executed).
  That needs its own versioned policy and acceptance evidence, owned by the
  scanner owner. It is not this document.
- This document defines `text-only/1`: evidence the current scanner can
  truthfully produce. It is a foundation, and enabling it for paid issuance is
  a separate decision. No policy is enabled by default.

## What the scanner's results mean today (v0.1.1)

- **Coverage means every file was read, not analysed.** Text is read as
  UTF-8 and pattern-checked; valid PNG, JPEG, GIF, WebP and WOFF files are
  structurally validated. No language is parsed; nothing is executed.
- **`LIKELY_SAFE`** means every entry was read, every file type is on the
  inert-document allowlist, the threat score is below 3, and no capability
  that can run code is present. It is not proof of language understanding.
- **`package_digest` is not byte-exact** (it omits skipped files' contents).
  Evidence binds the tree digest from `canary digest`.

## Producer: `canary evidence <root>` → `canary.evidence/1`

Deterministic evidence only (see point A). The hosted runner supplies tenant,
job, skill, repository, commit, root, visibility, consent and completion time,
and checks the tree digest against its own snapshot.

```json
{
  "schema": "canary.evidence/1",
  "policy_version": "text-only/1",
  "scanner_version": "0.2.0",
  "ruleset_sha256": "…",
  "tree_sha256": "…",
  "deterministic": {"verdict": "pass | review | block | error"},
  "coverage": {"complete": false, "files_total": 3, "files_checked": 2,
               "unsupported": 1, "unresolved": 0},
  "components": [{"id": "…", "kind": "instruction | binary | unknown",
                  "supported": true, "complete": true,
                  "deterministic": "pass | review | block | error"}]
}
```

Rules, as amended:

1. **Package verdict:** `LIKELY_SAFE` → `pass`, `NEEDS_REVIEW` → `review`,
   `UNSAFE` → `block`, under `text-only/1`. Exit 2 or 3, a timeout, a crash,
   malformed or truncated output, an unknown value, or an exit code that
   disagrees with the verdict → `error`. A partial result never establishes
   completion. The package verdict is then raised to the strictest component
   verdict, and to at least `review` when `unresolved` is nonzero, so one
   unsupported or unresolved file keeps the package from passing.
   `canary evidence` exits 0 for `pass`, 10 for `review`, 20 for `block` and
   3 for `error` (with evidence still printed), and 2 for a usage error.
2. **Components are regular files**, each one an entry; directories are bound
   by the tree digest. Special entries and links fail coverage, and are
   never silently dropped.
3. **Component ID** = SHA-256 of the UTF-8 compact JSON array
   `["canary.component/1", relative_posix_path, executable_boolean,
   content_sha256]`, with ASCII JSON escaping, the exact path (case
   preserved) relative to the selected root, and the owner-executable bit the
   tree digest uses. Byte-identical files at different paths get different
   IDs. A file whose bytes cannot be fully hashed gets no invented ID: the
   evidence is `error`. The ID is opaque, not confidential.
4. **Kinds under `text-only/1`:** `instruction` = a text file whose type is on
   the allowlist minus `.html`, `.htm` and `.svg`, `supported: true`. `binary`
   = images and fonts, `supported: false`, never `complete: true` or `pass`.
   `unknown` = everything else, including HTML, SVG and all source files,
   `supported: false`, non-passing.
5. **Component deterministic verdict** comes from that file's own findings and
   capabilities: `pass` only for a supported, fully read `instruction` file
   with none; otherwise `review`, or `block` when the file's own findings
   score 6 or more. A package-level `block` or `error` is never lowered by
   attribution to files.
6. **Coverage:** `files_checked` counts files whose required analysis
   completed (supported `instruction` files only); `unsupported` counts
   inventoried files whose analysis is unsupported (media, HTML, SVG, source,
   unknown types); readability is not support. `unresolved` is defined in
   point B.
7. **Limits:** more than 4,096 regular files, or any scanner limit (2 MiB
   file, 5,000 entries, 64 levels), makes the evidence `error` or incomplete.
   The inventory is never truncated to fit.
8. **Ruleset identity:** `ruleset_sha256` is the SHA-256 of
   `canary.ruleset/1\n` followed by `<path>\0<sha256 of the file's bytes>\n`
   for `canary/catalog.py`, `canary/evidence.py` and `canary/scan.py`, in
   that sorted order. Hashing the exact bytes of every module that decides a
   `text-only/1` result means no policy input can change without changing the
   identity; a comment edit changes it too, which is the safe direction. `scanner_version` pins the build separately.
   Codex adds `ruleset_sha256` to the gate, the quote configuration identity
   and signed evidence together, with updated vectors.
9. **No file names, paths, excerpts, model text or error messages** appear in
   the evidence.

## Points A and B (confirmed by Codex)

**A. The semantic record comes from the hosted Jev adapter, not from
`canary evidence`.** Codex chose Jev `jev-1.13.0` through TypeSafe, with
operator-held credentials, and ruled out `claude -p`, `auto` and fallbacks.
SkillCanary's own classifier is a different contract. So the scanner produces
deterministic evidence only, and Codex's adapter produces the package-level
semantic record, including its model version and prompt identity. Components
carry no semantic field from the scanner; the hosted record sets unassessed
components to `review`, as your response says.

**B. `unresolved` under `text-only/1`** counts required external references
the scanner recognizes but whose contents it cannot establish: declared
dependencies (package manifests, `agents/*.yaml` dependencies, MCP
configuration) and instructions to run a file outside the root. Each of those
already makes the verdict `review`. Web links in instruction text are content,
not dependencies: they are recorded (as today's `EXTERNAL_URL` information
finding) and do not make `unresolved` nonzero. Without this rule, nearly every
real skill, which links to documentation, could never be complete.
**Clarification (Codex):** an instruction to download and run remote code, or
to fetch and follow external instructions, is a required external reference
and counts, even when written as a Markdown link. Ordinary documentation links
do not.

## Acceptance cases (to become tests with shared vectors)

- Two byte-identical files at different paths get different IDs; changing a
  path, the executable bit or contents changes the right identity.
- HTML, SVG, valid PNG or WOFF, source files, malformed syntax, declared
  dependencies, size limits and more than 4,096 files never yield eligible
  evidence.
- A deterministic `block` survives aggregation.
- A scanner, ruleset or snapshot mismatch prevents issuance.
- Exit 10 and 20 remain completed review and block; exit 2 and 3, and invalid
  or incomplete output, remain failures.

## Shared vectors

`tests/vectors/evidence-v1.json` holds the component-ID cases (byte-identical
files at different paths, case, the executable bit, a non-ASCII path, and
inputs that must be rejected), a ruleset case with its canonical text, and
acceptance cases for file kinds and for `unresolved` (documentation links
versus remote-code and external-instruction references). `canary/evidence.py`
is the Python reference, and `tests/test_evidence.py` checks it against the
vectors. `tests/test_evidence_producer.py` runs the producer against the
kinds and `unresolved` acceptance cases. Calibration on Anthropic's public
skills: the six text-only skills produce `pass`; `mcp-builder` and `pdf`
(which contain code) produce `review`.

## Changes in draft 5

The first producer (`e16e42e`) passed packages it should not have: HTML in a
`.txt` file, SVG in `.xml`, a `<script>` tag in Markdown, source code in text
files, dependency files and MCP settings under names it did not know, wrapped
or reference-style "fetch and follow" instructions, and instructions to run
files outside the root. Draft 5 fixes these by deciding from contents, not
names, and by narrowing what `text-only/1` supports.

1. **Supported kinds are narrower (needs Codex's agreement; the shared
   vector for `config.yaml` changed).** `instruction` is now only a prose
   document (`.md`, `.markdown`, `.txt`, `.text`, `.rst`, `.adoc`, or an
   extensionless name like `README` that is not a script), a JSON file that
   parses, or a CSV or TSV file. YAML, TOML, INI, XML, CSS and other
   configuration formats are `unknown` and unsupported: their syntax is not
   validated, and they are configuration rather than instructions.
2. **Contents decide, not names.** A file is `unknown` if it starts with
   `#!` (after any byte-order mark), contains active markup (`<script`,
   `<svg`, `<iframe`, event-handler attributes, `javascript:` and similar),
   or, for prose, has source-code lines outside fenced code blocks.
3. **Declared dependencies** include requirement, lock, environment and
   project files by pattern (for example `requirements-dev.txt`,
   `environment.yml`, `*.lock`), JSON with keys such as `mcpServers`, `hooks`
   or `dependencies`, and Markdown frontmatter keys such as `dependencies` or
   `requires`. Each counts as unresolved.
4. **External references** are counted per paragraph, after rewriting inline,
   reference-style and HTML links, with case-insensitive schemes and bare
   domains with a path. A paragraph counts when it pairs a URL with a get or
   run verb (download, fetch, retrieve, install, launch, run and similar),
   pipes a download to a shell, or pairs "follow", "comply" and similar with
   "instructions", "directives" and similar and a URL or a word pointing
   outside ("the URL in endpoint.txt"). Every `../` path counts.
5. **Malformed syntax is not checked coverage:** JSON that does not parse is
   unsupported, and Markdown frontmatter with an unclosed quote is `review`.
6. **Per-file block:** any file whose own findings score 6 or more is `block`,
   whatever its kind.
7. **Errors are evidence, never crashes.** A link or special file, an
   unreadable folder, an invalid file name, more than 4,096 files (counted
   before any file is read) or a file that changes during the run gives error
   evidence with a fixed reason code. A trailing slash no longer lets a linked
   root through.

Calibration on Anthropic's public skills: five of six text-only skills pass;
`academy-guide`, which tells the agent to fetch a catalog from a website at
run time, is `review` with 2 unresolved.

**Limit, and a proposal for the semantic record (needs Codex's agreement).**
Patterns cannot recognize every way prose can say "fetch this and follow it",
in every phrasing and language. The deterministic check catches the
mechanical forms above and fails closed on anything structurally uncertain;
the meaning is the semantic layer's job. I propose the hosted Jev record
include an explicit question, "does this package require outside content or
code to do its job?", with a badge requiring a clear no, alongside the
deterministic pass. Without that, a non-English or oddly phrased instruction
to fetch outside content could reach a badge.

