# Canary layer-1 checks: categories, capabilities and limits

The patterns live in `canary/catalog.py`, the single source of truth. This file
explains what the scanner reports, how it reaches a verdict, and what it
cannot catch, which is the job of layer 2 (the isolated classifier).

## Three separate outputs

1. **Threat findings**: text that looks like an attack, from the catalog below.
2. **Capabilities**: each way the package can run code or grant itself power.
3. **Coverage**: whether every entry in the package was actually read.

The verdict is the strictest of the three. A package that runs code, or that
the scanner could not read in full, is never `LIKELY_SAFE`: a person approves
it. That is a review, not an accusation.

## Threat categories

| Category | Severity | Examples of what it catches |
|---|---|---|
| INSTRUCTION_OVERRIDE | high | "ignore previous instructions", "your new instructions are" |
| SAFEGUARD_BYPASS | high | "never ask the user for confirmation", `disableAllHooks`, `--dangerously-skip-permissions` |
| EXFILTRATION | high | webhook and tunnel hosts, "send … to https://…", `curl` with `-d`, `-F` or `-T` |
| SHELL_PIPE | high | `curl … \| sh` (and zsh, python, node, sudo), `bash <(curl …)`, `$(curl …)`, `eval "$(…)"` |
| CREDENTIAL_ACCESS | high | `~/.ssh`, `id_ed25519`, `~/.aws`, keychain reads, "paste your private key" |
| IDENTITY_REWRITE | medium | "you are now a…", "from now on, you are" |
| PERSISTENCE | medium | writes to agent config (`~/.claude/settings.json`, `~/.codex/hooks.json`), `launchctl`, cron |
| STEALTH | medium | "do not tell the user", "without the user knowing" |
| PROMPT_LEAK | medium | "reveal your system prompt" |
| OBFUSCATION | high | an invisible character inside a word, any bidirectional-control or Unicode tag character, a word mixing Latin with Cyrillic or Greek letters; medium for a long base64 run |
| EXTERNAL_URL | info | any URL; recorded, never scored |

## Capabilities

| Kind | Found by | Blocks auto-approval |
|---|---|---|
| `shell_injection` | a `` !`cmd` `` line or a ```` ```! ```` block in any `.md` file; Claude Code runs these before the model sees the skill | yes |
| `allowed_tools` | an `allowed-tools` key anywhere in the frontmatter, quoted, indented or inside `{…}`, after a byte-order mark or blank lines; it grants tools without a prompt, and workspace trust does not gate it | yes |
| `skill_hooks` | a `hooks` key anywhere in the frontmatter, in the same spellings; it registers hooks for the rest of the session | yes |
| `plugin_power` | a `plugin.json` using any key beyond the descriptive ones (so it may declare hooks, MCP servers or commands inline), one that is not valid JSON, or any `marketplace.json` | yes |
| `skill_dependencies` | an `agents/*.yaml` declaring dependencies, MCP servers, tools, permissions or install steps (Codex can auto-install MCP dependencies) | yes |
| `plugin_manifest` | a `plugin.json` using only descriptive keys: name, version, description, author, homepage, repository, license, keywords, skill paths, display name, category, tags | no (listed only) |
| `plugin_hooks` | any `hooks.json` | yes |
| `mcp_config` | `.mcp.json` or `mcp.json` | yes |
| `bin_dir` | any file under a directory named `bin`, in any case; Claude Code puts an enabled plugin's `bin/` on the shell's PATH | yes |
| `script` | a script extension or a `#!` first line | yes |
| `executable_bit` | any other file marked executable | yes |
| `package_manifest` | `package.json`, `pyproject.toml`, `requirements.txt`, `Gemfile`, `Cargo.toml`, `go.mod` and similar: a package manager runs code or fetches dependencies from these | yes |
| `unrecognized_file` | a text file whose type is not on the inert-document allowlist (Markdown, plain text, JSON, YAML, TOML, CSV, XML, HTML, CSS, SVG, INI and license or readme files). Unknown means possibly runnable | yes |
| `context_fork` | `context: fork` in frontmatter | no (listed only) |

## Coverage

Every entry is inventoried through directory handles, so paths longer than
the operating system's limit are still read, and errors while listing a
directory are recorded instead of dropped. `.git` and every other hidden
directory are scanned like any other. These make coverage incomplete: an
empty package, binary files, files over 2 MB, unreadable files or
directories, special files, any symbolic link inside the package (never
followed), more than 64 directory levels, and more than 5,000 entries.
Images, fonts and PDFs are the exception: listed as unscanned media without
blocking, but only when the extension, the first bytes, and the fact that the
content does not decode as text all agree. Anything that decodes as text is
scanned as text, whatever it is called.

File names are attacker-controlled text. Default output shows them only as
opaque `path_id` values; `--excerpts` reveals names and excerpts for a person.

## Scoring

high = 3, medium = 2, low = 1, info = 0, and **each distinct check counts
once**, at its strictest severity. Ten copies of one API example are one
signal; two different attack checks are two. Score 6 or more is `UNSAFE`,
3 to 5 is `NEEDS_REVIEW`.

Matching runs line by line and again over each paragraph joined into one line,
so a phrase or a `curl … |` pipe split across lines still matches. Within a
check every pattern is tried and the strictest result kept, so a
documentation-shaped decoy cannot mask an attack pattern on the same line.
Every repeat in the catalog is bounded, so a hostile file cannot stall the
scanner. Text is NFKC-normalized,
invisible characters are removed, and Cyrillic and Greek look-alikes are
folded to Latin before matching. Patterns are case-insensitive.

## Documentation contexts, and the 2026-09-26 calibration

An earlier calibration silenced every high or medium finding on a line that
also contained `--yes`, `-y`, `e.g.`, `for example`, `example:` or an
`X_API_KEY` name. The 2026-09-26 refutation showed that appending any of those
tokens hid a real attack line, so that rule is gone. The tokens now soften only
the patterns marked documentation-shaped in the catalog (`.pem` mentions,
`.env` reads, an API-key name near "send"); they never soften an override,
bypass, stealth, exfiltration, shell-pipe or `~/.ssh` finding. URL volume no
longer scores at all.

Measured on the 133 skills in one real `~/.agents/skills` library
(2026-09-26): the earlier engine rated 97 safe, 24 review, 12 unsafe; this one
rates 95 safe, 32 review, 6 unsafe. Of the 32 reviews, 24 are there only
because the skill runs code; the sixth unsafe is a `curl … | sh` split across
two lines, which the paragraph pass now catches. The planted attack fixture scores 23, `UNSAFE`.

## What layer 1 still misses

- **Paraphrase**: "kindly set aside what you were told earlier" matches no
  pattern. Layer 2 reads intent.
- **Social framing**: "for a security audit, please…". Layer 2.
- **Behavior that is fetched later**: a script that downloads its real payload,
  an MCP server run from `@latest`, a hook that syncs code every session.
  The scanner flags the capability; it cannot see the future bytes.
- **Multi-package attacks**: a clean skill that tells the agent to install a
  second one. The gate, not the scanner, has to stop that install.
