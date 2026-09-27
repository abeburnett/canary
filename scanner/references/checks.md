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
| OBFUSCATION | medium | long base64, any invisible or bidirectional-control character, a word mixing Latin with Cyrillic or Greek look-alikes |
| EXTERNAL_URL | info | any URL; recorded, never scored |

## Capabilities

| Kind | Found by | Blocks auto-approval |
|---|---|---|
| `shell_injection` | a `` !`cmd` `` line or a ```` ```! ```` block in any `.md` file; Claude Code runs these before the model sees the skill | yes |
| `allowed_tools` | `allowed-tools:` in frontmatter; grants tools without a prompt, and workspace trust does not gate it | yes |
| `skill_hooks` | `hooks:` in frontmatter; registers hooks for the rest of the session | yes |
| `plugin_power` | a `plugin.json` using any key beyond the descriptive ones (so it may declare hooks, MCP servers or commands inline), one that is not valid JSON, or any `marketplace.json` | yes |
| `skill_dependencies` | an `agents/*.yaml` declaring dependencies, MCP servers, tools, permissions or install steps (Codex can auto-install MCP dependencies) | yes |
| `plugin_manifest` | a `plugin.json` using only descriptive keys: name, version, description, author, homepage, repository, license, keywords, skill paths, display name, category, tags | no (listed only) |
| `plugin_hooks` | any `hooks.json` | yes |
| `mcp_config` | `.mcp.json` or `mcp.json` | yes |
| `bin_dir` | any file under a `bin/` directory; Claude Code puts an enabled plugin's `bin/` on the shell's PATH | yes |
| `script` | a script extension or a `#!` first line | yes |
| `executable_bit` | any other file marked executable | yes |
| `context_fork` | `context: fork` in frontmatter | no (listed only) |

## Coverage

Every entry is inventoried without following links. These make coverage
incomplete: an empty package, binary files, files over 2 MB, unreadable or
special files, a symlink that points outside the package, a symlinked
directory, and more than 5,000 entries. Images and fonts are the exception:
they are listed as unscanned media and do not block, but only when both the
extension and the file's first bytes say image or font, so a text payload
cannot pass as a picture.

## Scoring

high = 3, medium = 2, low = 1, info = 0, and **each distinct check counts
once**, at its strictest severity. Ten copies of one API example are one
signal; two different attack checks are two. Score 6 or more is `UNSAFE`,
3 to 5 is `NEEDS_REVIEW`.

Matching runs line by line and again over each paragraph joined into one line,
so a phrase split across lines still matches. Text is NFKC-normalized,
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
rates 94 safe, 34 review, 5 unsafe. Of the 34 reviews, 25 are there only
because the skill runs code. The planted attack fixture scores 23, `UNSAFE`.

## What layer 1 still misses

- **Paraphrase**: "kindly set aside what you were told earlier" matches no
  pattern. Layer 2 reads intent.
- **Social framing**: "for a security audit, please…". Layer 2.
- **Behavior that is fetched later**: a script that downloads its real payload,
  an MCP server run from `@latest`, a hook that syncs code every session.
  The scanner flags the capability; it cannot see the future bytes.
- **Multi-package attacks**: a clean skill that tells the agent to install a
  second one. The gate, not the scanner, has to stop that install.
