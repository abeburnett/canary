"""Does a shell command install a skill or plugin? (docs/architecture.md,
"canary hook", rule 3.)

The installer's own words decide, wherever they sit in the command. Shell
grammar has no end (keywords, functions, wrappers with options, variables,
`find -exec`...), and every attempt to work out which words *run* left a way
around it (program 2026-09-30, two review rounds). So the text is tidied the
way the shell would read words (quotes, `$'...'`, line continuations and
backslashes removed) and searched for:

- a `skills` package (`skills`, `@scope/skills`, `skills@1.2.3`) followed,
  after any options, by `add`, `a`, `install`, `i`, `update` or `upgrade`;
- `plugin` or `plugins` followed, after any options, by `install`, `i`,
  `update`, `add` or `marketplace add` (Claude Code and Codex);
- `clone` in a command that names a skills folder, or that runs in one.

A command that only mentions these words (`echo`, a heredoc) is denied too:
the message points to `canary add`, and the Write tool writes such a file.
A single, plain command asking only for help or a listing is allowed. A
command assembled from pieces (`npx $X add`) is out of reach, as is any
program that starts an installer itself; the watcher reports what lands.
"""

import os
import re

SKILLS_CLI = re.compile(
    r"(?<![\w.-])(?:@[\w.-]+/)?skills(?:@[^\s/;&|()]*)?"
    r"(?:\s+--?[\w-]+(?:=\S*)?)*\s+(?:add|a|install|i|update|upgrade)(?=\s|$)", re.I)
PLUGIN = re.compile(
    r"\bplugins?\b(?:\s+--?[\w-]+(?:=\S*)?(?:\s+(?!install\b|i\b|update\b|add\b|marketplace\b)[\w.@/-]+)?)*"
    r"\s+(?:install|i|update|add|marketplace\s+add)(?=\s|$)", re.I)
CLONE = re.compile(r"\bclone\b", re.I)
SKILLS_FOLDER = re.compile(r"\.(?:claude|agents|codex)/skills\b", re.I)
HELP = re.compile(r"(?:^|\s)(?:-h|--help|-l|--list)(?=\s|$)")
# A command with any of these is not "a single, plain command".
COMPOUND = set(";&|`$(){}<>\n\r\\")


def tidy(command):
    """The words as the shell would see them, near enough for a search."""
    text = command.replace("\\\r\n", "").replace("\\\n", "")
    text = re.sub(r"\$(?=['\"])", "", text)
    return text.replace("'", "").replace('"', "").replace("\\", "")


def installs(command, cwd, in_skills):
    """True when the command's words install a skill or plugin.
    `in_skills(path)` says whether a path lies in a skill folder."""
    text = tidy(command)
    found = bool(SKILLS_CLI.search(text) or PLUGIN.search(text))
    if not found and CLONE.search(text):
        found = bool(SKILLS_FOLDER.search(text) or in_skills(os.path.join(cwd, "SKILL.md"))
                     or in_skills(os.path.join(cwd, "x", "SKILL.md")))
    if not found:
        return False
    plain = not any(c in COMPOUND for c in command)
    return not (plain and HELP.search(text))
