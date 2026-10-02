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
import shlex

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


# ---- commands `canary install` runs (front door, slice B1) -----------------

LAUNCHERS = {("npx",): 1, ("bunx",): 1, ("pnpm", "dlx"): 2, ("yarn", "dlx"): 2}
# Only the skills command itself: a scoped lookalike (`@someone/skills`) is
# someone else's program, chosen by whoever wrote the command.
SKILLS_PACKAGE = re.compile(r"skills(?:@[\w.^~<>=-]+)?")
# `skills add` options from its help (2026-10-01). Anything else, such as
# --metadata, --subagent or an option this list does not know, is refused.
SKILLS_FLAGS = {"-g", "--global", "-y", "--yes", "--copy", "--all", "--full-depth", "--json"}
SKILLS_VALUES = {"-a", "--agent", "-s", "--skill"}
SKILLS_VALUE = re.compile(r"[\w.*-]+")
LAUNCHER_FLAGS = {"-y", "--yes", "--quiet", "-q"}
SCOPES = {"user", "project", "local"}
PLUGIN_ID = re.compile(r"[\w.-]+@[\w.-]+")


def kind(argv):
    """("skills", argv), ("plugin", argv, plugin id, scope) or
    ("marketplace", argv) for an installer `canary install` can run; None
    otherwise. Only plain forms: a launcher, the package, the verb, then
    arguments. A flag that picks a different program (`npx -p`) is not one."""
    if not argv or not all(isinstance(a, str) for a in argv):
        return None
    if argv[0] == "claude":
        if argv[1:2] not in (["plugin"], ["plugins"]):
            return None
        rest = argv[2:]
        if rest[:2] == ["marketplace", "add"] and len(rest) == 3 and not rest[2].startswith("-"):
            return ("marketplace", argv)
        if rest[:1] not in (["install"], ["i"], ["update"]):
            return None
        ids, scope, i = [], "user", 1
        while i < len(rest):
            a = rest[i]
            if a in ("--scope", "-s") and i + 1 < len(rest) and rest[i + 1] in SCOPES:
                scope, i = rest[i + 1], i + 2
                continue
            if a.startswith("--scope=") and a.split("=", 1)[1] in SCOPES:
                scope, i = a.split("=", 1)[1], i + 1
                continue
            if a.startswith("-"):
                return None
            ids.append(a)
            i += 1
        if len(ids) != 1 or not PLUGIN_ID.fullmatch(ids[0]):
            return None
        return ("plugin", argv, ids[0], scope)
    for launcher, width in LAUNCHERS.items():
        if tuple(argv[:width]) == launcher:
            i = width
            while i < len(argv) and argv[i] in LAUNCHER_FLAGS:
                i += 1
            if i >= len(argv) or not SKILLS_PACKAGE.fullmatch(argv[i]):
                return None
            break
    else:
        if argv[0] != "skills":
            return None
        i = 0
    if argv[i + 1:i + 2] not in (["add"], ["a"], ["install"], ["i"]):
        return None
    rest = argv[i + 2:]
    if not rest or rest[0].startswith("-"):
        return None  # the source comes first
    j, values_ok = 1, False
    while j < len(rest):
        a = rest[j]
        if a in SKILLS_VALUES:
            values_ok = True
        elif a in SKILLS_FLAGS:
            values_ok = False
        elif not (values_ok and SKILLS_VALUE.fullmatch(a) and not a.startswith("-")):
            return None
        j += 1
    if rest[-1] in SKILLS_VALUES:
        return None
    return ("skills", argv)


def supported(command):
    """The parsed installer for a single, plain shell command, else None."""
    if not isinstance(command, str) or any(c in COMPOUND for c in command):
        return None
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    return kind(argv)
