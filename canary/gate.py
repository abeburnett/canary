"""The gate's decision, independent of any host (docs/architecture.md,
"canary hook", decision rules). Hooks are a guard, not proof: a command can
hide its target from any parser, which is why Lockdown adds root ownership.
"""

import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass, field

SUPPORT = os.path.join("Library", "Application Support", "Canary")
FRAGMENTS = (".claude/skills", ".agents/skills", ".claude/plugins", ".codex/skills",
             ".codex/plugins", ".canary-lock", "application support/canary",
             "managed-settings", "/etc/codex", "claudecode/managed", ".claude/commands",
             ".claude/agents", ".claude/settings", ".claude.json", ".mcp.json", "agents.md",
             "agents.override.md", ".codex/config", ".codex/hooks", ".codex/rules",
             "application support/skillcanary")
# In a command SkillCanary could not map, a bare host folder (`cd ~/.claude &&
# tool skills/x $V`) may be where the relative writes that follow land.
HOST_FOLDER = re.compile(r"(?:^|[\s/'\"=:])\.(?:claude|agents|codex)(?=$|[\s'\";&|)<>])")
INSTALLERS = re.compile(
    r"(\b(npx|bunx)\b(\s+-\S+)*\s+[@\w./-]*\bskills(@\S*)?\s+(add|install|update)\b"
    r"|\b(pnpm|yarn)\s+dlx\s+(-\S+\s+)*[@\w./-]*\bskills(@\S*)?\s+(add|install|update)\b"
    r"|\bclaude\s+plugins?\s+(install|update|marketplace\s+add)\b"
    r"|\bcodex\s+plugins?\s+(install|add|update|marketplace\s+add)\b)", re.I)
REPO_ROOTS = (".claude/skills", ".claude/commands", ".claude/agents", ".agents/skills",
              ".codex/skills")
SHELL_SYNTAX = set(";&|<>()$`\\\n\r*?[]{}~")
REDIRECT = ("This installs skills or plugins without SkillCanary checking them first. "
            "Use `canary add <link>` instead; it checks the package and asks the person.")
PROTECTED_SKILL = ("SkillCanary protects this skills folder. To change an installed skill, "
                   "run `canary edit start <name or folder>`, edit the draft it prints, then "
                   "run `canary edit apply <draft>`; the person approves in a dialog. To "
                   "install a new skill, use `canary add <link>`. Reading this folder is allowed.")
PROTECTED = ("This would change a folder or file agents load skills or settings from, which "
             "SkillCanary protects. Reading it is allowed. Ask the person to make this change "
             "in their own editor or terminal. To install a skill, use `canary add <link>`; "
             "to change one, use `canary edit start <name>`.")
MENTIONED = ("SkillCanary could not tell whether this command changes the protected folder "
             "it names, so it is blocked. To read, use plain commands (ls, grep, cat) or the "
             "Read tool. To write a file whose text mentions the folder, use the Write tool. "
             "To change a skill, use `canary edit start <name>`.")
QUARANTINED = ("That file is a quarantined package SkillCanary has not approved. "
               "Agents may not read it; use `canary check` for a verdict.")
UNREADABLE = ("SkillCanary could not check this tool call, so it is blocked. "
              "If it is harmless, ask the person to run it in their own terminal.")


@dataclass
class ToolCall:
    tool_name: str
    command: object          # shell or patch text, or None for file tools
    paths_read: list
    paths_written: list
    cwd: str
    precise: bool = True     # False: the adapter could not map it exactly
    text: str = ""           # everything the call says, for text screening
    trees_read: list = field(default_factory=list)     # read recursively
    trees_written: list = field(default_factory=list)  # rewritten wholesale (git)
    screen: bool = False     # mapped, but also screen the text (unknown commands)
    folders_written: list = field(default_factory=list)  # `.`/`..` for unknown commands


@dataclass
class PlannedFile:
    path: str
    content: str
    mode: int
    action: str              # "create" or "manual"


def quarantine_dir(home):
    return os.path.join(home, SUPPORT, "quarantine")


def protected_paths(home, cwd, adapters):
    """Every host's discovery roots and config, plus Canary's own state."""
    paths = [quarantine_dir(home), os.path.join(home, ".agents", ".canary-lock.json"),
             os.path.join(home, SUPPORT), "/Library/Application Support/ClaudeCode",
             "/etc/codex", "/Library/Application Support/SkillCanary",
             "/usr/local/lib/skillcanary", "/usr/local/bin/canary"]
    for adapter in adapters:
        paths += adapter.discovery_roots(home, cwd) + adapter.config_files(home)
    return sorted({os.path.realpath(p) for p in paths})


def _fold(path):
    return os.path.normpath(path).casefold()


def _inside(p, r):
    return p == r or p.startswith(r.rstrip("/") + "/")


def _protected_hit(path, protected, existing_only=False):
    """Inside a protected location, or a folder that contains one. With
    existing_only, a contained location counts only if it exists on disk."""
    p = _fold(os.path.realpath(path))
    for root in protected:
        r = _fold(root)
        if _inside(p, r):
            return True
        if _inside(r, p) and (not existing_only or os.path.lexists(root)):
            return True
    return False


def _in_any_skills_folder(path):
    """Inside a skills, commands or agents folder of any repository, not only
    the ones above the working folder."""
    p = _fold(os.path.realpath(path))
    return any(f"/{rel}/" in p + "/" for rel in REPO_ROOTS)


def _user_level_folder(path, protected, home):
    p = _fold(os.path.realpath(path))
    h = _fold(os.path.realpath(home))
    parts = p.split("/")
    return (_inside(h, p) or any(part in (".claude", ".agents", ".codex") for part in parts)
            or any(_inside(p, _fold(r)) for r in protected))


def _reads_inside(path, protected):
    p = _fold(os.path.realpath(path))
    return any(_inside(p, _fold(r)) for r in protected)


def _write_reason(paths, protected):
    """PROTECTED_SKILL when a write lands inside a skills folder, else PROTECTED."""
    for path in paths:
        p = _fold(os.path.realpath(path))
        for root in protected:
            r = _fold(root)
            if _inside(p, r) and "skills" in r.split("/"):
                return PROTECTED_SKILL
        if any(f"/{rel}/" in p + "/" for rel in REPO_ROOTS if rel.endswith("skills")):
            return PROTECTED_SKILL
    return PROTECTED


def _names_protected(text, protected, home):
    t = text.casefold()
    if any(f in t for f in FRAGMENTS):
        return True
    spellings = set()
    for r in protected:
        spellings.add(r)
        for base in {home, os.path.realpath(home)}:
            if r.startswith(base + "/"):
                rest = r[len(base):]
                spellings.update({"~" + rest, "$home" + rest, "${home}" + rest})
    return any(s.casefold() in t for s in spellings)


def _is_canary(command, canary_bin):
    if not isinstance(command, str) or any(c in SHELL_SYNTAX for c in command):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens or tokens[0] != "canary" or not canary_bin:
        return False
    found = shutil.which("canary")
    if not found or os.path.realpath(found) != os.path.realpath(canary_bin):
        return False
    st = os.stat(canary_bin)
    return st.st_uid == 0 and not st.st_mode & 0o022


def decide(call, protected, home, canary_bin=None):
    """A deny reason, or None to allow. Any internal error denies."""
    try:
        text = call.text or (call.command if isinstance(call.command, str) else "")
        if INSTALLERS.search(text):
            return REDIRECT
        if _is_canary(call.command, canary_bin):
            return None
        if call.precise:
            hits = [p for p in call.paths_written
                    if _protected_hit(p, protected) or _in_any_skills_folder(p)]
            # A git checkout rewrites a whole repository; its placeholder
            # skills folders count only once they exist.
            trees = protected + [os.path.join(os.path.realpath(t), rel)
                                 for t in call.trees_written for rel in REPO_ROOTS]
            hits += [p for p in call.trees_written
                     if _protected_hit(p, trees, existing_only=True)]
            # `tool .` may only read (prettier --check .), so a whole folder
            # counts as written only where user-level protection lives: the
            # home folder or above, a host folder, or inside a protected one.
            hits += [p for p in call.folders_written if _user_level_folder(p, protected, home)]
            if hits:
                return _write_reason(hits, protected)
            quarantine = [r for r in protected if _fold(r).endswith("/canary/quarantine")]
            if (any(_reads_inside(p, quarantine) for p in call.paths_read)
                    or any(_protected_hit(p, quarantine) for p in call.trees_read)):
                return QUARANTINED
            if call.screen and _names_protected(text, protected, home):
                return MENTIONED
            return None
        if _names_protected(text, protected, home) or HOST_FOLDER.search(text.casefold()):
            return MENTIONED
        return None
    except Exception:
        return UNREADABLE


def envelope(raw):
    """The payload dict, or ValueError if it is not a usable pre-tool-use event."""
    payload = json.loads(raw)
    if (not isinstance(payload, dict) or payload.get("hook_event_name") != "PreToolUse"
            or not isinstance(payload.get("tool_name"), str)
            or not isinstance(payload.get("tool_input"), dict)
            or not isinstance(payload.get("cwd"), str) or not os.path.isabs(payload["cwd"])):
        raise ValueError("not a PreToolUse event")
    return payload


def unmapped(payload):
    """A ToolCall for input the adapter could not map: screened as text."""
    tool_input = payload["tool_input"]
    command = tool_input.get("command") if isinstance(tool_input.get("command"), str) else None
    return ToolCall(payload["tool_name"], command, [], [], payload["cwd"], precise=False,
                    text=json.dumps(tool_input, ensure_ascii=False))
