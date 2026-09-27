"""The gate's decision, independent of any host (docs/architecture.md,
"canary hook", decision rules). Hooks are a guard, not proof: a command can
hide its target from any parser, which is why Lockdown adds root ownership.
"""

import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass

SUPPORT = os.path.join("Library", "Application Support", "Canary")
FRAGMENTS = (".claude/skills", ".agents/skills", ".claude/plugins", ".codex/skills",
             ".codex/plugins", ".canary-lock", "application support/canary",
             "managed-settings", "/etc/codex", "claudecode/managed")
INSTALLERS = re.compile(
    r"(\b(npx|bunx)\b(\s+-\S+)*\s+[@\w./-]*\bskills(@\S*)?\s+(add|install|update)\b"
    r"|\b(pnpm|yarn)\s+dlx\s+(-\S+\s+)*[@\w./-]*\bskills(@\S*)?\s+(add|install|update)\b"
    r"|\bclaude\s+plugins?\s+(install|update|marketplace\s+add)\b"
    r"|\bcodex\s+plugins?\s+(install|add|update|marketplace\s+add)\b)", re.I)
SHELL_SYNTAX = set(";&|<>()$`\\\n\r*?[]{}~")
REDIRECT = ("This installs skills or plugins without SkillCanary checking them first. "
            "Use `canary add <link>` instead; it checks the package and asks the person.")
PROTECTED = ("This would change a folder agents load skills or settings from, which "
             "SkillCanary protects. To install a skill, use `canary add <link>`.")
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
             "/etc/codex", "/usr/local/lib/skillcanary", "/usr/local/bin/canary"]
    for adapter in adapters:
        paths += adapter.discovery_roots(home, cwd) + adapter.config_files(home)
    return sorted({os.path.realpath(p) for p in paths})


def _fold(path):
    return os.path.normpath(path).casefold()


def _protected_hit(path, protected):
    """Inside a protected location, or a folder that contains one."""
    p = _fold(os.path.realpath(path))
    for r in protected:
        r = _fold(r)
        if p == r or p.startswith(r.rstrip("/") + "/") or r.startswith(p.rstrip("/") + "/"):
            return True
    return False


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
            if any(_protected_hit(p, protected) for p in call.paths_written):
                return PROTECTED
            quarantine = [r for r in protected if _fold(r).endswith("/canary/quarantine")]
            if any(_protected_hit(p, quarantine) for p in call.paths_read):
                return QUARANTINED
            return None
        if _names_protected(text, protected, home):
            return PROTECTED
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
