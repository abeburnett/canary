"""The gate's decision, independent of any host (docs/architecture.md,
"canary hook", decision rules).

SkillCanary is a front door: it checks a skill before any agent can use it.
The hook's only job is to send installs through that check. It stops an
agent's installer command, and a file tool that creates a skill that is not
there yet. Everything else passes, including edits to installed skills: a
skill that changes or arrives another way is for the guest list and the
watcher to report, not for the hook to block (program 2026-09-30).
"""

import json
import os
import re
import shlex
import shutil
from dataclasses import dataclass

from canary import installers

SUPPORT = os.path.join("Library", "Application Support", "Canary")
# Skills folders in any repository, and the user-level ones by the same name.
SKILL_ROOTS = (".claude/skills", ".agents/skills", ".codex/skills")
SHELL_SYNTAX = set(";&|<>()$`\\\n\r*?[]{}~")
SHELL_TOOLS = {"Bash"}
# A shell command naming the quarantine reads or changes a package that is
# still waiting for its check.
QUARANTINE_TEXT = re.compile(r"application\\?\s*support/canary/quarantine", re.I)
REDIRECT = ("This installs skills or plugins without SkillCanary checking them first. "
            "Run the installer as a command of its own through `canary install -- <command>` "
            "(for example `canary install -- npx skills add <owner/repo>`), or use "
            "`canary add <link>`; both check what it adds and ask the person.")
INSTALL_INSTEAD = ("SkillCanary checks skills and plugins before they are installed. Run "
                   "this instead; it runs the same installer, checks what it adds and asks "
                   "the person: canary install -- {command}")
NEW_SKILL = ("This creates a new skill without SkillCanary checking it first. To install a "
             "skill, use `canary add <link or folder>`; it checks it and asks the person. "
             "Editing a skill that is already installed is allowed.")
RECORD = ("That is SkillCanary's own record of what was installed and checked. "
          "Agents may read it but not rewrite it; canary trust and canary add change it.")
QUARANTINED = ("That file is a quarantined package SkillCanary has not approved. "
               "Agents may not read it; use `canary check` for a verdict.")
WATCHER = ("That is SkillCanary's watcher, which holds skills that arrive without a check. "
           "Agents may not stop or change it; the person can, with canary setup.")
# The watcher's label or launch-agent file named in a shell command (decision
# 10): as with installer words, a command that only mentions it is denied too.
WATCHER_TEXT = re.compile(r"com\.skillcanary\.watcher", re.I)
UNREADABLE = ("SkillCanary could not check this tool call, so it is blocked. "
              "If it is harmless, ask the person to run it in their own terminal.")


@dataclass(frozen=True)
class Rewrite:
    """Allow the call, with its command replaced (Claude Code's updatedInput)."""
    command: str


@dataclass
class ToolCall:
    tool_name: str
    command: object          # shell or patch text, or None for file tools
    paths_read: list
    paths_written: list
    cwd: str


@dataclass
class PlannedFile:
    path: str
    content: str
    mode: int
    action: str              # "create" or "manual"


def quarantine_dir(home):
    return os.path.join(home, SUPPORT, "quarantine")


def user_skill_roots(home, adapters):
    """Each host's user-level skills folder (CODEX_HOME's included)."""
    roots = [adapter.install_root(home) for adapter in adapters]
    for adapter in adapters:
        roots += getattr(adapter, "extra_skill_roots", lambda h: [])(home)
    return sorted({os.path.realpath(r) for r in roots})


def _fold(path):
    return os.path.normpath(path).casefold()


def _inside(p, r):
    return p == r or p.startswith(r.rstrip("/") + "/")


def _skill_folder(path, roots):
    """The skill folder a path lies in (the first folder under a skills
    folder), or None. Matches the user-level roots and any repository's
    `.claude/skills`, `.agents/skills` or `.codex/skills`, ignoring case."""
    norm = os.path.normpath(path)
    p = norm.casefold()
    # Case folding can change a name's length; then work on the folded form,
    # which can only make a SKILL.md harder to find (fails closed).
    base = norm if len(norm) == len(p) else p
    candidates = [_fold(r).rstrip("/") for r in roots]
    for rel in SKILL_ROOTS:
        i = p.find("/" + rel + "/")
        if i >= 0:
            candidates.append(p[:i + 1 + len(rel)])
    for root in sorted(candidates, key=len, reverse=True):
        if p.startswith(root + "/"):
            rest = p[len(root) + 1:]
            if "/" in rest:             # a file inside a folder under the root
                return base[:len(root) + 1 + rest.index("/")]
    return None


def _creates_skill(path, roots):
    """A write that makes a skill: into a skill folder that has no SKILL.md
    yet. Checked on the path as given and as resolved, so a link into a
    skills folder counts too."""
    for candidate in {os.path.abspath(path), os.path.realpath(path)}:
        folder = _skill_folder(candidate, roots)
        if folder and not os.path.isfile(os.path.join(folder, "SKILL.md")):
            return True
    return False


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


def decide(call, home, roots, canary_bin=None, can_rewrite=False):
    """A deny reason, None to allow, or a Rewrite (only when the host can
    rewrite a command). Any internal error denies."""
    try:
        if call.tool_name in SHELL_TOOLS and isinstance(call.command, str):
            if _is_canary(call.command, canary_bin):
                return None
            in_skills = lambda p: any(_skill_folder(c, roots) for c in
                                      {os.path.abspath(p), os.path.realpath(p)})
            if installers.installs(call.command, call.cwd, in_skills):
                parsed = installers.supported(call.command)
                if parsed is None:
                    return REDIRECT
                words = shlex.join(parsed[1])
                if can_rewrite and canary_bin:
                    return Rewrite(f"/usr/bin/python3 -I -B {shlex.quote(canary_bin)} "
                                   f"install -- {words}")
                return INSTALL_INSTEAD.format(command=words)
            if QUARANTINE_TEXT.search(call.command):
                return QUARANTINED
            if WATCHER_TEXT.search(installers.tidy(call.command)):
                return WATCHER
        if call.tool_name == "apply_patch" and not call.paths_written:
            return UNREADABLE  # a patch the adapter could not read
        if any(_creates_skill(p, roots) for p in call.paths_written):
            return NEW_SKILL
        support = _fold(os.path.realpath(os.path.join(home, SUPPORT)))
        lockfile = _fold(os.path.realpath(os.path.join(home, ".agents", ".canary-lock.json")))
        quarantine_root = _fold(os.path.realpath(quarantine_dir(home)))
        agent_file = _fold(os.path.realpath(os.path.join(
            home, "Library", "LaunchAgents", "com.skillcanary.watcher.plist")))
        for p in call.paths_written:
            f = _fold(os.path.realpath(p))
            if f == agent_file:
                return WATCHER
            if (_inside(f, support) and not _inside(f, quarantine_root)) or f == lockfile:
                return RECORD
        quarantine = _fold(os.path.realpath(quarantine_dir(home)))
        if any(_inside(_fold(os.path.realpath(p)), quarantine)
               for p in call.paths_read + call.paths_written):
            return QUARANTINED
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
    """A ToolCall for input the adapter could not map: only a shell command
    is looked at (for installers)."""
    tool_input = payload["tool_input"]
    command = tool_input.get("command") if isinstance(tool_input.get("command"), str) else None
    return ToolCall(payload["tool_name"], command, [], [], payload["cwd"])
