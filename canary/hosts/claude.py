"""Claude Code host boundary (docs/architecture.md, "Host adapters").

Deny contract verified 2026-09-26 on the installed Claude Code: a reason on
stderr with exit 2 blocks, deny JSON blocks at exit 0 or 2, and a hook that
exits 1 lets the call run. `deny` returns the JSON with exit 2 and the hook
command also writes the reason to stderr, so either reading blocks.
"""
import json
import os
import shlex
from pathlib import Path

from canary.shellparse import path as _path, shell as _shell

MANAGED_DIR = "/Library/Application Support/ClaudeCode/managed-settings.d"
FILE_TOOLS = {"Write": ("file_path", "w"), "Edit": ("file_path", "w"),
              "MultiEdit": ("file_path", "w"), "NotebookEdit": ("notebook_path", "w"),
              "Read": ("file_path", "r"), "Glob": ("path", "r"), "Grep": ("path", "r"),
              "LS": ("path", "r")}
SEARCH_TOOLS = {"Glob", "Grep", "LS"}
# Tools whose input is only words for a person or another agent. They touch
# no files, and whatever they start is itself checked by this hook, so the
# words may name a protected folder.
TEXT_TOOLS = {"AskUserQuestion", "TodoWrite", "Agent", "Task", "SendMessage",
              "EnterPlanMode", "ExitPlanMode", "mcp__ccd_session__spawn_task",
              "mcp__ccd_session__mark_chapter"}
_FALLBACK = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
             '"permissionDecision":"deny","permissionDecisionReason":'
             '"Canary could not validate this call. Use canary add <source>."}}', 2)


def install_root(home: str) -> str:
    """User-level skills folder Claude Code discovers."""
    return os.path.join(home, ".claude", "skills")


def deny(reason: str) -> tuple[str, int]:
    try:
        if type(reason) is not str or not reason.strip():
            return _FALLBACK
        return json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": reason[:4096]}}, ensure_ascii=True), 2
    except BaseException:
        return _FALLBACK


def parse_pre_tool_use(payload: dict):
    """File tools and simple shell commands map exactly; anything else
    raises ValueError and the gate screens it as text."""
    from canary.gate import ToolCall
    if type(payload) is not dict or payload.get("hook_event_name") != "PreToolUse":
        raise ValueError("Expected PreToolUse payload")
    cwd, tool, args = payload.get("cwd"), payload.get("tool_name"), payload.get("tool_input")
    if type(cwd) is not str or not os.path.isabs(cwd) or type(args) is not dict:
        raise ValueError("Invalid tool envelope")
    if tool in FILE_TOOLS:
        key, mode = FILE_TOOLS[tool]
        value = args.get(key)
        if value is None and mode == "r" and tool != "Read":
            value = cwd
        target = _path(value, cwd)
        if tool in SEARCH_TOOLS:
            return ToolCall(tool, None, [], [], cwd, trees_read=[target])
        return ToolCall(tool, None, [target] if mode == "r" else [],
                        [target] if mode == "w" else [], cwd)
    if tool in TEXT_TOOLS:
        return ToolCall(tool, None, [], [], cwd)
    if tool == "Bash":
        command = args.get("command")
        if type(command) is not str or not command.strip():
            raise ValueError("Expected command text")
        m = _shell(command, cwd)
        return ToolCall(tool, command, m.reads, m.writes, cwd, trees_read=m.trees_read,
                        trees_written=m.trees_written, screen=m.screen)
    raise ValueError("Tool without file semantics")


def discovery_roots(home: str, cwd: str) -> list[str]:
    """User and project folders Claude Code loads skills, commands, agents,
    plugins or hooks from, walking from cwd up to the repository root."""
    home_p, current = Path(home).resolve(), Path(cwd).resolve()
    roots = [home_p / ".claude" / d for d in ("skills", "commands", "agents", "plugins")]
    ancestors = [current, *current.parents]
    repo = next((p for p in ancestors if (p / ".git").exists()), current)
    for directory in ancestors:
        roots += [directory / ".claude" / d for d in ("skills", "commands", "agents")]
        roots += [directory / ".claude" / "settings.json",
                  directory / ".claude" / "settings.local.json", directory / ".mcp.json"]
        if directory == repo:
            break
    return sorted({str(p.resolve()) for p in roots})


def config_files(home: str) -> list[str]:
    h = Path(home).resolve()
    return sorted({str(p) for p in (h / ".claude" / "settings.json",
                                    h / ".claude" / "settings.local.json",
                                    h / ".claude.json", Path(MANAGED_DIR).parent)})


def managed_install_plan(canary_bin: str):
    """One drop-in file Canary owns; never touches other managed files."""
    from canary.gate import PlannedFile
    if type(canary_bin) is not str or not os.path.isabs(canary_bin) or any(
            c in canary_bin for c in ("\x00", "\n", "\r", '"', "'")):
        raise ValueError("Expected an absolute Canary executable path")
    settings = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command",
         "command": f"/usr/bin/python3 -I -B {shlex.quote(canary_bin)} hook --host claude"}]}]}}
    target = os.path.join(MANAGED_DIR, "canary.json")
    action = "manual" if os.path.lexists(target) else "create"
    return [PlannedFile(path=target, content=json.dumps(settings, indent=2) + "\n",
                        mode=0o644, action=action)]
