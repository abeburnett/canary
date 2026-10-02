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

from canary.shellparse import given as _given, path as _path

MANAGED_DIR = "/Library/Application Support/ClaudeCode/managed-settings.d"
FILE_TOOLS = {"Write": ("file_path", "w"), "Edit": ("file_path", "w"),
              "MultiEdit": ("file_path", "w"), "NotebookEdit": ("notebook_path", "w"),
              "Read": ("file_path", "r"), "Glob": ("path", "r"), "Grep": ("path", "r"),
              "LS": ("path", "r")}
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


# A rewritten install runs the installer, the checks and the person's dialog,
# so it gets Claude Code's longest Bash timeout (ten minutes).
REWRITE_TIMEOUT_MS = 600000
CAN_REWRITE = True


def rewrite(tool_input: dict, command: str) -> tuple[str, int]:
    """Replace the call's command and leave the decision to the person's own
    permission settings. Verified live (2026-10-01, `claude -p`): with no
    permissionDecision, Claude Code checks the replaced command against the
    person's rules and runs it only if they allow it; with "allow" it would
    skip that check. Hooks do not run again on the replaced command."""
    updated = {"command": command, "timeout": REWRITE_TIMEOUT_MS}
    if isinstance(tool_input.get("description"), str):
        updated["description"] = tool_input["description"]
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "updatedInput": updated}}, ensure_ascii=True), 0


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
        target = _given(value, cwd)
        return ToolCall(tool, None, [target] if mode == "r" else [],
                        [target] if mode == "w" else [], cwd)
    # Every other tool, the shell included, is looked at only as a command.
    command = args.get("command")
    return ToolCall(tool, command if isinstance(command, str) else None, [], [], cwd)


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
    run = f"/usr/bin/python3 -I -B {shlex.quote(canary_bin)}"
    settings = {"hooks": {
        "PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": f"{run} hook --host claude"}]}],
        # The guest list: one notice when a skill arrived without the check or
        # changed since approval, nothing otherwise.
        "SessionStart": [{"matcher": "startup|resume|clear", "hooks": [
            {"type": "command", "command": f"{run} session-start --host claude"}]}]}}
    target = os.path.join(MANAGED_DIR, "canary.json")
    action = "manual" if os.path.lexists(target) else "create"
    return [PlannedFile(path=target, content=json.dumps(settings, indent=2) + "\n",
                        mode=0o644, action=action)]
