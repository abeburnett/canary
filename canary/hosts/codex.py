"""Codex 0.157 host boundary; decisions and dataclasses belong to canary.gate.

Discovery covers verified local default locations, not configured external
roots, custom project markers/fallback names, or resource-backed skills.
Shell paths are conservative hints, not a shell interpreter or enforcement
proof. The gate must inspect command text and deny parsing failures.
"""
import json
import os
import shlex
from pathlib import Path

_FALLBACK = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
             '"permissionDecision":"deny","permissionDecisionReason":'
             '"Canary could not validate this call. Use canary add <source>."}}', 0)


def install_root(home: str) -> str:
    """User skills folder Codex discovers (docs/codex-facts.md)."""
    return os.path.join(home, ".agents", "skills")


def deny(reason: str) -> tuple[str, int]:
    """Codex consumes JSON decisions at exit 0, including internal failures."""
    try:
        if type(reason) is not str or not reason.strip():
            return _FALLBACK
        return json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": reason[:4096],
        }}, ensure_ascii=True), 0
    except BaseException:
        # This last-resort boundary must not turn a hook failure into permission.
        return _FALLBACK


def _path(value, cwd):
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("Expected a nonempty filesystem path")
    if value.startswith("~") and value != "~" and not value.startswith("~/"):
        raise ValueError("Named-user expansion is not supported")
    path = Path(os.path.expanduser(value))
    if not path.is_absolute():
        path = Path(cwd) / path
    try:
        return str(path.resolve())
    except (OSError, RuntimeError) as exc:
        raise ValueError("Cannot resolve tool path") from exc


def _shell_paths(command, cwd):
    # Do not guess expansion, subprocess or directory-change semantics.
    if any(char in command for char in ("$", "`", "\n", "\r")):
        raise ValueError("Shell expansion or multiline command requires review")
    try:
        tokens = list(shlex.shlex(command, posix=True, punctuation_chars=True))
    except ValueError as exc:
        raise ValueError("Invalid shell quoting") from exc
    if not tokens or any(t in {";", "&&", "||", "|", "&", "(", ")"} for t in tokens):
        raise ValueError("Compound shell commands require review")
    executable = os.path.basename(tokens[0])
    if executable in {"cd", "pushd", "popd", "eval", "exec", "source", "."}:
        raise ValueError("Indirect shell execution requires review")
    reads, writes, args = [], [], []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {">", ">>", "<"}:
            index += 1
            if index == len(tokens):
                raise ValueError("Missing redirect target")
            (reads if token == "<" else writes).append(_path(tokens[index], cwd))
        elif any(c in token for c in "<>"):
            raise ValueError("Unsupported redirection")
        elif not token.startswith("-"):
            args.append(token)
        index += 1
    if executable in {"touch", "mkdir", "rm", "rmdir", "tee"}:
        writes.extend(_path(arg, cwd) for arg in args)
    elif executable in {"cp", "mv"}:
        if len(args) < 2:
            raise ValueError("Missing copy or move paths")
        reads.extend(_path(arg, cwd) for arg in args[:-1])
        writes.append(_path(args[-1], cwd))
        if executable == "mv":
            writes.extend(reads)
    elif executable in {"cat", "head", "tail", "less", "more", "ls", "stat", "wc", "find"}:
        reads.extend(_path(arg, cwd) for arg in args)
    else:
        # Unknown commands still go to the gate with their complete command.
        # Explicit path operands are conservatively both reads and writes.
        for arg in args:
            if arg.startswith(("/", "./", "../", "~/")):
                resolved = _path(arg, cwd)
                reads.append(resolved)
                writes.append(resolved)
    return list(dict.fromkeys(reads)), list(dict.fromkeys(writes))


def _patch_paths(command, cwd):
    lines = command.splitlines()
    if not lines or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("Invalid apply_patch envelope")
    reads, writes = [], []
    active = None
    for line in lines[1:-1]:
        for header in ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "):
            if line.startswith(header):
                target = _path(line[len(header):], cwd)
                if header == "*** Move to: " and active != "*** Update File: ":
                    raise ValueError("Move without update")
                writes.append(target)
                if header in {"*** Update File: ", "*** Delete File: "}:
                    reads.append(target)
                if header != "*** Move to: ":
                    active = header
                break
        else:
            if active is None or (line.startswith("*** ") and line != "*** End of File"):
                raise ValueError("Unrecognized patch section")
    if not writes:
        raise ValueError("Patch contains no file operation")
    return list(dict.fromkeys(reads)), list(dict.fromkeys(writes))


def parse_pre_tool_use(payload: dict):
    """Normalize captured Bash/apply_patch input; opaque tools fail closed."""
    if type(payload) is not dict or payload.get("hook_event_name") != "PreToolUse":
        raise ValueError("Expected PreToolUse payload")
    cwd = payload.get("cwd")
    if type(cwd) is not str or not os.path.isabs(cwd) or "\x00" in cwd:
        raise ValueError("Expected absolute cwd")
    tool, args = payload.get("tool_name"), payload.get("tool_input")
    if type(tool) is not str or type(args) is not dict:
        raise ValueError("Invalid tool envelope")
    command = args.get("command")
    if type(command) is not str or not command.strip() or "\x00" in command:
        raise ValueError("Expected command text")
    if tool == "Bash":
        reads, writes = _shell_paths(command, cwd)
    elif tool == "apply_patch":
        reads, writes = _patch_paths(command, cwd)
    else:
        # MCP arguments have no shared read/write semantics; do not treat an
        # arbitrary argument object as a harmless call with empty paths.
        raise ValueError("Unsupported Codex tool shape")
    from canary.gate import ToolCall
    return ToolCall(tool_name=tool, command=command, paths_read=reads,
                    paths_written=writes, cwd=_path(cwd, cwd))


def _codex_home(home):
    base = os.environ.get("CODEX_HOME") or str(Path(home) / ".codex")
    if not os.path.isabs(base):
        raise ValueError("CODEX_HOME must be absolute")
    return Path(base).resolve()


def _resolved_unique(paths):
    return list(dict.fromkeys(str(Path(path).resolve()) for path in paths))


def discovery_roots(home: str, cwd: str) -> list[str]:
    """Verified local defaults and linked targets; external config is excluded.

    Individual AGENTS files are included as protected paths, rather than
    protecting their entire parent directory (which would block all repo work).
    """
    if not os.path.isabs(home) or not os.path.isabs(cwd):
        raise ValueError("Home and cwd must be absolute")
    home, current = Path(home).resolve(), Path(cwd).resolve()
    ch = _codex_home(home)
    roots = [home / ".agents/skills", ch / "skills", ch / "skills/.system",
             ch / "plugins/cache", ch / "plugins/marketplaces", Path("/etc/codex/skills"),
             ch / "AGENTS.md", ch / "AGENTS.override.md"]
    ancestors = [current, *current.parents]
    repo = next((p for p in ancestors if (p / ".git").exists()), current)
    for directory in ancestors:
        roots.extend([directory / ".agents/skills", directory / ".codex/skills",
                      directory / ".codex/config.toml", directory / ".codex/hooks.json",
                      directory / "AGENTS.md", directory / "AGENTS.override.md"])
        if directory == repo:
            break
    # Include symlink destinations, including nested links, without cycling.
    pending, seen = list(roots), set()
    while pending:
        path = pending.pop()
        resolved = path.resolve()
        if path.is_symlink():
            roots.append(resolved)
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            with os.scandir(resolved) as entries:
                pending.extend(Path(entry.path) for entry in entries
                               if entry.is_symlink() or entry.is_dir(follow_symlinks=False))
    return _resolved_unique(roots)


def config_files(home: str) -> list[str]:
    """Default local policy files; project policy is in discovery_roots."""
    if not os.path.isabs(home):
        raise ValueError("Home must be absolute")
    ch = _codex_home(home)
    # Protect newly created named profiles too, not only files present today.
    paths = [ch] + [ch / name for name in ("config.toml", "hooks.json", "rules", "plugins")]
    paths.extend(ch.glob("*.config.toml"))
    paths.extend(Path("/etc/codex") / name for name in
                 ("config.toml", "hooks.json", "requirements.toml", "managed_config.toml"))
    return _resolved_unique(paths)


def managed_install_plan(canary_bin: str):
    """Return an additive requirements block; never install or modify policy."""
    if type(canary_bin) is not str or not os.path.isabs(canary_bin) or any(
            char in canary_bin for char in ("\x00", "\n", "\r")):
        raise ValueError("Expected an absolute Canary executable path")
    command = shlex.quote(canary_bin) + " hook --host codex"
    content = ('[features]\nhooks = true\n\n[hooks]\nmanaged_dir = "/etc/codex"\n'
               '\n[[hooks.PreToolUse]]\nmatcher = ".*"\n'
               '\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = '
               + json.dumps(command, ensure_ascii=False) + '\n')
    target = "/etc/codex/requirements.toml"
    try:
        os.lstat(target)
    except FileNotFoundError:
        action = "create"
    else:
        action = "manual"
    from canary.gate import PlannedFile
    return [PlannedFile(path=target, content=content, mode=0o644, action=action)]
