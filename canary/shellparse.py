"""Conservative shell and path parsing shared by the host adapters.

Moved unchanged from canary/hosts/codex.py so both adapters map shell
commands the same way. A ValueError means "cannot map exactly"; the gate
then screens the command as text (docs/architecture.md, decision rule 4).
"""
import os
import shlex
from pathlib import Path


def path(value, cwd):
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


def shell_paths(command, cwd):
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
            (reads if token == "<" else writes).append(path(tokens[index], cwd))
        elif any(c in token for c in "<>"):
            raise ValueError("Unsupported redirection")
        elif not token.startswith("-"):
            args.append(token)
        index += 1
    if executable in {"touch", "mkdir", "rm", "rmdir", "tee"}:
        writes.extend(path(arg, cwd) for arg in args)
    elif executable in {"cp", "mv"}:
        if len(args) < 2:
            raise ValueError("Missing copy or move paths")
        reads.extend(path(arg, cwd) for arg in args[:-1])
        writes.append(path(args[-1], cwd))
        if executable == "mv":
            writes.extend(reads)
    elif executable in {"cat", "head", "tail", "less", "more", "ls", "stat", "wc", "find"}:
        reads.extend(path(arg, cwd) for arg in args)
    else:
        # Unknown commands still go to the gate with their complete command.
        # Explicit path operands are conservatively both reads and writes.
        for arg in args:
            if arg.startswith(("/", "./", "../", "~/")):
                resolved = path(arg, cwd)
                reads.append(resolved)
                writes.append(resolved)
    return list(dict.fromkeys(reads)), list(dict.fromkeys(writes))
