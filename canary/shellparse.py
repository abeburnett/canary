"""Conservative shell and path parsing shared by the host adapters.

`shell` maps a command to what it reads and writes, and says whether its
text must also be screened (docs/architecture.md, decision rules 4-5).
It models a small set of commands exactly and treats everything else as
unknown. A ValueError means "cannot map at all"; the gate then screens the
whole command as text.

The lexer is our own, not shlex: shlex cannot tell a quoted `;` from a real
separator, or `2>` from an argument `2` followed by `>`, and both mistakes
turn a write into something that looks like a read.
"""
import os
import re
from pathlib import Path

OPERATORS = ("&&", "||", ";;", "|&", "<<<", "<<", ">>", "&>", ">&", "<&", ">|",
             "|", ";", "&", "<", ">", "(", ")")
SEPARATORS = {"&&", "||", "|", ";", "&"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>"}
GLOB = set("*?[{")

READ_ONLY = {"ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "find",
             "stat", "diff", "cmp", "du", "readlink", "realpath", "basename", "dirname",
             "less", "more", "nl", "od", "strings", "cut", "tr", "column", "comm", "paste",
             "fold", "rev", "shasum", "md5", "jq", "sort", "sed"}
NO_PATHS = {"echo", "printf", "pwd", "true", "false", "which", "type"}
WRITERS = {"touch", "mkdir", "rm", "rmdir", "tee", "cp", "mv"}
INDIRECT = {"cd", "pushd", "popd", "eval", "exec", "source", "."}
FIND_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0",
                "-fprintf", "-fls"}
RECURSIVE = {"find", "rg", "du"}
SED_READ = re.compile(r"(\d+|\$)(,(\d+|\$))?p")

# Subcommands that change only the index, refs or history, never the files
# in the working tree. Everything else, including aliases, rewrites the tree.
GIT_TREE_SAFE = {"status", "log", "diff", "show", "blame", "ls-files", "ls-tree",
                 "rev-parse", "grep", "shortlog", "describe", "cat-file", "rev-list",
                 "merge-base", "for-each-ref", "show-ref", "branch", "tag", "add",
                 "commit", "fetch", "push"}


def path(value, cwd):
    if not isinstance(value, str) or not value or "\x00" in value:
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


class Word(str):
    """A word with its quotes removed; `globbed` when it has an unquoted
    glob or brace the shell would expand."""
    globbed = False


def _word(raw_chars):
    text, globbed = "", False
    for char, quoted in raw_chars:
        text += char
        if not quoted and char in GLOB:
            globbed = True
    word = Word(text)
    word.globbed = globbed
    return word


def lex(command):
    """[("op", text) | ("word", Word) | ("fd", digits)]. Backslashes,
    expansion and newlines cannot be mapped."""
    if any(c in command for c in ("\\", "$", "`", "\n", "\r", "\x00")):
        raise ValueError("Escapes, expansion or multiline commands require review")
    tokens, chars, quote, started = [], [], None, False

    def flush():
        nonlocal chars, started
        if started:
            tokens.append(("word", _word(chars)))
        chars, started = [], False

    i = 0
    while i < len(command):
        c = command[i]
        if quote:
            if c == quote:
                quote = None
            else:
                chars.append((c, True))
            i += 1
            continue
        if c in "'\"":
            quote, started = c, True
            i += 1
            continue
        if c.isspace():
            flush()
            i += 1
            continue
        op = next((o for o in OPERATORS if command.startswith(o, i)), None)
        if op:
            # `2>` is a file-descriptor number only when it touches the operator.
            if (op[0] in "<>" and started and chars
                    and all(ch.isdigit() and not q for ch, q in chars)):
                tokens.append(("fd", "".join(ch for ch, _ in chars)))
                chars, started = [], False
            else:
                flush()
            tokens.append(("op", op))
            i += len(op)
            continue
        chars.append((c, False))
        started = True
        i += 1
    if quote:
        raise ValueError("Unclosed quote")
    flush()
    return tokens


def _segments(tokens):
    """Split at separators: [(separator before, words, redirects)]."""
    segments, words, redirects, before = [], [], [], None
    i = 0
    while i < len(tokens):
        kind, value = tokens[i]
        if kind == "fd":
            i += 1
            continue
        if kind == "word":
            words.append(value)
        elif value in SEPARATORS:
            if not words and not redirects:
                raise ValueError("Empty command in a chain")
            segments.append((before, words, redirects))
            words, redirects, before = [], [], value
        elif value in WRITE_REDIRECTS | {"<", ">&", "<&"}:
            if i + 1 >= len(tokens) or tokens[i + 1][0] != "word":
                raise ValueError("Missing redirect target")
            redirects.append((value, tokens[i + 1][1]))
            i += 1
        else:
            raise ValueError("Subshells, heredocs and here-strings require review")
        i += 1
    if words or redirects:
        segments.append((before, words, redirects))
    elif before is not None and before != "&":
        raise ValueError("Chain ends in an operator")
    if not segments:
        raise ValueError("Empty command")
    return segments


class Mapped:
    def __init__(self):
        self.reads, self.writes = [], []
        self.trees_read, self.trees_written = [], []
        self.screen = False


def _target(word, cwd):
    """A path for one word; a globbed word stands for its fixed prefix folder."""
    if not word.globbed:
        return path(word, cwd), False
    fixed = re.split(r"[*?\[{]", word, maxsplit=1)[0]
    folder = fixed if fixed.endswith("/") else os.path.dirname(fixed)
    return path(folder or ".", cwd), True


def _read(m, word, cwd, recursive=False):
    p, globbed = _target(word, cwd)
    (m.trees_read if recursive or globbed else m.reads).append(p)


def _write(m, word, cwd):
    p, globbed = _target(word, cwd)
    # A glob can land anywhere under its folder, so the folder is written.
    m.writes.append(p)


def _looks_like_path(word):
    return word.startswith(("/", "./", "../", "~/")) or word == "~"


def _unknown(m, words, cwd):
    """No model of this command: screen its text, and count every argument
    that looks like a path, including option values, as read and written."""
    m.screen = True
    for word in words[1:]:
        value = word.split("=", 1)[1] if word.startswith("-") and "=" in word else word
        if _looks_like_path(value) or word.globbed:
            v = Word(value)
            v.globbed = word.globbed
            _read(m, v, cwd)
            _write(m, v, cwd)


def _repo_top(folder):
    for p in (Path(folder), *Path(folder).parents):
        if (p / ".git").exists():
            return str(p)
    return folder


def _git(m, words, cwd):
    i, folder = 1, cwd
    while i < len(words) and words[i].startswith("-"):
        if words[i] == "-C" and i + 1 < len(words):
            folder = path(words[i + 1], folder)
            i += 2
        elif words[i] in ("--no-pager", "-P"):
            i += 1
        else:
            # -c, --git-dir, --work-tree and the rest can point git anywhere.
            m.trees_written.append(_repo_top(folder))
            _unknown(m, words, cwd)
            return
    sub, rest = (words[i], words[i + 1:]) if i < len(words) else ("status", [])
    if sub not in GIT_TREE_SAFE:
        m.trees_written.append(_repo_top(folder))
        for word in rest:
            if _looks_like_path(word):
                _write(m, word, folder)
        return
    m.trees_read.append(folder)
    for word in rest:
        if word.startswith("--output"):
            value = word.split("=", 1)[1] if "=" in word else None
            if value is None:
                raise ValueError("git --output needs its value attached")
            _write(m, Word(value), folder)
        elif word in ("-O", "--open-files-in-pager") or word.startswith(("-O", "--ext-diff")):
            m.trees_written.append(_repo_top(folder))
        elif _looks_like_path(word):
            _read(m, word, folder)


def _read_only(m, name, words, cwd):
    args = words[1:]
    if name == "find" and any(a in FIND_ACTIONS for a in args):
        return False
    if name == "rg" and any(a.startswith("--pre") for a in args):
        return False
    if name == "sort" and any(a.startswith("--output") or (
            a.startswith("-") and not a.startswith("--") and "o" in a) for a in args):
        return False
    if name == "sed":
        options = [a for a in args if a.startswith("-")]
        operands = [a for a in args if not a.startswith("-")]
        if set(options) - {"-n", "-E", "-r"} or not operands or not SED_READ.fullmatch(operands[0]):
            return False
        args = operands[1:]
    recursive = name in RECURSIVE or (
        name in ("grep", "egrep", "fgrep", "ls")
        and any(a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a)
                or a in ("--recursive", "--dereference-recursive") for a in args))
    for arg in args:
        if not arg.startswith("-"):
            _read(m, arg, cwd, recursive)
    return True


def _writer(m, name, words, cwd):
    args = [a for a in words[1:] if not a.startswith("-")]
    if any(a in ("-t", "--target-directory") or a.startswith("--target-directory")
           for a in words[1:]):
        raise ValueError("Target-directory options require review")
    if name in {"touch", "mkdir", "rm", "rmdir", "tee"}:
        for arg in args:
            _write(m, arg, cwd)
        return
    if len(args) < 2:
        raise ValueError("Missing copy or move paths")
    for arg in args[:-1]:
        _read(m, arg, cwd, recursive=True)
        if name == "mv":
            _write(m, arg, cwd)
    _write(m, args[-1], cwd)


def shell(command, cwd):
    """A Mapped result for a shell command, or ValueError."""
    segments = _segments(lex(command))
    m = Mapped()
    for index, (before, words, redirects) in enumerate(segments):
        after = segments[index + 1][0] if index + 1 < len(segments) else None
        for op, target in redirects:
            if op in (">&", "<&") and (target.isdigit() or target == "-"):
                continue
            if op == "<":
                _read(m, target, cwd)
            else:
                _write(m, target, cwd)
        if not words:
            continue
        name = os.path.basename(words[0])
        if words[0].globbed:
            raise ValueError("A globbed command name requires review")
        if name == "cd":
            # Only a plain `cd dir &&` or `cd dir ;` moves what follows.
            if before in ("|", "||", "&") or after in ("|", "||", "&") or len(words) > 2:
                raise ValueError("A directory change that may not happen requires review")
            if len(words) == 2 and (words[1] == "-" or words[1].globbed):
                raise ValueError("cd - or a globbed cd requires review")
            cwd = path(words[1] if len(words) == 2 else "~", cwd)
            continue
        if name in INDIRECT:
            raise ValueError("Indirect shell execution requires review")
        if name in NO_PATHS:
            continue
        if name == "git":
            _git(m, words, cwd)
        elif name in WRITERS:
            _writer(m, name, words, cwd)
        elif not (name in READ_ONLY and _read_only(m, name, words, cwd)):
            _unknown(m, words, cwd)
    for attr in ("reads", "writes", "trees_read", "trees_written"):
        setattr(m, attr, list(dict.fromkeys(getattr(m, attr))))
    return m
