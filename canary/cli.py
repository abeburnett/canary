"""Command-line entry point. Exit codes are fixed in docs/architecture.md."""

import json
import math
import sys

from canary import add, classify, scan

EXIT_FOR_VERDICT = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 10, "UNSAFE": 20}
EXIT_USAGE = 2
EXIT_INTERNAL = 3

USAGE = ("usage: canary scan <skill-file-or-directory> [--json | --text] [--excerpts]"
         " [--exclude <relative-path>]...\n"
         "       canary check <skill-file-or-directory> [--json | --text] [--excerpts]"
         " [--backend auto|claude|anthropic_api|openai_api|none] [--model <id>]"
         " [--timeout <seconds>]\n"
         "       canary add <github-link-or-folder> [--host claude|codex]... [--json | --text]"
         " [--backend <name>] [--model <id>] [--timeout <seconds>]")
VALUE_FLAGS = {"--backend", "--model", "--timeout"}


def _scan(args):
    exclude, rest, i = [], [], 0
    while i < len(args):
        if args[i] == "--exclude" and i + 1 < len(args):
            exclude.append(args[i + 1])
            i += 2
            continue
        rest.append(args[i])
        i += 1
    args = rest
    paths = [a for a in args if not a.startswith("--")]
    flags = {a for a in args if a.startswith("--")}
    unknown = flags - {"--json", "--text", "--excerpts"}
    if len(paths) != 1 or unknown:
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    try:
        result = scan.scan_package(paths[0], excerpts="--excerpts" in flags, exclude=exclude)
    except scan.PathError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if "--text" in flags:
        print(scan.render_text(result))
    else:
        print(json.dumps(result, indent=2))
    return EXIT_FOR_VERDICT[result["verdict"]]


def _check(args):
    values, rest, i = {}, [], 0
    while i < len(args):
        if args[i] in VALUE_FLAGS:
            if i + 1 >= len(args) or args[i] in values:
                print(USAGE, file=sys.stderr)
                return EXIT_USAGE
            values[args[i]] = args[i + 1]
            i += 2
            continue
        rest.append(args[i])
        i += 1
    paths = [a for a in rest if not a.startswith("--")]
    flags = {a for a in rest if a.startswith("--")}
    backend = values.get("--backend", "auto")
    try:
        timeout = float(values.get("--timeout", classify.DEFAULT_TIMEOUT_S))
    except ValueError:
        timeout = -1
    if (len(paths) != 1 or flags - {"--json", "--text", "--excerpts"}
            or not math.isfinite(timeout) or timeout <= 0
            or backend not in ("auto", "claude", "anthropic_api", "openai_api", "none")):
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    try:
        result = classify.check(paths[0], backend=backend, model=values.get("--model"),
                                timeout_s=timeout, excerpts="--excerpts" in flags)
    except scan.PathError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if "--text" in flags:
        print(classify.render_text(result))
    else:
        print(json.dumps(result, indent=2))
    return EXIT_FOR_VERDICT[result["verdict"]]


def _add(args):
    values, hosts, rest, i = {}, [], [], 0
    while i < len(args):
        if args[i] in VALUE_FLAGS | {"--host"}:
            if i + 1 >= len(args) or args[i] in values:
                print(USAGE, file=sys.stderr)
                return EXIT_USAGE
            if args[i] == "--host":
                hosts.append(args[i + 1])
            else:
                values[args[i]] = args[i + 1]
            i += 2
            continue
        rest.append(args[i])
        i += 1
    sources = [a for a in rest if not a.startswith("-")]
    flags = {a for a in rest if a.startswith("-")}
    backend = values.get("--backend", "auto")
    try:
        timeout = float(values.get("--timeout", classify.DEFAULT_TIMEOUT_S))
    except ValueError:
        timeout = -1
    # No flag approves an install: only the person, in the dialog.
    if (len(sources) != 1 or flags - {"--json", "--text"}
            or not math.isfinite(timeout) or timeout <= 0
            or set(hosts) - set(add.HOSTS)
            or backend not in ("auto", "claude", "anthropic_api", "openai_api", "none")):
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    try:
        out = add.add(sources[0], backend=backend, model=values.get("--model"),
                      timeout_s=timeout, hosts=hosts or None)
    except add.SourceError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except add.LockError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    print(add.render_text(out) if "--text" in flags else json.dumps(out, indent=2))
    return add.EXIT_FOR_OUTCOME[out["outcome"]]


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if argv else EXIT_USAGE
    command, rest = argv[0], argv[1:]
    try:
        if command == "scan":
            return _scan(rest)
        if command == "check":
            return _check(rest)
        if command == "add":
            return _add(rest)
    except Exception as exc:  # fail closed: callers treat 3 as NEEDS_REVIEW
        print(f"canary: internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    print(USAGE, file=sys.stderr)
    return EXIT_USAGE
