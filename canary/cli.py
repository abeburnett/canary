"""Command-line entry point. Exit codes are fixed in docs/architecture.md."""

import json
import sys

from canary import scan

EXIT_FOR_VERDICT = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 10, "UNSAFE": 20}
EXIT_USAGE = 2
EXIT_INTERNAL = 3

USAGE = ("usage: canary scan <skill-file-or-directory> [--json | --text] [--excerpts]"
         " [--exclude <relative-path>]...")


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


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if argv else EXIT_USAGE
    command, rest = argv[0], argv[1:]
    try:
        if command == "scan":
            return _scan(rest)
    except Exception as exc:  # fail closed: callers treat 3 as NEEDS_REVIEW
        print(f"canary: internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    print(USAGE, file=sys.stderr)
    return EXIT_USAGE
