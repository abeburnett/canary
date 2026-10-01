"""Command-line entry point. Exit codes are fixed in docs/architecture.md."""

import json
import math
import os
import sys

from canary import add, classify, scan, setup

EXIT_FOR_VERDICT = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 10, "UNSAFE": 20}
EXIT_USAGE = 2
EXIT_INTERNAL = 3

USAGE = ("usage: canary scan <skill-file-or-directory> [--json | --text] [--excerpts]"
         " [--exclude <relative-path>]...\n"
         "       canary check <skill-file-or-directory> [--json | --text] [--excerpts]"
         " [--backend auto|claude|anthropic_api|openai_api|none] [--model <id>]"
         " [--timeout <seconds>]\n"
         "       canary add <github-link-or-folder> [--host claude|codex]... [--json | --text]"
         " [--backend <name>] [--model <id>] [--timeout <seconds>]\n"
         "       canary list [--json]\n"
         "       canary trust <skill-folder-or-skills-folder>\n"
         "       canary setup [--level scan|guard]\n"
         "       canary doctor [--json]\n"
         "       canary digest <folder>")
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


CANARY_BIN = "/Library/Application Support/SkillCanary/bin/canary"


def _hook(args):
    """Answer a host's pre-tool-use hook. Never raises and never exits with
    anything but allow (0, silent) or the host's deny: a crash fails open."""
    host = args[1] if len(args) == 2 and args[0] == "--host" else None
    try:
        from canary import gate
        from canary.hosts import claude, codex
        adapters = {"claude": claude, "codex": codex}
        adapter = adapters.get(host, claude)
    except BaseException:
        sys.stdout.write('{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
                         '"permissionDecision":"deny","permissionDecisionReason":'
                         '"SkillCanary could not start."}}')
        sys.stderr.write("SkillCanary could not start.\n")
        return 2 if host != "codex" else 0
    try:
        if host is None:
            raise ValueError("unknown host")
        payload = gate.envelope(sys.stdin.read())
        home = os.path.expanduser("~")
        try:
            call = adapter.parse_pre_tool_use(payload)
        except ValueError:
            call = gate.unmapped(payload)
        roots = gate.user_skill_roots(home, adapters.values())
        reason = gate.decide(call, home, roots, CANARY_BIN)
    except BaseException:
        reason = gate.UNREADABLE
    if reason is None:
        return 0
    out, code = adapter.deny(reason)
    sys.stdout.write(out)
    sys.stderr.write(reason + "\n")
    return code


def _setup(args):
    level = None
    if args[:1] == ["--level"] and len(args) == 2 and args[1] in setup.LEVELS:
        level = args[1]
    elif args == ["--level", "lockdown"]:
        print("canary: Lockdown was removed; use canary setup --level guard, which also "
              "returns locked skill folders to you.", file=sys.stderr)
        return EXIT_USAGE
    elif args:
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    out, code = setup.setup(level)
    if out["outcome"] == "cancelled":
        print("Setup cancelled; nothing changed.")
    elif out["outcome"] == "not_changed":
        print(f"The password step was not completed; this Mac stays at {out['level']}.")
    else:
        print(f"SkillCanary is set to {out['level']}: {setup.CLAIMS[out['level']]}")
        for m in out["manual"]:
            print(f"\n{m['path']} already exists and belongs to an administrator. "
                  "Add this block to it, then run canary doctor:\n" + m["block"])
    return code


def _doctor(args):
    if args not in ([], ["--json"]):
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    level, gaps, claim = setup.doctor()
    if args:
        print(json.dumps({"level": level, "gaps": gaps, "claim": claim}, indent=2))
    else:
        print(f"Protection level: {level}\nWhat SkillCanary can claim here: {claim}")
        for g in gaps:
            print(f"  Gap: {g}")
    return 10 if gaps else 0


def _list(args):
    from canary import guestlist
    if args not in ([], ["--json"]):
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    try:
        report = guestlist.scan(cwd=os.getcwd())
    except OSError as exc:
        print(f"canary: could not read the guest list ({exc.strerror or exc}).", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2) if args else guestlist.render_text(report))
    return 0


def _trust(args):
    from canary import guestlist
    if len(args) != 1 or args[0].startswith("-"):
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    try:
        names = guestlist.trust(args[0])
    except ValueError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"canary: could not write the guest list ({exc.strerror or exc}).", file=sys.stderr)
        return 1
    print("Marked as yours: " + ", ".join(names))
    return 0


def _session_start(args):
    """A host's SessionStart hook: one notice when a skill needs a look,
    nothing otherwise. Never fails the session: any error is silence."""
    try:
        from canary import guestlist
        host = args[1] if len(args) == 2 and args[0] == "--host" else None
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            payload = {}
        cwd = payload.get("cwd") if isinstance(payload, dict) else None
        line = guestlist.session_line(guestlist.scan(cwd=cwd if isinstance(cwd, str) else None))
        if line and host in ("claude", "codex"):
            sys.stdout.write(json.dumps({"systemMessage": line, "hookSpecificOutput": {
                "hookEventName": "SessionStart", "additionalContext": line}}))
    except BaseException:
        pass
    return 0


def _digest(args):
    if len(args) != 1 or not os.path.isdir(args[0]):
        print(USAGE, file=sys.stderr)
        return EXIT_USAGE
    try:
        print(add.tree_digest(args[0]))
    except add.SourceError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return 0


def main(argv):
    if argv[:1] == ["--version"]:
        from canary import __version__
        print(f"canary {__version__}")
        return 0
    if argv[:1] == ["hook"]:
        return _hook(argv[1:])
    if argv[:1] == ["session-start"]:
        return _session_start(argv[1:])
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
        if command == "setup":
            return _setup(rest)
        if command == "doctor":
            return _doctor(rest)
        if command == "list":
            return _list(rest)
        if command == "trust":
            return _trust(rest)
        if command == "digest":
            return _digest(rest)
        if command == "evidence":
            if len(rest) != 1:
                print(USAGE, file=sys.stderr)
                return EXIT_USAGE
            from canary import evidence
            ev = evidence.produce(rest[0])
            print(json.dumps(ev, indent=2))
            return evidence.EXIT[ev["deterministic"]["verdict"]]
        if command == "_roots" and len(rest) >= 5 and rest[0] == "unlock":
            # Internal: run by the privileged setup step only.
            # It acts as the owner the setup step names: root on a real Mac
            # (tests stand the current user in for root, with owner set to it).
            if os.geteuid() != setup._ids(rest[1])[0]:
                print("canary: _roots runs only inside canary setup's administrator step",
                      file=sys.stderr)
                return EXIT_USAGE
            return setup.change_roots(rest[0], rest[1], rest[2], rest[3], rest[4:])
    except Exception as exc:  # fail closed: callers treat 3 as NEEDS_REVIEW
        # Exception text can quote file names from the package being checked.
        print(f"canary: internal error ({type(exc).__name__})", file=sys.stderr)
        return EXIT_INTERNAL
    print(USAGE, file=sys.stderr)
    return EXIT_USAGE
