"""Identities for `canary.evidence/1` (docs/evidence-contract.md).

Reference implementations shared with the hosted consumer through the vectors
in tests/vectors/evidence-v1.json. The producer (`canary evidence`) is built
on these; nothing here decides a verdict.
"""

import hashlib
import json
import os
import re
import stat

from canary import __version__, scan

COMPONENT_SCHEMA = "canary.component/1"
RULESET_SCHEMA = "canary.ruleset/1"
# Every module whose code decides a text-only/1 result. Hashing their exact
# bytes means no policy input can change without changing the ruleset
# identity (a comment edit changes it too, which is the safe direction).
RULESET_FILES = ("canary/catalog.py", "canary/evidence.py", "canary/scan.py")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def component_id(relative_posix_path, executable, content_sha256):
    """SHA-256 of the UTF-8 compact JSON array
    ["canary.component/1", path, executable, content_sha256], ASCII-escaped.
    Byte-identical files at different paths get different IDs."""
    if (not isinstance(relative_posix_path, str) or not relative_posix_path
            or relative_posix_path.startswith("/") or "\\" in relative_posix_path
            or any(p in ("", ".", "..") for p in relative_posix_path.split("/"))):
        raise ValueError("component path must be a relative POSIX path inside the root")
    if not isinstance(executable, bool):
        raise ValueError("executable must be a boolean")
    if (not isinstance(content_sha256, str) or len(content_sha256) != 64
            or any(c not in "0123456789abcdef" for c in content_sha256)):
        raise ValueError("content_sha256 must be 64 lowercase hex characters")
    encoded = json.dumps([COMPONENT_SCHEMA, relative_posix_path, executable, content_sha256],
                         separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def ruleset_sha256_of(files):
    """files: {relative path: bytes}, exactly RULESET_FILES. The hash of
    "canary.ruleset/1\\n" followed by "<path>\\0<sha256 of bytes>\\n" for each
    path in sorted order."""
    if set(files) != set(RULESET_FILES):
        raise ValueError("ruleset inputs must be exactly RULESET_FILES")
    lines = [RULESET_SCHEMA] + [f"{path}\0{hashlib.sha256(files[path]).hexdigest()}"
                                for path in sorted(files)]
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def ruleset_sha256():
    """The ruleset identity of this installed scanner."""
    files = {}
    for path in RULESET_FILES:
        with open(os.path.join(ROOT, path), "rb") as fh:
            files[path] = fh.read()
    return ruleset_sha256_of(files)


# ---- the text-only/1 producer (`canary evidence`) --------------------------

POLICY = "text-only/1"
MAX_COMPONENTS = 4096
EXIT = {"pass": 0, "review": 10, "block": 20, "error": 3}
RANK = {"pass": 0, "review": 1, "block": 2, "error": 3}
# HTML and SVG can carry scripts when a person opens them, so text-only/1
# does not count reading them as analysing them.
ACTIVE_TEXT = {".html", ".htm", ".svg"}
# Capabilities that describe what kind of file this is, rather than what an
# instruction file says. Any of them means the file is not an instruction.
TYPE_CAPABILITIES = {"script", "unrecognized_file", "executable_bit", "bin_dir",
                     "package_manifest", "plugin_power", "plugin_hooks", "mcp_config"}
# Declared dependencies: the package needs something outside itself.
DEPENDENCY_CAPABILITIES = {"package_manifest", "mcp_config", "skill_dependencies"}

URL = r"https?://\S+"
MD_LINK = re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+)\)")
# "download … and run it", "install from <url>", "curl <url> | sh" ...
RUN_REMOTE = re.compile(
    r"\b(run|execute|exec|install|source|eval|pipe|bash|sh|zsh|python3?|node)\b", re.I)
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)
# "fetch … and follow its instructions", "follow the [latest instructions](url)"
FOLLOW = re.compile(r"\b(follow|obey|apply|execute|carry out)\b", re.I)
INSTRUCTIONS = re.compile(r"\b(instructions?|steps|directions|rules|exactly|commands?)\b", re.I)


def _sentences(text):
    flat = MD_LINK.sub(lambda m: f"{m.group(1)} {m.group(2)}", text)
    return [s for s in re.split(r"(?<=[.!?])\s+|\n", flat) if s.strip()]


def external_references(text):
    """How many sentences tell the agent to run remote code or to fetch and
    follow external instructions. Plain documentation links do not count."""
    count = 0
    for sentence in _sentences(text):
        if PIPE_TO_SHELL.search(sentence):
            count += 1
        elif re.search(URL, sentence) and (
                RUN_REMOTE.search(sentence)
                or (FOLLOW.search(sentence) and INSTRUCTIONS.search(sentence))):
            count += 1
    return count


def _error(reason_code):
    """Evidence for a package that could not be fully analysed. The reason is
    a fixed code, never a path or message."""
    return {"schema": "canary.evidence/1", "policy_version": POLICY,
            "scanner_version": __version__, "ruleset_sha256": ruleset_sha256(),
            "tree_sha256": None, "deterministic": {"verdict": "error", "reason": reason_code},
            "coverage": {"complete": False, "files_total": 0, "files_checked": 0,
                         "unsupported": 0, "unresolved": 0},
            "components": []}


def _inventory(root):
    """[(relative posix path, executable, content sha256)] for every regular
    file, read without following links; None if a link or special file exists."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                return None
            h = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 16), b""):
                    h.update(chunk)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            out.append((rel, bool(st.st_mode & 0o100), h.hexdigest()))
            if len(out) > MAX_COMPONENTS:
                return "too_many"
    return sorted(out)


def produce(root):
    """canary.evidence/1 for the package folder `root` (deterministic only)."""
    from canary import add
    if not os.path.isdir(root) or os.path.islink(root):
        return _error("not_a_folder")
    try:
        inventory = _inventory(root)
        tree = add.tree_digest(root)
    except (OSError, add.SourceError):
        return _error("unreadable")
    if inventory is None:
        return _error("link_or_special_file")
    if inventory == "too_many":
        return _error("too_many_files")
    if not inventory:
        return _error("empty")

    texts = []
    result = scan.scan_package(root, excerpts=True, texts=texts)
    text_of = {rel.replace(os.sep, "/"): t for rel, t in texts}
    caps, findings, skipped = {}, {}, {}
    for c in result["capabilities"]:
        caps.setdefault(c["path"].replace(os.sep, "/"), set()).add(c["kind"])
    for f in result["findings"]:
        if f["severity"] != "info":
            findings.setdefault(f["path"].replace(os.sep, "/"), []).append(f)
    for s in result["coverage"]["skipped"]:
        skipped[s["path"].replace(os.sep, "/")] = s["reason"]

    components, unsupported, unresolved, checked = [], 0, 0, 0
    for rel, executable, sha in inventory:
        ext = os.path.splitext(rel.lower())[1]
        kinds = caps.get(rel, set())
        if rel in skipped:
            kind = "binary" if skipped[rel] == "media" else "unknown"
        elif rel in text_of and not (kinds & TYPE_CAPABILITIES) and ext not in ACTIVE_TEXT:
            kind = "instruction"
        else:
            kind = "unknown"
        supported = kind == "instruction"
        complete = supported and rel in text_of
        if skipped.get(rel) in ("unreadable", "too_large"):
            verdict = "error"
        elif not complete:
            verdict = "review"
        else:
            weights = {}
            for f in findings.get(rel, []):
                w = scan.SEVERITY_WEIGHT[f["severity"]]
                weights[f["check_id"]] = max(w, weights.get(f["check_id"], 0))
            score = sum(weights.values())
            refs = external_references(text_of[rel])
            unresolved += refs
            verdict = ("block" if score >= 6 else
                       "review" if score or (kinds & scan.REVIEW_CAPABILITIES) or refs
                       else "pass")
        if kinds & DEPENDENCY_CAPABILITIES:
            unresolved += 1
        unsupported += not supported
        checked += complete
        components.append({"id": component_id(rel, executable, sha), "kind": kind,
                           "supported": supported, "complete": complete,
                           "deterministic": verdict})

    package = {"LIKELY_SAFE": "pass", "NEEDS_REVIEW": "review", "UNSAFE": "block"}[result["verdict"]]
    # Strictest of the package scan and every component: one unsupported or
    # unresolved file keeps the package from passing.
    for c in components:
        if RANK[c["deterministic"]] > RANK[package]:
            package = c["deterministic"]
    if unresolved and package == "pass":
        package = "review"
    total = len(inventory)
    coverage = {"complete": (result["coverage"]["complete"] and checked == total
                             and not unsupported and not unresolved),
                "files_total": total, "files_checked": checked,
                "unsupported": unsupported, "unresolved": unresolved}
    return {"schema": "canary.evidence/1", "policy_version": POLICY,
            "scanner_version": __version__, "ruleset_sha256": ruleset_sha256(),
            "tree_sha256": tree.split(":", 1)[1], "deterministic": {"verdict": package},
            "coverage": coverage,
            "components": sorted(components, key=lambda c: c["id"])}
