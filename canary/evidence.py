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
#
# Contract draft 6: the deterministic `pass` claims only properties a check
# can be complete about (prose file types, no matching tag-openers, no
# shebang, an allowlisted frontmatter, definite outside references). Whether
# prose contains code or sends the agent elsewhere is a judgment about
# meaning: the hosted semantic record answers it for every package. The
# pattern heuristics below remain as extra review triggers only.

POLICY = "text-only/1"
MAX_COMPONENTS = 4096
EXIT = {"pass": 0, "review": 10, "block": 20, "error": 3}
RANK = {"pass": 0, "review": 1, "block": 2, "error": 3}

PROSE_EXTENSIONS = {".md", ".markdown", ".txt", ".text", ".rst", ".adoc"}
BADGE_FRONTMATTER_KEYS = {"name", "description", "license"}
TAG_OPENER = re.compile(r"<[A-Za-z!/?]")
BLOCK_SCALARS = {">", "|", ">-", "|-", ">+", "|+"}
PARENT_SEGMENT = re.compile(r"\.\.[/\\]")
PLAIN_SCALAR = re.compile(r"""^[^\s"'\[\]{}|>&*!%@`#,][^#]*$""")
QUOTED_SCALAR = re.compile(r"""^(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*')$""")
AUTOLINK = re.compile(r"<(?:[a-z][a-z0-9+.-]*:[^>\s]+)>", re.I)
HREF = re.compile(r"\bhref\s*=", re.I)
TYPE_CAPABILITIES = {"script", "unrecognized_file", "executable_bit", "bin_dir",
                     "package_manifest", "plugin_power", "plugin_hooks", "mcp_config"}
DEPENDENCY_CAPABILITIES = {"package_manifest", "mcp_config", "skill_dependencies"}
DEPENDENCY_NAME = re.compile(
    r"(^|/)(requirements[\w.-]*\.(txt|in)|constraints[\w.-]*\.txt|environment\.ya?ml|"
    r"pipfile(\.lock)?|pyproject\.toml|setup\.(py|cfg)|package(-lock)?\.json|"
    r"(yarn|pnpm-lock|bun|deno|poetry|cargo|gemfile|composer)\.(lock|lockb|yaml|json)|"
    r"gemfile|cargo\.toml|go\.(mod|sum)|composer\.json|deno\.jsonc?|\.mcp\.json|mcp\.json|"
    r"[\w.-]*\.lock)$", re.I)
FRONTMATTER_DEPENDENCY_KEYS = {"dependencies", "requires", "mcp", "mcpservers",
                               "mcp_servers", "tools", "install", "setup"}

SOURCE_LINE = re.compile(
    r"^\s*(import\s+[\w.]+|from\s+[\w.]+\s+import\b|def\s+\w+\s*\(|class\s+\w+\s*[:(]"
    r"|function\s+\w+\s*\(|(const|let|var)\s+\w+\s*=|console\.\w+\s*\(|print\s*\("
    r"|require\s*\(|#include\b|package\s+\w+\s*;|fn\s+\w+\s*\(|public\s+(static\s+)?\w+"
    r"|export\s+\w+=|sudo\s|chmod\s|rm\s+-\w|\$\s*\(|eval\s)", re.M)
FENCE = re.compile(r"^\s*(```|~~~)")

SCHEME_URL = r"[a-z][a-z0-9+.-]*://[^\s<>\"')\]]+"
BARE_URL = r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>\"')\]]*)"
URLISH = re.compile(rf"{SCHEME_URL}|{BARE_URL}", re.I)
MD_LINK = re.compile(r"\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)")
REF_DEF = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*<?(\S+?)>?(?:\s.*)?$", re.M)
REF_USE = re.compile(r"\[([^\]]*)\]\s*\[([^\]]*)\]")
SHORTCUT = re.compile(r"\[([^\]]+)\](?![(\[:])")
HTML_ANCHOR = re.compile(r"<a\b[^>]*?\bhref\s*=\s*[\"']?([^\"'\s>]+)[^>]*>(.*?)</a\s*>", re.I | re.S)
GET_OR_RUN = re.compile(
    r"\b(run|runs|execute|exec|install|source|eval|pipe|launch|start|download|fetch|retrieve|"
    r"curl|wget|clone|pull|load|import|bash|sh|zsh|python3?|node)\b", re.I)
FOLLOW = re.compile(r"\b(follow|obey|comply|adhere|apply|act on|carry out|do what|execute)\b", re.I)
DIRECTIVES = re.compile(r"\b(instructions?|steps|directions|directives|rules|guidance|commands?|"
                        r"exactly|whatever|everything)\b", re.I)
# Words that point outside the package ("the URL in endpoint.txt"); a file
# inside the package is not a reference to fetch.
POINTER = re.compile(r"\b(urls?|links?|endpoints?|address|websites?|site|server|domain)\b", re.I)
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)


def _outside_fences(text):
    out, fenced = [], False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            out.append(line)
    return "\n".join(out)


def _label(text):
    return " ".join(text.split()).casefold()


def _link_text(text):
    """Links rewritten as "text URL": inline, HTML, and every Markdown
    reference form (full, collapsed, shortcut; labels matched case- and
    whitespace-insensitively, across line breaks)."""
    refs = {_label(k): v for k, v in REF_DEF.findall(text)}
    text = REF_DEF.sub("", text)
    text = HTML_ANCHOR.sub(lambda m: f"{m.group(2)} {m.group(1)}", text)
    text = MD_LINK.sub(lambda m: f"{m.group(1)} {m.group(2)}", text)
    text = REF_USE.sub(lambda m: f"{m.group(1)} {refs.get(_label(m.group(2) or m.group(1)), '')}", text)
    return SHORTCUT.sub(lambda m: f"{m.group(1)} {refs[_label(m.group(1))]}"
                        if _label(m.group(1)) in refs else m.group(0), text)


def external_references(text):
    """Paragraphs that tell the agent to run remote code, fetch and follow
    outside instructions, or use files outside the package. Paragraphs, not
    lines or sentences, so wrapping or splitting a sentence does not hide it.
    Plain documentation links do not count."""
    count = 0
    for para in re.split(r"\n\s*\n", _link_text(text)):
        flat = " ".join(para.split())
        if PIPE_TO_SHELL.search(flat):
            count += 1
        elif URLISH.search(flat) and GET_OR_RUN.search(flat):
            count += 1
        elif FOLLOW.search(flat) and DIRECTIVES.search(flat) and (URLISH.search(flat) or POINTER.search(flat)):
            count += 1
    return count


def _frontmatter_problems(text):
    """(declares dependencies, needs review) for Markdown frontmatter, using
    the scanner's own boundary and key rules, then a strict badge rule: only
    name, description and license, each a plain or correctly quoted one-line
    value."""
    lines = text.lstrip("\ufeff").splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return False, False
    if any(k == "unparsed_frontmatter" for k, _ in scan._frontmatter_capabilities(text)):
        return False, True
    close = next(j for j in range(i + 1, len(lines)) if lines[j].strip() == "---")
    declares, review, block_open = False, False, False
    for _, key, value, indented in scan._yaml_lines(lines[i + 1:close], i + 2):
        if indented:
            # Only the continuation of a ">" or "|" block value; the scanner
            # already rejects a continuation that looks like another key.
            review = review or not block_open
            continue
        block_open = False
        if key is None:
            review = True
            continue
        if key in FRONTMATTER_DEPENDENCY_KEYS:
            declares = True
        if key not in BADGE_FRONTMATTER_KEYS:
            review = True
        if value in BLOCK_SCALARS:
            block_open = True
        elif not (PLAIN_SCALAR.match(value) or QUOTED_SCALAR.match(value)):
            review = True
    return declares, review


def recognized_references(text):
    """How many outside references the patterns recognize: URLs with any
    scheme, bare domains with a path, autolinks, Markdown reference
    definitions and href attributes. Recognized, not guaranteed exhaustive."""
    return (len(URLISH.findall(text)) + len(AUTOLINK.findall(text))
            + len(REF_DEF.findall(text)) + len(HREF.findall(text)))


def _classify(rel, text, kinds):
    """(kind, supported, unresolved count, external references, forced review)
    for one file."""
    lower = rel.lower()
    base = lower.rsplit("/", 1)[-1]
    ext = os.path.splitext(base)[1]
    if DEPENDENCY_NAME.search(lower):
        return "unknown", False, 1, 0, True
    if text is None:
        return "unknown", False, 0, 0, True
    body = text.lstrip("\ufeff")
    unresolved = (1 if kinds & DEPENDENCY_CAPABILITIES else 0) + len(PARENT_SEGMENT.findall(body))
    references = recognized_references(body)
    prose = ext in PROSE_EXTENSIONS or (ext == "" and not (kinds & TYPE_CAPABILITIES))
    if (not prose or (kinds & TYPE_CAPABILITIES) or body.startswith("#!")
            or TAG_OPENER.search(body)):
        return "unknown", False, unresolved, references, True
    declares, review = (_frontmatter_problems(body) if ext in (".md", ".markdown")
                        else (False, False))
    unresolved += declares + external_references(body)
    visible = _outside_fences(body) if ext in (".md", ".markdown") else body
    review = (review or bool(SOURCE_LINE.search(visible))
              or any(scan.INTERPRETER_RUN.search(scan.normalize(line)) for line in body.splitlines()))
    return "instruction", True, unresolved, references, review


def _error(reason_code):
    """Evidence for a package that could not be fully analysed. The reason is
    a fixed code, never a path or message."""
    return {"schema": "canary.evidence/1", "policy_version": POLICY,
            "scanner_version": __version__, "ruleset_sha256": ruleset_sha256(),
            "tree_sha256": None, "deterministic": {"verdict": "error", "reason": reason_code},
            "coverage": {"complete": False, "files_total": 0, "files_checked": 0,
                         "unsupported": 0, "unresolved": 0},
            "references": {"external": 0}, "components": []}


class _Stop(Exception):
    def __init__(self, reason):
        self.reason = reason


def _raise(err):
    raise _Stop("unreadable")


def _inventory(root):
    """[(relative posix path, executable, content sha256)] for every regular
    file, read without following links. Counts before hashing, so an
    oversized package is refused without reading it."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_raise):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                raise _Stop("link_or_special_file")
            entries.append((path, st))
            if len(entries) > MAX_COMPONENTS:
                raise _Stop("too_many_files")
    out = []
    for path, st in entries:
        h = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        out.append((rel, bool(st.st_mode & 0o100), h.hexdigest()))
    return sorted(out)


def produce(root):
    """canary.evidence/1 for the package folder `root` (deterministic only).
    Never raises: every failure is error evidence with a fixed reason."""
    try:
        return _produce(root)
    except _Stop as stop:
        return _error(stop.reason)
    except ValueError:
        return _error("invalid_name")
    except Exception:  # OSError, PathError, SourceError, anything unforeseen
        return _error("unreadable")


def _produce(root):
    from canary import add
    root = os.path.normpath(root)
    if os.path.islink(root) or not os.path.isdir(root):
        return _error("not_a_folder")
    before = add.tree_digest(root)
    inventory = _inventory(root)
    if not inventory:
        return _error("empty")
    texts = []
    result = scan.scan_package(root, excerpts=True, texts=texts)
    after = add.tree_digest(root)
    text_of = {rel.replace(os.sep, "/"): t for rel, t in texts}
    sha_of = {rel: sha for rel, _, sha in inventory}
    if before != after or any(
            hashlib.sha256(t.encode("utf-8", "surrogateescape")).hexdigest() != sha_of.get(rel)
            for rel, t in text_of.items()):
        return _error("changed_during_run")

    caps, findings, skipped = {}, {}, {}
    for c in result["capabilities"]:
        caps.setdefault(c["path"].replace(os.sep, "/"), set()).add(c["kind"])
    for f in result["findings"]:
        if f["severity"] != "info":
            findings.setdefault(f["path"].replace(os.sep, "/"), []).append(f)
    for s in result["coverage"]["skipped"]:
        skipped[s["path"].replace(os.sep, "/")] = s["reason"]

    components, unsupported, unresolved, checked, references = [], 0, 0, 0, 0
    for rel, executable, sha in inventory:
        component_key = component_id(rel, executable, sha)
        kinds = caps.get(rel, set())
        if skipped.get(rel) == "media":
            kind, supported, refs, external, review = "binary", False, 0, 0, True
        else:
            kind, supported, refs, external, review = _classify(rel, text_of.get(rel), kinds)
        references += external
        weights = {}
        for f in findings.get(rel, []):
            w = scan.SEVERITY_WEIGHT[f["severity"]]
            weights[f["check_id"]] = max(w, weights.get(f["check_id"], 0))
        score = sum(weights.values())
        complete = supported and rel in text_of
        if skipped.get(rel) in ("unreadable", "too_large"):
            verdict = "error"
        elif score >= 6:
            verdict = "block"
        elif (not complete or review or score or refs
              or (kinds & scan.REVIEW_CAPABILITIES)):
            verdict = "review"
        else:
            verdict = "pass"
        unresolved += refs
        unsupported += not supported
        checked += complete
        components.append({"id": component_key, "kind": kind, "supported": supported,
                           "complete": complete, "deterministic": verdict})

    package = {"LIKELY_SAFE": "pass", "NEEDS_REVIEW": "review", "UNSAFE": "block"}[result["verdict"]]
    for c in components:
        if RANK[c["deterministic"]] > RANK[package]:
            package = c["deterministic"]
    if unresolved and package == "pass":
        package = "review"
    total = len(inventory)
    coverage = {"complete": (result["coverage"]["complete"] and checked == total
                             and not unsupported and not unresolved
                             and all(c["deterministic"] == "pass" for c in components)),
                "files_total": total, "files_checked": checked,
                "unsupported": unsupported, "unresolved": unresolved}
    return {"schema": "canary.evidence/1", "policy_version": POLICY,
            "scanner_version": __version__, "ruleset_sha256": ruleset_sha256(),
            "tree_sha256": before.split(":", 1)[1], "deterministic": {"verdict": package},
            "coverage": coverage, "references": {"external": references},
            "components": sorted(components, key=lambda c: c["id"])}
