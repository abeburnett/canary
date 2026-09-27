"""Layer 1: deterministic package scanner.

Reads every entry in a package without executing, importing or installing
anything, and reports three things that combine into one verdict:

- threat findings from the pattern catalog (catalog.py);
- capabilities: each way the package can run code or grant itself power;
- coverage: whether every entry was actually read.

The scanner allowlists what it knows is inert rather than listing what is
dangerous: a text file that is not a recognized document type counts as
possibly runnable, an entry it could not read makes coverage incomplete, and
links inside a package are never followed. Any of these blocks automatic
approval. The interface is fixed in docs/architecture.md.
"""

import hashlib
import json
import os
import re
import stat
import unicodedata

from canary import catalog

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_DEPTH = 64
MAX_ROOT_LINK_HOPS = 40

# Document types a host reads as text and never runs.
INERT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".text", ".rst", ".adoc", ".json", ".yaml",
    ".yml", ".toml", ".csv", ".tsv", ".xml", ".html", ".htm", ".css", ".svg",
    ".ini", ".cfg", ".conf",
}
INERT_NAMES = {
    "license", "licence", "notice", "readme", "changelog", "authors",
    "contributors", "copying", ".gitignore", ".gitattributes", ".editorconfig",
    ".gitkeep", ".npmignore",
}
SCRIPT_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts",
    ".mts", ".cts", ".rb", ".pl", ".php", ".ps1", ".psm1", ".bat", ".cmd",
    ".swift", ".go", ".lua", ".applescript", ".scpt", ".command",
}
# Files that make a package manager run code or fetch dependencies.
PACKAGE_MANIFESTS = {
    "package.json", "pyproject.toml", "requirements.txt", "gemfile",
    "cargo.toml", "go.mod", "pipfile", "composer.json",
}
MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns",
                    ".woff", ".woff2", ".ttf", ".otf", ".wav", ".pdf"}
MEDIA_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
               b"RIFF", b"\x00\x00\x01\x00", b"wOFF", b"wOF2", b"\x00\x01\x00\x00",
               b"OTTO", b"icns", b"%PDF-")

# Capability kinds that run code or grant tools. Any of them blocks auto-approval.
REVIEW_CAPABILITIES = {
    "shell_injection", "allowed_tools", "skill_hooks", "plugin_power",
    "plugin_hooks", "mcp_config", "bin_dir", "script", "executable_bit",
    "skill_dependencies", "package_manifest", "unrecognized_file",
}
# Plugin-manifest keys that only describe the plugin. A manifest using any
# other key (hooks, mcpServers, commands, agents, install steps, vendor
# extensions) can make the host run code, so it blocks auto-approval.
DECLARATIVE_MANIFEST_KEYS = {
    "$schema", "name", "version", "description", "author", "homepage",
    "repository", "license", "keywords", "skills", "displayName", "category", "tags",
}
# Keys matched wherever they appear (quoted, indented or inside {flow style}).
FRONTMATTER_KEYS = [
    ("allowed_tools", re.compile(r"[\"']?\ballowed[-_]tools\b[\"']?\s*:", re.I)),
    ("skill_hooks", re.compile(r"[\"']?\bhooks\b[\"']?\s*:", re.I)),
    ("context_fork", re.compile(r"\bcontext\b[\"']?\s*:\s*[\"']?fork\b", re.I)),
]
DEPENDENCY_KEYS = re.compile(
    r"[\"']?\b(dependencies|mcp|mcp_servers|mcpservers|tools|permissions|install)\b[\"']?\s*:", re.I)
SHELL_INJECTION_INLINE = re.compile(r"(?:^|\s)!`[^`\n]+`")
SHELL_INJECTION_FENCE = re.compile(r"^\s*(```|~~~)!\s*$")

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}
VERDICT_RANK = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}

# Characters that render as nothing. They are removed before matching; one
# placed inside a word, a bidirectional control, or a Unicode tag character is
# itself a finding.
_INVISIBLE_RANGES = (
    "­͏؜ᅟᅠ឴឵᠋-᠏​-‏"
    "‪-‮⁠-⁯⠀ㅤ︀-️﻿ﾠ"
    "\U000e0000-\U000e0fff\U0001d173-\U0001d17a"
)
INVISIBLE = re.compile(f"[{_INVISIBLE_RANGES}]")
ALWAYS_SUSPECT = re.compile("[‪-‮⁦-⁩\U000e0000-\U000e007f]")
INVISIBLE_IN_WORD = re.compile(f"[^\\W\\d_][{_INVISIBLE_RANGES}]+[^\\W\\d_]")

# Latin look-alikes from Cyrillic, Greek and IPA, folded before matching so a
# homoglyph cannot slip a phrase past the catalog.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "т": "t",
    "к": "k", "м": "m", "н": "h", "в": "b", "п": "n", "г": "r", "ш": "w",
    "ԛ": "q", "ԝ": "w", "ь": "b", "ɡ": "g", "ɑ": "a", "ı": "i",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "І": "I", "Ј": "J", "Ѕ": "S", "К": "K", "М": "M", "Н": "H", "В": "B",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
    "ρ": "p", "υ": "u", "Ο": "O", "Α": "A", "Ε": "E", "Ι": "I", "Κ": "K",
    "Ν": "N", "Τ": "T", "Ρ": "P",
})
WORD = re.compile(r"[^\W\d_]+")


class PathError(Exception):
    pass


def _sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def _path_id(rel):
    return "f:" + _sha(rel)[:12]


def _mixed_script(word):
    latin = other = False
    for ch in word:
        name = unicodedata.name(ch, "")
        if name.startswith("LATIN"):
            latin = True
        elif name.startswith(("CYRILLIC", "GREEK")):
            other = True
    return latin and other


def normalize(text):
    """Text as the catalog sees it: NFKC, invisibles removed, look-alikes folded."""
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", text)).translate(CONFUSABLES)


# ---------------------------------------------------------------- inventory

def _inventory(root):
    """Yield (rel, kind, payload) for every entry under root.

    Walks with directory handles, so paths longer than the OS limit are still
    read, and never follows links. For kind 'file' the payload is what
    _read_at returned; any other kind is a skip reason with payload None.
    """
    errors = []
    count = 0
    for dirpath, dirnames, filenames, dirfd in os.fwalk(
            root, follow_symlinks=False, onerror=errors.append):
        rel_dir = os.path.relpath(dirpath, root)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        keep = []
        for d in dirnames:
            count += 1
            rel = os.path.normpath(os.path.join(rel_dir, d))
            try:
                st = os.stat(d, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                yield rel, "unreadable", None
                continue
            if stat.S_ISLNK(st.st_mode):
                yield rel, "symlink", None
            elif depth + 1 > MAX_DEPTH:
                yield rel, "too_deep", None
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            count += 1
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if count > MAX_ENTRIES:
                yield rel, "too_many_entries", None
                return
            yield rel, "file", _read_at(dirfd, name)
    for exc in errors:
        name = getattr(exc, "filename", None)
        yield (os.path.relpath(name, root) if name else "?"), "unreadable", None


def _read_at(dirfd, name):
    """(bytes, executable) for a regular file, or a skip reason string.

    Never follows links and never blocks on FIFOs or devices.
    """
    try:
        st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            return "symlink"
        if not stat.S_ISREG(st.st_mode):
            return "special_file"
        if st.st_size > MAX_FILE_BYTES:
            return "too_large"
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return "special_file"
            chunks, total = [], 0
            while total <= MAX_FILE_BYTES:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) > MAX_FILE_BYTES:
            return "too_large"
        return data, bool(st.st_mode & 0o111)
    except OSError:
        return "unreadable"


def _classify(rel, data, executable):
    """(text, None) for readable text, else (None, skip reason).

    Anything that decodes as text is scanned as text, whatever its name or
    first bytes, so a payload cannot pass itself off as an image or font.
    """
    if b"\x00" not in data[:8192]:
        try:
            return data.decode("utf-8"), None
        except UnicodeDecodeError:
            pass
    ext = os.path.splitext(rel)[1].lower()
    if ext in MEDIA_EXTENSIONS and data.startswith(MEDIA_MAGIC) and not executable:
        return None, "media"
    return None, "binary"


def _resolve_root(target):
    """Follow the named target's own links, a bounded number of hops."""
    path = os.path.abspath(target)
    for _ in range(MAX_ROOT_LINK_HOPS):
        if not os.path.islink(path):
            return path
        path = os.path.normpath(os.path.join(os.path.dirname(path), os.readlink(path)))
    return None


# ------------------------------------------------------------- capabilities

def _path_capabilities(rel, executable):
    parts = [p.lower() for p in rel.split(os.sep)]
    base = parts[-1]
    ext = os.path.splitext(base)[1]
    caps = []
    if "bin" in parts[:-1]:
        caps.append("bin_dir")
    if ext in SCRIPT_EXTENSIONS:
        caps.append("script")
    elif executable:
        caps.append("executable_bit")
    if base == "hooks.json":
        caps.append("plugin_hooks")
    if base in (".mcp.json", "mcp.json"):
        caps.append("mcp_config")
    if base == "marketplace.json":  # lists plugin sources, which may be commands
        caps.append("plugin_power")
    if base in PACKAGE_MANIFESTS:
        caps.append("package_manifest")
    return caps


def _content_capabilities(rel, text):
    parts = [p.lower() for p in rel.split(os.sep)]
    base = parts[-1]
    stem, ext = os.path.splitext(base)
    caps = []  # (kind, line)
    if text.startswith("#!"):
        caps.append(("script", 1))
    elif ext not in INERT_EXTENSIONS and ext not in SCRIPT_EXTENSIONS \
            and base not in INERT_NAMES and stem not in INERT_NAMES:
        caps.append(("unrecognized_file", 0))
    if base == "plugin.json":
        caps.append(("plugin_manifest" if _declarative_manifest(text) else "plugin_power", 0))
    if len(parts) >= 2 and parts[-2] == "agents" and ext in (".yaml", ".yml") \
            and DEPENDENCY_KEYS.search(text):
        caps.append(("skill_dependencies", 0))
    if ext in (".md", ".markdown"):
        block, first = _frontmatter(text)
        for kind, rx in FRONTMATTER_KEYS:
            if rx.search(block):
                caps.append((kind, first))
        for n, line in enumerate(text.splitlines(), start=1):
            if SHELL_INJECTION_INLINE.search(line) or SHELL_INJECTION_FENCE.match(line):
                caps.append(("shell_injection", n))
    return caps


def _declarative_manifest(text):
    try:
        manifest = json.loads(text)
    except (ValueError, RecursionError):
        return False
    if not isinstance(manifest, dict) or not set(manifest) <= DECLARATIVE_MANIFEST_KEYS:
        return False
    skills = manifest.get("skills", [])
    if isinstance(skills, str):
        skills = [skills]
    return isinstance(skills, list) and all(isinstance(x, str) for x in skills)


def _frontmatter(text):
    """The leading frontmatter block and its first line number, or ('', 0).

    Tolerates a byte-order mark, leading blank lines and an indented fence,
    because a host that tolerates them would still honor the keys inside.
    """
    lines = text.lstrip("﻿").splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return "", 0
    for j in range(i + 1, min(len(lines), i + 400)):
        if lines[j].strip() == "---":
            return "\n".join(lines[i + 1:j]), i + 2
    return "\n".join(lines[i + 1:i + 400]), i + 2


# ------------------------------------------------------------------ threats

def _obfuscation(rel, text):
    findings = []
    for n, line in enumerate(text.splitlines(), start=1):
        body = line[1:] if n == 1 and line.startswith("﻿") else line
        if ALWAYS_SUSPECT.search(body) or INVISIBLE_IN_WORD.search(body):
            findings.append(catalog.finding("invisible-character", rel, n, body))
        elif any(_mixed_script(w) for w in WORD.findall(INVISIBLE.sub("", body))):
            findings.append(catalog.finding("mixed-script-word", rel, n, body))
    return findings


def _findings(rel, text):
    findings = _obfuscation(rel, text)
    seen = set()
    raw_lines = text.splitlines()
    lines = [normalize(l) for l in raw_lines]
    for n, line in enumerate(lines, start=1):
        for f in catalog.match_line(rel, n, line, raw_lines[n - 1]):
            seen.add((f["check_id"], n))
            findings.append(f)
    # Second pass over paragraphs, so a phrase split across lines still matches.
    for start, end, joined, raw in _paragraphs(lines, raw_lines):
        for f in catalog.match_paragraph(rel, start, joined, raw):
            if not any((f["check_id"], n) in seen for n in range(start, end + 1)):
                seen.add((f["check_id"], start))
                findings.append(f)
    return findings


def _paragraphs(lines, raw_lines):
    start, buf, raw = None, [], []
    for n, line in enumerate(lines, start=1):
        if line.strip():
            if start is None:
                start = n
            buf.append(line.strip())
            raw.append(raw_lines[n - 1].strip())
        elif buf:
            if len(buf) > 1:
                yield start, n - 1, " ".join(buf), " ".join(raw)
            start, buf, raw = None, [], []
    if len(buf) > 1:
        yield start, len(lines), " ".join(buf), " ".join(raw)


def _threat_verdict(score):
    if score >= 6:
        return "UNSAFE"
    if score >= 3:
        return "NEEDS_REVIEW"
    return "LIKELY_SAFE"


# --------------------------------------------------------------------- scan

def _entries(target):
    visible = os.path.basename(os.path.normpath(target)) or target
    root = _resolve_root(target)
    if root is None:
        return [(visible, "symlink_loop", None)]
    if os.path.isdir(root):
        return list(_inventory(root))
    if os.path.isfile(root):
        # A named file keeps the name the caller used, even through a link.
        parent = os.open(os.path.dirname(root), os.O_RDONLY)
        try:
            return [(visible, "file", _read_at(parent, os.path.basename(root)))]
        finally:
            os.close(parent)
    return [(visible, "special_file", None)]


def scan_package(target, excerpts=False):
    """Scan a package. `excerpts` reveals attacker-controlled text (matched
    excerpts and file names) and is for a person's terminal, never an agent."""
    if not os.path.lexists(target):
        raise PathError(f"no such path: {target}")
    entries = _entries(target)

    findings, capabilities, skipped, manifest = [], [], [], []
    scanned = 0
    for rel, kind, payload in entries:
        if kind == "file" and isinstance(payload, str):
            kind, payload = payload, None
        if kind != "file":
            skipped.append({"path": rel, "reason": kind})
            manifest.append(f"{rel}\0{kind}")
            capabilities.extend({"kind": k, "path": rel, "line": 0}
                                for k in _path_capabilities(rel, False))
            continue
        data, executable = payload
        try:
            capabilities.extend({"kind": k, "path": rel, "line": 0}
                                for k in _path_capabilities(rel, executable))
            text, reason = _classify(rel, data, executable)
            if text is None:
                skipped.append({"path": rel, "reason": reason})
                manifest.append(f"{rel}\0{reason}\0{_sha(data)}")
                continue
            capabilities.extend({"kind": k, "path": rel, "line": line}
                                for k, line in _content_capabilities(rel, text))
            findings.extend(_findings(rel, text))
        except Exception:  # fail closed: an entry we could not analyze counts as unread
            skipped.append({"path": rel, "reason": "unreadable"})
            manifest.append(f"{rel}\0unreadable")
            continue
        scanned += 1
        manifest.append(f"{rel}\0file\0{'x' if executable else '-'}\0{_sha(data)}")

    blocking = [x for x in skipped if x["reason"] != "media"]
    complete = scanned > 0 and not blocking
    # Each distinct check counts once, at its strictest severity: ten copies of
    # one API example are one signal, while two different attack checks are two.
    strictest = {}
    for f in findings:
        w = SEVERITY_WEIGHT[f["severity"]]
        strictest[f["check_id"]] = max(w, strictest.get(f["check_id"], 0))
    score = sum(strictest.values())
    threat = _threat_verdict(score)
    verdict, reasons = threat, []
    if threat != "LIKELY_SAFE":
        cats = sorted({f["category"] for f in findings if f["severity"] != "info"})
        reasons.append(f"Threat patterns found ({', '.join(cats)}), score {score}.")
    if not complete:
        verdict = max(verdict, "NEEDS_REVIEW", key=VERDICT_RANK.get)
        if scanned == 0 and not blocking:
            reasons.append("Nothing to scan: the package has no readable text.")
        else:
            why = sorted({s["reason"] for s in blocking})
            reasons.append(f"Scan incomplete: {len(blocking)} entries not read ({', '.join(why)}).")
    code = sorted({c["kind"] for c in capabilities if c["kind"] in REVIEW_CAPABILITIES})
    if code:
        verdict = max(verdict, "NEEDS_REVIEW", key=VERDICT_RANK.get)
        reasons.append(f"Runs code or grants tools ({', '.join(code)}); a person must approve it.")

    for f in findings:
        excerpt = f.pop("excerpt")
        f["excerpt_sha256"] = _sha(excerpt)
        if excerpts:
            f["excerpt"] = excerpt
    # File names are attacker-controlled text too: agents see opaque ids only.
    for item in findings + capabilities + skipped:
        item["path_id"] = _path_id(item["path"])
        if not excerpts:
            del item["path"]
    return {
        "schema": "canary.scan/1",
        "target": os.path.abspath(target),
        "package_digest": "sha256:" + _sha("\n".join(sorted(manifest))),
        "verdict": verdict,
        "threat_verdict": threat,
        "score": score,
        "coverage": {"complete": complete, "files_total": len(entries),
                     "files_scanned": scanned, "skipped": skipped},
        "capabilities": capabilities,
        "findings": findings,
        "reasons": reasons,
    }


def render_text(result):
    items = result["capabilities"] + result["coverage"]["skipped"] + result["findings"]
    revealed = any("path" in i for i in items)

    def where(item):
        return repr(item["path"]) if "path" in item else item["path_id"]

    out = [f"Canary scan: {result['target']}",
           f"Verdict: {result['verdict']}  (threat {result['threat_verdict']}, score {result['score']}; "
           f"{result['coverage']['files_scanned']}/{result['coverage']['files_total']} entries read)"]
    out += [f"  - {r}" for r in result["reasons"]]
    for c in result["capabilities"]:
        out.append(f"  [CODE  ] {c['kind']} {where(c)}" + (f":{c['line']}" if c["line"] else ""))
    for s in result["coverage"]["skipped"]:
        out.append(f"  [SKIP  ] {s['reason']} {where(s)}")
    for f in result["findings"]:
        out.append(f"  [{f['severity'].upper():6}] {f['category']} {where(f)}:{f['line']}"
                   + (f"  {f['excerpt']!r}" if "excerpt" in f else ""))
    if items and not revealed:
        out.append("  File names and excerpts are hidden. Run with --excerpts in your own terminal to see them.")
    return "\n".join(out)
