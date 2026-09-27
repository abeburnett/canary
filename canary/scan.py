"""Layer 1: deterministic package scanner.

Reads every entry in a package without executing, importing or installing
anything. Produces three separate things, combined into one verdict:

- threat findings from the pattern catalog (catalog.py);
- capabilities: each way the package can run code or grant itself power;
- coverage: whether every entry was actually read.

Anything the scanner could not read, and any capability that runs code,
blocks automatic approval. The interface is fixed in docs/architecture.md.
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
IGNORED_DIRS = {".git"}  # version-control metadata; no agent loads skills from it

SCRIPT_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts",
    ".mts", ".cts", ".rb", ".pl", ".php", ".ps1", ".psm1", ".bat", ".cmd",
    ".swift", ".go", ".lua", ".applescript", ".scpt", ".command",
}
# Capability kinds that run code or grant tools. Any of them blocks auto-approval.
REVIEW_CAPABILITIES = {
    "shell_injection", "allowed_tools", "skill_hooks", "plugin_power",
    "plugin_hooks", "mcp_config", "bin_dir", "script", "executable_bit",
    "skill_dependencies",
}
# Plugin-manifest keys that only describe the plugin. A manifest using any
# other key (hooks, mcpServers, commands, agents, install steps, vendor
# extensions) can make the host run code, so it blocks auto-approval.
DECLARATIVE_MANIFEST_KEYS = {
    "$schema", "name", "version", "description", "author", "homepage",
    "repository", "license", "keywords", "skills", "displayName", "category", "tags",
}
DEPENDENCY_KEYS = re.compile(r"^\s*(dependencies|mcp|mcp_servers|mcpServers|tools|permissions|install)\s*:", re.M)

# Images and fonts, recognized by content, not name. They are listed as
# unscanned assets but do not make coverage incomplete.
MEDIA_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
               b"RIFF", b"\x00\x00\x01\x00", b"wOFF", b"wOF2", b"\x00\x01\x00\x00",
               b"OTTO", b"icns")
MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns",
                    ".woff", ".woff2", ".ttf", ".otf", ".wav"}
SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}
VERDICT_RANK = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}

# Invisible and bidirectional-control characters. A byte-order mark at the
# very start of a file is the one legitimate use and is allowed.
INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿]")

# Latin look-alikes from Cyrillic and Greek, folded before matching so a
# homoglyph cannot slip a phrase past the catalog.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ɡ": "g",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "І": "I", "Ј": "J", "Ѕ": "S", "К": "K", "М": "M", "Н": "H", "В": "B",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
    "ρ": "p", "υ": "u", "Ο": "O", "Α": "A", "Ε": "E", "Ι": "I", "Κ": "K",
    "Ν": "N", "Τ": "T", "Ρ": "P",
})
WORD = re.compile(r"[^\W\d_]+")
SHELL_INJECTION_INLINE = re.compile(r"(?:^|\s)!`[^`\n]+`")
SHELL_INJECTION_FENCE = re.compile(r"^\s*(```|~~~)!\s*$")


class PathError(Exception):
    pass


def _sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def _script_like(rel, data):
    return os.path.splitext(rel)[1].lower() in SCRIPT_EXTENSIONS or data.startswith(b"#!")


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


def _inventory(root):
    """Yield (rel, kind, abs_path) for every entry under root, never following links.

    kind is 'file', 'symlink_file', or a skip reason.
    """
    real_root = os.path.realpath(root)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            rel = os.path.normpath(os.path.join(rel_dir, d))
            if d in IGNORED_DIRS and not os.path.islink(full):
                continue
            if os.path.islink(full):
                target = os.path.realpath(full)
                inside = target == real_root or target.startswith(real_root + os.sep)
                yield rel, ("symlink_dir" if inside else "symlink_escape"), full
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            count += 1
            if count > MAX_ENTRIES:
                yield os.path.normpath(os.path.join(rel_dir, name)), "too_many_entries", None
                return
            full = os.path.join(dirpath, name)
            rel = os.path.normpath(os.path.join(rel_dir, name))
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(full)
                inside = target.startswith(real_root + os.sep)
                if not inside:
                    yield rel, "symlink_escape", full
                elif not os.path.isfile(target):
                    yield rel, "special_file", full
                else:
                    yield rel, "symlink_file", target
            elif stat.S_ISREG(st.st_mode):
                yield rel, "file", full
            else:
                yield rel, "special_file", full


def _read(path):
    """Return (bytes, text) or (None, skip_reason). Never blocks on special files."""
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return None, "special_file"
        if st.st_size > MAX_FILE_BYTES:
            return None, "too_large"
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None, "unreadable"
    ext = os.path.splitext(path)[1].lower()
    if ext in MEDIA_EXTENSIONS and data.startswith(MEDIA_MAGIC) and not os.access(path, os.X_OK):
        return None, "media"
    if b"\x00" in data[:8192]:
        return None, "binary"
    try:
        return data, data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "binary"


def _frontmatter(text):
    """Top-level keys and values of a leading YAML block, without a YAML parser."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    keys = {}
    for i, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            break
        m = re.match(r"^([A-Za-z][\w-]*)\s*:\s*(.*)$", line)
        if m:
            keys[m.group(1).lower()] = (m.group(2).strip(), i)
    return keys


def _declarative_manifest(text):
    try:
        manifest = json.loads(text)
    except ValueError:
        return False
    if not isinstance(manifest, dict) or not set(manifest) <= DECLARATIVE_MANIFEST_KEYS:
        return False
    skills = manifest.get("skills", [])
    if isinstance(skills, str):
        skills = [skills]
    return isinstance(skills, list) and all(isinstance(x, str) for x in skills)


def _capabilities(rel, abs_path, data, text):
    caps = []
    parts = rel.split(os.sep)
    base = parts[-1].lower()
    if "bin" in parts[:-1]:
        caps.append({"kind": "bin_dir", "path": rel, "line": 0})
    if _script_like(rel, data):
        caps.append({"kind": "script", "path": rel, "line": 0})
    elif os.access(abs_path, os.X_OK):
        caps.append({"kind": "executable_bit", "path": rel, "line": 0})
    if base in ("hooks.json",):
        caps.append({"kind": "plugin_hooks", "path": rel, "line": 0})
    if base in (".mcp.json", "mcp.json"):
        caps.append({"kind": "mcp_config", "path": rel, "line": 0})
    if base == "plugin.json":
        kind = "plugin_manifest" if _declarative_manifest(text) else "plugin_power"
        caps.append({"kind": kind, "path": rel, "line": 0})
    if base == "marketplace.json":  # lists plugin sources, which may be commands
        caps.append({"kind": "plugin_power", "path": rel, "line": 0})
    if len(parts) >= 2 and parts[-2] == "agents" and base.endswith((".yaml", ".yml")) \
            and DEPENDENCY_KEYS.search(text):
        caps.append({"kind": "skill_dependencies", "path": rel, "line": 0})
    if base.endswith(".md"):
        front = _frontmatter(text)
        for key, kind in (("allowed-tools", "allowed_tools"), ("hooks", "skill_hooks")):
            if key in front:
                caps.append({"kind": kind, "path": rel, "line": front[key][1]})
        if "context" in front and front["context"][0].strip("'\"").lower() == "fork":
            caps.append({"kind": "context_fork", "path": rel, "line": front["context"][1]})
        for n, line in enumerate(text.splitlines(), start=1):
            if SHELL_INJECTION_INLINE.search(line) or SHELL_INJECTION_FENCE.match(line):
                caps.append({"kind": "shell_injection", "path": rel, "line": n})
    return caps


def _obfuscation(rel, text):
    findings = []
    for n, line in enumerate(text.splitlines(), start=1):
        body = line[1:] if n == 1 and line.startswith("﻿") else line
        if INVISIBLE.search(body):
            findings.append(catalog.finding("invisible-character", rel, n, body))
        elif any(_mixed_script(w) for w in WORD.findall(body)):
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


def scan_package(target, excerpts=False):
    if not os.path.lexists(target):
        raise PathError(f"no such path: {target}")
    # The target the user named is followed once (installed skills are often
    # symlinks into ~/.agents/skills); links inside the package are not.
    root = os.path.realpath(target)
    if os.path.isdir(root):
        entries = list(_inventory(root))
    elif os.path.isfile(root) and not os.path.islink(root):
        entries = [(os.path.basename(root), "file", root)]
    else:
        entries = [(os.path.basename(root), "special_file", root)]

    findings, capabilities, skipped, manifest = [], [], [], []
    scanned = 0
    for rel, kind, abs_path in entries:
        if kind not in ("file", "symlink_file"):
            skipped.append({"path": rel, "reason": kind})
            manifest.append(f"{rel}\0{kind}")
            continue
        data, text = _read(abs_path)
        if data is None:
            skipped.append({"path": rel, "reason": text})
            manifest.append(f"{rel}\0{text}")
            continue
        scanned += 1
        mode = "x" if os.access(abs_path, os.X_OK) else "-"
        manifest.append(f"{rel}\0{kind}\0{mode}\0{_sha(data)}")
        capabilities.extend(_capabilities(rel, abs_path, data, text))
        findings.extend(_findings(rel, text))

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
        if scanned == 0 and not skipped:
            reasons.append("Nothing to scan: the package is empty.")
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
    return {
        "schema": "canary.scan/1",
        "target": root,
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
    out = [f"Canary scan: {result['target']}",
           f"Verdict: {result['verdict']}  (threat {result['threat_verdict']}, score {result['score']}; "
           f"{result['coverage']['files_scanned']}/{result['coverage']['files_total']} entries read)"]
    out += [f"  - {r}" for r in result["reasons"]]
    for c in result["capabilities"]:
        out.append(f"  [CODE  ] {c['kind']} {c['path']}" + (f":{c['line']}" if c["line"] else ""))
    for s in result["coverage"]["skipped"]:
        out.append(f"  [SKIP  ] {s['reason']} {s['path']}")
    for f in result["findings"]:
        out.append(f"  [{f['severity'].upper():6}] {f['category']} {f['path']}:{f['line']}"
                   + (f"  {f['excerpt']}" if "excerpt" in f else ""))
    return "\n".join(out)
