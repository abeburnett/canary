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
import zlib

from canary import catalog

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_DEPTH = 64

# Document types a host reads as text and never runs.
INERT_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".text", ".rst", ".adoc", ".json", ".yaml",
    ".yml", ".toml", ".csv", ".tsv", ".xml", ".html", ".htm", ".css", ".svg",
    ".ini", ".cfg", ".conf", ".jsonl", ".ndjson",
}
INERT_NAME = re.compile(
    r"^(license|licence|notice|readme|changelog|authors|contributors|copying)([-_.][\w.-]*)?$", re.I)
INERT_DOTFILES = {".gitignore", ".gitattributes", ".editorconfig", ".gitkeep", ".npmignore"}
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
# Images and web fonts whose structure the scanner validates (see _valid_media).
# Anything else binary, including PDFs, makes coverage incomplete.
MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".woff", ".woff2"}

# Capability kinds that run code or grant tools. Any of them blocks auto-approval.
REVIEW_CAPABILITIES = {
    "shell_injection", "allowed_tools", "skill_hooks", "plugin_power",
    "plugin_hooks", "mcp_config", "bin_dir", "script", "executable_bit",
    "skill_dependencies", "package_manifest", "unrecognized_file",
    "unparsed_frontmatter", "instructs_execution",
}
# Plugin-manifest keys that only describe the plugin. A manifest using any
# other key (hooks, mcpServers, commands, agents, install steps, vendor
# extensions) can make the host run code, so it blocks auto-approval.
DECLARATIVE_MANIFEST_KEYS = {
    "$schema", "name", "version", "description", "author", "homepage",
    "repository", "license", "keywords", "skills", "displayName", "category", "tags",
}
# Frontmatter keys are allowlisted. A key that grants power is its own
# blocking capability, and so is frontmatter this parser cannot read line by
# line (flow style, escaped or unusual keys, an unclosed block). Any other
# unknown key is listed but does not block: hosts ignore keys they do not
# define, so it cannot grant power by itself.
INERT_FRONTMATTER_KEYS = {
    "name", "description", "license", "version", "metadata", "author", "authors",
    "tags", "category", "keywords", "compatibility", "argument-hint", "user-invocable",
    "disable-model-invocation", "model", "effort", "when_to_use", "when-to-use",
    "homepage", "repository", "agent", "disallowed-tools", "title", "icon",
}
POWER_FRONTMATTER_KEYS = {"allowed-tools": "allowed_tools", "allowed_tools": "allowed_tools",
                          "hooks": "skill_hooks"}
# Codex agents/*.yaml: only the display block is known to be inert.
INERT_AGENT_KEYS = {"interface", "display_name", "short_description", "icon_small",
                    "icon_large", "brand_color", "default_prompt",
                    "policy", "allow_implicit_invocation"}
YAML_KEY = re.compile(r"""^(?:"([A-Za-z0-9_-]*)"|'([A-Za-z0-9_-]*)'|([A-Za-z0-9_][A-Za-z0-9_-]*))\s*:(?:\s|$)""")
YAML_KEY_ANYWHERE = re.compile(r"(^|\s)[\"']?[A-Za-z_][\w-]*[\"']?\s*:(\s|$)")
BLOCK_STARTS = ("", "|", ">", "|-", ">-", "|+", ">+")
INTERPRETER_RUN = re.compile(
    r"\b(python\d?(?:\.\d+)?|node|deno|bun|bash|sh|zsh|fish|ruby|perl|php|g?awk|rscript|julia|lua"
    r"|osascript|pwsh|powershell)\s+(?:-{1,2}[\w-]+\s+)*[\"'`]?([\w.-]*[./][\w./-]+)", re.I)
SHELL_INJECTION_INLINE = re.compile(r"(?:^|\s)!`[^`\n]+`")
SHELL_INJECTION_FENCE = re.compile(r"^\s*(```|~~~)!\s*$")

SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}
VERDICT_RANK = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}

# Characters that render as nothing. They are removed before matching; one
# placed inside a word, a bidirectional control, or a Unicode tag character is
# itself a finding.
_INVISIBLE_RANGES = (
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    "\u202a-\u202e\u2060-\u206f\u2800\u3164\ufe00-\ufe0f\ufeff\uffa0"
    "\U000e0000-\U000e0fff\U0001d173-\U0001d17a"
)
INVISIBLE = re.compile(f"[{_INVISIBLE_RANGES}]")
# Bidirectional overrides and tag characters are never needed in a skill.
# Soft hyphens and bidi isolates are normal in real text: they are removed
# before matching (so a phrase hidden with them is still caught) but not
# flagged on their own.
ALWAYS_SUSPECT = re.compile("[\u202a-\u202e\U000e0000-\U000e007f]")
_ZERO_WIDTH = ("\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200d\u2060-\u2064"
               "\u3164\ufe00-\ufe0f\ufeff\uffa0")
INVISIBLE_IN_WORD = re.compile(f"[^\\W\\d_][{_ZERO_WIDTH}]+[^\\W\\d_]")

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

# Context labels (program 2026-10-06, owner decision 1). A label only tells the
# reader where a finding sits; it never changes a severity, score or verdict,
# because an attacker could wrap a real payload in a code block or a "never do
# this:" line.
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
FORBIDDING = re.compile(
    r"\b(never|do not|don't|must not|should not|refuse to|reject|watch for|look out for"
    r"|beware of)\b")


class PathError(Exception):
    pass


def _sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def _path_id(rel):
    return "f:" + _sha(rel)[:12]


def _mixed_script(word):
    """A Latin word containing a Cyrillic or Greek letter that imitates a Latin one."""
    latin = lookalike = False
    for ch in word:
        if unicodedata.name(ch, "").startswith("LATIN"):
            latin = True
        elif ord(ch) in CONFUSABLES:
            lookalike = True
    return latin and lookalike


def normalize(text):
    """Text as the catalog sees it: NFKC, invisibles removed, look-alikes folded."""
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", text)).translate(CONFUSABLES)


# ---------------------------------------------------------------- inventory

def _inventory(root, exclude=frozenset()):
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
            rel = os.path.normpath(os.path.join(rel_dir, d))
            if rel in exclude:
                continue
            count += 1
            if count > MAX_ENTRIES:
                yield rel, "too_many_entries", None
                return
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
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if rel in exclude:
                continue
            count += 1
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
    if ext in MEDIA_EXTENSIONS and not executable and _valid_media(ext, data):
        return None, "media"
    return None, "binary"


def _valid_media(ext, data):
    """True only when the bytes parse as the image or font their extension names."""
    try:
        if ext == ".png":
            return _png_ok(data)
        if ext in (".jpg", ".jpeg"):
            return _jpeg_ok(data)
        if ext == ".gif":
            return _gif_ok(data)
        if ext == ".webp":
            return (data[:4] == b"RIFF" and data[8:12] == b"WEBP"
                    and int.from_bytes(data[4:8], "little") + 8 == len(data))
        if ext in (".woff", ".woff2"):
            return (data[:4] == (b"wOFF" if ext == ".woff" else b"wOF2")
                    and int.from_bytes(data[8:12], "big") == len(data))
    except IndexError:
        return False
    return False


def _png_ok(d):
    """Every chunk's length and CRC check out, ending exactly at IEND."""
    if not d.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    i = 8
    while i + 12 <= len(d):
        n = int.from_bytes(d[i:i + 4], "big")
        if i + 12 + n > len(d):
            return False
        if zlib.crc32(d[i + 4:i + 8 + n]) & 0xFFFFFFFF != int.from_bytes(d[i + 8 + n:i + 12 + n], "big"):
            return False
        kind = d[i + 4:i + 8]
        i += 12 + n
        if kind == b"IEND":
            return i == len(d)
    return False


def _jpeg_ok(d):
    """Marker segments are well formed up to the start of scan; the file ends at EOI."""
    if not (d.startswith(b"\xff\xd8") and d.endswith(b"\xff\xd9")):
        return False
    i = 2
    while i + 4 <= len(d):
        if d[i] != 0xFF:
            return False
        marker = d[i + 1]
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = int.from_bytes(d[i + 2:i + 4], "big")
        if length < 2:
            return False
        if marker == 0xDA:
            return True
        i += 2 + length
    return False


def _gif_ok(d):
    """Blocks and sub-blocks parse from the header to a trailer at the last byte."""
    if d[:6] not in (b"GIF87a", b"GIF89a") or len(d) < 14:
        return False
    flags, i = d[10], 13
    if flags & 0x80:
        i += 3 * (2 ** ((flags & 7) + 1))
    while i < len(d):
        block = d[i]
        if block == 0x3B:
            return i == len(d) - 1
        if block == 0x21:
            i += 2
        elif block == 0x2C:
            if i + 10 > len(d):
                return False
            image_flags = d[i + 9]
            i += 10
            if image_flags & 0x80:
                i += 3 * (2 ** ((image_flags & 7) + 1))
            i += 1
        else:
            return False
        while True:
            if i >= len(d):
                return False
            size = d[i]
            i += 1
            if size == 0:
                break
            i += size
    return False


def _resolve_root(target):
    """Resolve the named target the way the operating system does, or None on a loop."""
    try:
        path = os.path.realpath(target)
    except (OSError, RecursionError, ValueError):
        return None
    return None if os.path.islink(path) else path


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
    ext = os.path.splitext(base)[1]
    caps = []  # (kind, line)
    # A readme- or license-style name is inert only with no extension or an inert
    # one: README.awk is still an awk program.
    inert_name = base in INERT_DOTFILES or bool(INERT_NAME.match(base) and (ext == "" or ext in INERT_EXTENSIONS))
    if text.startswith("#!"):
        caps.append(("script", 1))
    elif ext not in INERT_EXTENSIONS and ext not in SCRIPT_EXTENSIONS and not inert_name:
        caps.append(("unrecognized_file", 0))
    if base == "plugin.json":
        caps.append(("plugin_manifest" if _declarative_manifest(text) else "plugin_power", 0))
    if len(parts) >= 2 and parts[-2] == "agents" and ext in (".yaml", ".yml"):
        caps.extend(_agent_metadata_capabilities(text))
    if ext in (".md", ".markdown"):
        caps.extend(_frontmatter_capabilities(text))
        for n, line in enumerate(text.splitlines(), start=1):
            if SHELL_INJECTION_INLINE.search(line) or SHELL_INJECTION_FENCE.match(line):
                caps.append(("shell_injection", n))
            if INTERPRETER_RUN.search(normalize(line)):
                caps.append(("instructs_execution", n))
    return caps


def _yaml_lines(lines, first_line_no):
    """(line number, top-level key or None, value, indented) for each meaningful line."""
    for offset, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indented = raw[:1] in (" ", "\t")
        m = YAML_KEY.match(stripped)
        key = next(g for g in m.groups() if g is not None).lower() if m else None
        value = stripped[m.end():].strip() if m else stripped
        yield first_line_no + offset, key, value, indented


def _frontmatter_capabilities(text):
    lines = text.lstrip("\ufeff").splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines) or lines[i].strip() != "---":
        return []
    close = next((j for j in range(i + 1, len(lines)) if lines[j].strip() == "---"), None)
    if close is None:
        return [("unparsed_frontmatter", i + 1)]
    caps, block_open = [], False
    for n, key, value, indented in _yaml_lines(lines[i + 1:close], i + 2):
        if indented:
            # Belongs to the previous key: a nested block, or a scalar continuation.
            # A continuation that itself looks like a key is not valid YAML.
            if not block_open and YAML_KEY_ANYWHERE.search(value if key is None else f"{key}: {value}"):
                caps.append(("unparsed_frontmatter", n))
            continue
        if key is None:
            caps.append(("unparsed_frontmatter", n))
            block_open = False
            continue
        bare = value.split(" #", 1)[0].strip()
        block_open = bare in BLOCK_STARTS
        if key in POWER_FRONTMATTER_KEYS:
            caps.append((POWER_FRONTMATTER_KEYS[key], n))
        elif key == "context":
            if bare.strip("\"'").lower() == "fork":
                caps.append(("context_fork", n))
        elif key not in INERT_FRONTMATTER_KEYS:
            caps.append(("unknown_frontmatter_key", n))
    return caps


def _agent_metadata_capabilities(text):
    for n, key, value, indented in _yaml_lines(text.lstrip("\ufeff").splitlines(), 1):
        if key is None or key not in INERT_AGENT_KEYS:
            return [("skill_dependencies", n)]
    return []


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


# ------------------------------------------------------------------ threats

def _obfuscation(rel, text):
    findings = []
    for n, line in enumerate(text.splitlines(), start=1):
        body = line[1:] if n == 1 and line.startswith("\ufeff") else line
        if ALWAYS_SUSPECT.search(body) or INVISIBLE_IN_WORD.search(body):
            findings.append(catalog.finding("invisible-character", rel, n, body))
        elif any(_mixed_script(w) for w in WORD.findall(INVISIBLE.sub("", body))):
            findings.append(catalog.finding("mixed-script-word", rel, n, body))
    return findings


def _code_lines(raw_lines):
    """The line numbers inside fenced code blocks, decided on the raw lines.
    An opening fence is up to three spaces, then three or more backticks or
    tildes; the block closes at the next line of up to three spaces, at least
    as many of the same character, and only whitespace. An unclosed block runs
    to the end. The fence lines themselves are outside."""
    inside, closer = set(), None
    for n, line in enumerate(raw_lines, start=1):
        if closer is None:
            m = FENCE_OPEN.match(line)
            if m:
                closer = re.compile(" {0,3}" + re.escape(m.group(1)[0]) + "{"
                                    + str(len(m.group(1))) + r",}\s*")
        elif closer.fullmatch(line):
            closer = None
        else:
            inside.add(n)
    return inside


def _context(line_no, code, raw_lines):
    if line_no in code:
        return "code_example"
    if 1 <= line_no <= len(raw_lines) and FORBIDDING.search(normalize(raw_lines[line_no - 1]).lower()):
        return "forbidding"
    return None


def _findings(rel, text):
    findings = _obfuscation(rel, text)
    seen = set()
    raw_lines = text.splitlines()
    lines = [normalize(l) for l in raw_lines]
    for n, line in enumerate(lines, start=1):
        for f in catalog.match_line(rel, n, line, raw_lines[n - 1]):
            if f["severity"] != "info":
                seen.add((f["check_id"], n))
            findings.append(f)
    # Second pass over paragraphs, so a phrase split across lines still matches.
    for start, end, joined, raw in _paragraphs(lines, raw_lines):
        for f in catalog.match_paragraph(rel, start, joined, raw):
            if not any((f["check_id"], n) in seen for n in range(start, end + 1)):
                seen.add((f["check_id"], start))
                findings.append(f)
    code = _code_lines(raw_lines)
    for f in findings:
        f["context"] = _context(f["line"], code, raw_lines)
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

def _entries(target, exclude):
    """(entries, aliases). aliases maps a scanned name to the other name it has."""
    visible = os.path.basename(os.path.normpath(target)) or target
    root = _resolve_root(target)
    if root is None:
        return [(visible, "symlink_loop", None)], {}
    if os.path.isdir(root):
        return list(_inventory(root, frozenset(os.path.normpath(e) for e in exclude))), {}
    if os.path.isfile(root):
        # A named file keeps the name the caller used, even through a link.
        # Keep both names: a link called notes.txt that points at setup.sh is a script.
        parent = os.open(os.path.dirname(root), os.O_RDONLY)
        try:
            entry = (visible, "file", _read_at(parent, os.path.basename(root)))
        finally:
            os.close(parent)
        target_name = os.path.basename(root)
        return [entry], ({visible: target_name} if target_name != visible else {})
    return [(visible, "special_file", None)], {}


def scan_package(target, excerpts=False, exclude=(), texts=None):
    """Scan a package. `excerpts` reveals attacker-controlled text (matched
    excerpts, file names and the target path) and is for a person's terminal,
    never an agent. `exclude` lists paths, relative to a directory target,
    that belong to other packages and are scanned separately. When `texts` is
    a list, each file read as text is appended as (relative path, text), so
    layer 2 classifies exactly the bytes layer 1 read."""
    if not os.path.lexists(target):
        raise PathError(f"no such path: {target}")
    entries, aliases = _entries(target, exclude)

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
            for name in [rel] + ([aliases[rel]] if rel in aliases else []):
                capabilities.extend({"kind": k, "path": rel, "line": 0}
                                    for k in _path_capabilities(name, executable) if name != rel)
                capabilities.extend({"kind": k, "path": rel, "line": line}
                                    for k, line in _content_capabilities(name, text))
            findings.extend(_findings(rel, text))
        except Exception:  # fail closed: an entry we could not analyze counts as unread
            skipped.append({"path": rel, "reason": "unreadable"})
            manifest.append(f"{rel}\0unreadable")
            continue
        scanned += 1
        if texts is not None:
            texts.append((rel, text))
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
    result = {
        "schema": "canary.scan/1",
        "target_id": _path_id(os.path.abspath(target)),
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
    # The target path is caller-supplied but may still carry attacker text
    # (a downloaded folder's name), so agents see only its id.
    if excerpts:
        result["target"] = os.path.abspath(target)
    return result


def render_text(result):
    items = result["capabilities"] + result["coverage"]["skipped"] + result["findings"]
    revealed = any("path" in i for i in items)

    def where(item):
        return repr(item["path"]) if "path" in item else item["path_id"]

    out = [f"Canary scan: {repr(result['target']) if 'target' in result else result['target_id']}",
           f"Verdict: {result['verdict']}  (threat {result['threat_verdict']}, score {result['score']}; "
           f"{result['coverage']['files_scanned']}/{result['coverage']['files_total']} entries read)"]
    out += [f"  - {r}" for r in result["reasons"]]
    from canary import explain
    for c in result["capabilities"]:
        out.append(f"  [CODE  ] {c['kind']} {where(c)}" + (f":{c['line']}" if c["line"] else ""))
    for s in result["coverage"]["skipped"]:
        out.append(f"  [SKIP  ] {s['reason']} {where(s)}")
    for f in result["findings"]:
        out.append(f"  [{f['severity'].upper():6}] {f['category']} {where(f)}:{f['line']}"
                   + (f"  {f['excerpt']!r}" if "excerpt" in f else "")
                   + (f" [{explain.CONTEXT_TAG[f['context']]}]" if f.get("context") else ""))
    if items and not revealed:
        out.append("  File names and excerpts are hidden. Run with --excerpts in your own terminal to see them.")
    return "\n".join(out)
