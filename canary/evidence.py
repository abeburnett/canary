"""Identities for `canary.evidence/1` (docs/evidence-contract.md).

Reference implementations shared with the hosted consumer through the vectors
in tests/vectors/evidence-v1.json. The producer (`canary evidence`) is built
on these; nothing here decides a verdict.
"""

import hashlib
import json
import os

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
