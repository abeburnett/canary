#!/usr/bin/env python3
"""Rewrite scanner/manifest.json with the SHA-256 of every bundled scanner file.

Usage: scripts/update-manifest.py <scanner-source-commit>
Run after any change under bin/ or canary/; the Action refuses a mismatch.
"""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

if len(sys.argv) != 2:
    sys.exit("usage: update-manifest.py <scanner-source-commit>")
files = ["bin/canary"] + sorted(p.relative_to(ROOT).as_posix()
                               for p in (ROOT / "canary").rglob("*.py"))
manifest = {
    "version": sys.argv[1],
    "files": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files},
}
(ROOT / "scanner" / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(f"manifest: {len(files)} files, version {manifest['version']}")
