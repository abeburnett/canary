#!/usr/bin/env python3
"""Copy the benchmark's harmless skills into bench/benign/ (owner decision 11).

The 94 skills are the field report's (docs/field-report/results.csv), minus
six whose license does not allow copying. Each repository is read at a pinned
commit with `gh api`, so the copy is repeatable; only regular files and
folders are copied (links and special files are skipped and reported), and
each repository's license goes beside its skills. Re-running replaces
bench/benign/ and rewrites the benign entries of bench/manifest.json.

Usage: python3 scripts/vendor-bench-benign.py
"""

import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "bench")
REPOS = {
    "anthropics/skills": ("8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4", "Apache-2.0"),
    "obra/superpowers": ("8ca22dba9a94f28898bbce59f2537ff4d87c747d", "MIT"),
    "wshobson/agents": ("156b7a5e7a8b93642628a339ee4039c925b34c7f", "MIT"),
}
# Not copied: "All rights reserved" (docx, pdf, pptx, xlsx) or no license file.
LEFT_OUT = {"docx", "pdf", "pptx", "xlsx", "doc-coauthoring", "template"}


def tarball(repo, sha):
    data = subprocess.run(["gh", "api", f"repos/{repo}/tarball/{sha}"], capture_output=True,
                          check=True, timeout=600).stdout
    return tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")


def main():
    with open(os.path.join(ROOT, "docs", "field-report", "results.csv")) as fh:
        wanted = {}
        for row in csv.DictReader(fh):
            if row["skill"] not in LEFT_OUT:
                wanted.setdefault(row["source_repo"], set()).add(row["skill"])
    out_root = os.path.join(BENCH, "benign")
    shutil.rmtree(out_root, ignore_errors=True)
    samples, skipped = [], []
    for repo, (sha, license_id) in REPOS.items():
        slug = repo.replace("/", "--")
        tar = tarball(repo, sha)
        members = tar.getmembers()
        top = members[0].name.split("/")[0]
        # A skill folder: one holding SKILL.md, named as in the field report.
        folders = {}
        for m in members:
            parts = m.name.split("/")
            if parts[-1] == "SKILL.md" and len(parts) >= 3 and parts[-2] in wanted[repo]:
                folders.setdefault(parts[-2], "/".join(parts[:-1]))
        missing = wanted[repo] - set(folders)
        if missing:
            sys.exit(f"{repo}@{sha[:7]}: no folder for {sorted(missing)}")
        for name, prefix in sorted(folders.items()):
            dest = os.path.join(out_root, slug, name)
            for m in members:
                if not (m.name == prefix or m.name.startswith(prefix + "/")):
                    continue
                rel = m.name[len(prefix):].lstrip("/")
                target = os.path.join(dest, rel)
                if m.isdir():
                    os.makedirs(target, exist_ok=True)
                elif m.isreg():
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as fh:
                        fh.write(tar.extractfile(m).read())
                    if m.mode & 0o100:
                        os.chmod(target, 0o755)
                else:
                    skipped.append(f"{repo}:{m.name}")
            samples.append({
                "id": f"benign/{slug}/{name}", "label": "benign", "category": "real-world",
                "path": f"benign/{slug}/{name}",
                "source": f"https://github.com/{repo}/tree/{sha}/{prefix[len(top) + 1:]}",
                "license": license_id})
        license_member = next((m for m in members if m.name.split("/")[-1] in
                               ("LICENSE", "LICENSE.txt", "LICENSE.md")
                               and m.name.count("/") == 1), None)
        if license_member is not None:
            with open(os.path.join(out_root, slug, "LICENSE"), "wb") as fh:
                fh.write(tar.extractfile(license_member).read())
        elif license_id == "Apache-2.0":
            # anthropics/skills keeps a LICENSE.txt in each skill folder.
            pass
    path = os.path.join(BENCH, "manifest.json")
    try:
        with open(path) as fh:
            manifest = json.load(fh)
    except OSError:
        manifest = {"schema": "canary.bench/1", "samples": []}
    manifest["samples"] = [s for s in manifest["samples"] if s["label"] != "benign"] + samples
    with open(path, "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    print(f"copied {len(samples)} harmless skills; skipped {len(skipped)} non-regular entries")
    for s in skipped:
        print("  skipped", s)


if __name__ == "__main__":
    main()
