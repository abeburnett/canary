#!/usr/bin/env python3
"""Run SkillCanary's bundled deterministic scanner for a GitHub Action.

Each skill folder (a directory holding SKILL.md) is scanned as one package, so
findings spread across a skill's files are totalled the way the scanner totals
them. Everything else under the path, except those folders and the
checkout's own .git, is scanned as one more package, so a harmless skill
folder cannot hide files next to it. The Action's verdict is the strictest
package verdict.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ACTION_ROOT = Path(__file__).resolve().parents[1]
CANARY = ACTION_ROOT / "bin" / "canary"
MANIFEST = ACTION_ROOT / "scanner" / "manifest.json"
SCANNER_EXIT = {0: "LIKELY_SAFE", 10: "NEEDS_REVIEW", 20: "UNSAFE"}
LAYER1_TO_ACTION = {
    "LIKELY_SAFE": "safe",
    "NEEDS_REVIEW": "review",
    "UNSAFE": "unsafe",
}
VERDICT_RANK = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}
FAIL_RANK = {"never": 3, "unsafe": 2, "review": 1}
SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")


class ActionError(Exception):
    """An operational error that prevents a complete scan."""


def bundled_files():
    """Every file the scanner runs from, relative to the Action root."""
    files = {"bin/canary"}
    # Every module, including canary/hosts and canary/classifiers: cli.py
    # imports them, so an unlisted file would run unchecked.
    files.update(p.relative_to(ACTION_ROOT).as_posix()
                 for p in (ACTION_ROOT / "canary").rglob("*.py"))
    return files


def scanner_manifest():
    """Check every bundled scanner file against the manifest; return its version."""
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        bundled_version = manifest["version"]
        expected = manifest["files"]
        if not isinstance(expected, dict):
            raise TypeError
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ActionError("the bundled scanner manifest is invalid") from exc
    if set(expected) != bundled_files():
        raise ActionError("the bundled scanner files do not match the manifest")
    for name, digest in expected.items():
        try:
            actual = hashlib.sha256((ACTION_ROOT / name).read_bytes()).hexdigest()
        except OSError as exc:
            raise ActionError("the bundled scanner failed its integrity check") from exc
        if actual != digest:
            raise ActionError("the bundled scanner failed its integrity check")
    return bundled_version


def is_within(path, directory):
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def resolve_target(workspace, supplied_path):
    try:
        target = (workspace / supplied_path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ActionError("the scan path does not exist or cannot be resolved") from exc
    if not is_within(target, workspace):
        raise ActionError("the scan path must stay inside GITHUB_WORKSPACE")
    if target.is_dir():
        walk_errors = []
        for root, directories, files in os.walk(target, onerror=walk_errors.append):
            for name in directories + files:
                candidate = Path(root) / name
                if not candidate.is_symlink():
                    continue
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise ActionError("the scan path contains an invalid symlink") from exc
                if not is_within(resolved, workspace):
                    raise ActionError("the scan path contains a symlink outside GITHUB_WORKSPACE")
        if walk_errors:
            raise ActionError("the scan path could not be read completely")
        if not any(files for _, _, files in os.walk(target)):
            raise ActionError("the scan path contains no files")
    return target


def skill_packages(target):
    """[(package, exclude)]: each skill folder, then the rest of the path."""
    if not target.is_dir():
        return [(target, [])]
    skills = sorted({Path(root) for root, _, files in os.walk(target)
                     if any(name.lower() == "skill.md" for name in files)})
    if skills == [target]:
        return [(target, [".git"] if (target / ".git").is_dir() else [])]
    exclude = [os.path.relpath(skill, target) for skill in skills if skill != target]
    if (target / ".git").is_dir():
        exclude.append(".git")
    packages = [(skill, []) for skill in skills if skill != target]
    skipped = {target / rel for rel in exclude}
    rest_has_files = False
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if Path(root) / d not in skipped]
        if files:
            rest_has_files = True
            break
    if rest_has_files or not packages:
        packages.append((target, exclude))
    return packages


def display_path(path, workspace):
    rel = os.path.relpath(path, workspace)
    if SAFE_PATH.match(rel):
        return rel
    # Repository paths are attacker-controlled in pull requests; never echo odd ones.
    return "path-sha256:" + hashlib.sha256(rel.encode("utf-8", "replace")).hexdigest()[:12]


def scan(package, exclude, environment):
    command = [sys.executable, str(CANARY), "scan", str(package), "--json"]
    for rel in exclude:
        command += ["--exclude", rel]
    completed = subprocess.run(
        command,
        env=environment, text=True, capture_output=True, check=False,
    )
    if completed.returncode not in SCANNER_EXIT:
        raise ActionError("the bundled scanner could not complete")
    try:
        report = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ActionError("the bundled scanner returned malformed JSON") from exc
    if not isinstance(report, dict) or report.get("schema") != "canary.scan/1":
        raise ActionError("the bundled scanner returned malformed JSON")
    verdict = report.get("verdict")
    coverage = report.get("coverage")
    if verdict != SCANNER_EXIT[completed.returncode] or not isinstance(coverage, dict) \
            or not isinstance(coverage.get("complete"), bool) \
            or not isinstance(report.get("findings"), list) \
            or not isinstance(report.get("capabilities"), list):
        raise ActionError("the bundled scanner returned malformed JSON")
    return report


def safe_display(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def write_outputs(layer1_verdict, complete):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise ActionError("GITHUB_OUTPUT is not set")
    verdict = LAYER1_TO_ACTION[layer1_verdict]
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"verdict={verdict}\n")
        output.write(f"layer1_verdict={layer1_verdict}\n")
        output.write(f"coverage_complete={'true' if complete else 'false'}\n")
    return verdict


def main():
    fail_on = os.environ.get("CANARY_FAIL_ON", "unsafe").lower()
    if fail_on not in FAIL_RANK:
        raise ActionError("fail-on must be one of: unsafe, review, never")

    repository_private = os.environ.get("CANARY_REPOSITORY_PRIVATE", "false").lower()
    if repository_private not in ("true", "false"):
        raise ActionError("repository privacy metadata is invalid")
    if repository_private == "true" and not os.environ.get("CANARY_API_TOKEN", "").strip():
        raise ActionError("CANARY_API_TOKEN is required for private repositories")

    requested_version = os.environ.get("CANARY_VERSION", "latest")
    bundled_version = scanner_manifest()
    if requested_version not in ("latest", bundled_version):
        raise ActionError(
            f"requested scanner version is not bundled; use latest or {bundled_version}"
        )

    try:
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    except (KeyError, OSError, RuntimeError) as exc:
        raise ActionError("GITHUB_WORKSPACE is missing or invalid") from exc
    target = resolve_target(workspace, os.environ.get("CANARY_INPUT_PATH", "."))
    scanner_environment = os.environ.copy()
    scanner_environment.pop("CANARY_API_TOKEN", None)

    overall, complete = "LIKELY_SAFE", True
    for package, exclude in skill_packages(target):
        report = scan(package, exclude, scanner_environment)
        verdict = report["verdict"]
        overall = max(overall, verdict, key=VERDICT_RANK.get)
        complete = complete and report["coverage"]["complete"]
        categories = sorted({f.get("category", "?") for f in report["findings"]
                             if f.get("severity") != "info"})
        kinds = sorted({c.get("kind", "?") for c in report["capabilities"]})
        print(
            f"SkillCanary: package={safe_display(display_path(package, workspace))} "
            f"verdict={verdict} score={report.get('score')} "
            f"coverage_complete={report['coverage']['complete']} "
            f"threats={safe_display(','.join(categories) or 'none')} "
            f"capabilities={safe_display(','.join(kinds) or 'none')}"
        )
    write_outputs(overall, complete)
    failed = FAIL_RANK[fail_on] <= VERDICT_RANK[overall]
    if not complete and fail_on != "never":
        print("SkillCanary: some files could not be read, so this scan cannot pass.")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ActionError, KeyError, OSError) as exc:
        print(f"SkillCanary action error: {safe_display(exc)}", file=sys.stderr)
        raise SystemExit(2)
