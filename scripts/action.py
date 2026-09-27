#!/usr/bin/env python3
"""Run Canary's bundled deterministic scanner for a GitHub Action."""

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ACTION_ROOT = Path(__file__).resolve().parents[1]
SCANNER = ACTION_ROOT / "scanner" / "bin" / "jev-scan"
MANIFEST = ACTION_ROOT / "scanner" / "manifest.json"
SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 2, "high": 3}
LAYER1_TO_ACTION = {
    "LIKELY_SAFE": "safe",
    "NEEDS_REVIEW": "review",
    "UNSAFE": "unsafe",
}
VERDICT_RANK = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}
FAIL_RANK = {"never": 3, "unsafe": 2, "review": 1}
SCANNER_SKIPPED_DIRECTORIES = {"bin", ".git", "__pycache__", "node_modules"}


class ActionError(Exception):
    """An operational error that prevents a complete scan."""


def scanner_manifest():
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        expected_hash = manifest["sha256"]
        bundled_version = manifest["version"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ActionError("the bundled scanner manifest is invalid") from exc
    actual_hash = hashlib.sha256(SCANNER.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise ActionError("the bundled scanner failed its integrity check")
    return bundled_version


def verdict_for_score(score):
    if score >= 6:
        return "UNSAFE"
    if score >= 3:
        return "NEEDS_REVIEW"
    return "LIKELY_SAFE"


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

        def remember_walk_error(error):
            walk_errors.append(error)

        for root, directories, files in os.walk(target, onerror=remember_walk_error):
            directories[:] = [
                name for name in directories
                if name not in SCANNER_SKIPPED_DIRECTORIES
            ]
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
    return target


def worst_file_verdict(findings):
    scores = defaultdict(int)
    for finding in findings:
        scores[finding["file"]] += SEVERITY_WEIGHT[finding["severity"]]
    verdicts = [verdict_for_score(score) for score in scores.values()]
    return max(verdicts, key=VERDICT_RANK.get, default="LIKELY_SAFE")


def validated_report(raw_output):
    try:
        report = json.loads(raw_output)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ActionError("the bundled scanner returned malformed JSON") from exc
    if not isinstance(report, dict):
        raise ActionError("the bundled scanner returned malformed JSON")
    files_scanned = report.get("files_scanned")
    findings = report.get("findings")
    if not isinstance(files_scanned, int) or isinstance(files_scanned, bool):
        raise ActionError("the bundled scanner returned malformed JSON")
    if files_scanned < 1:
        raise ActionError("the scan found no supported files")
    if not isinstance(findings, list):
        raise ActionError("the bundled scanner returned malformed JSON")
    if report.get("deterministic_verdict") not in LAYER1_TO_ACTION:
        raise ActionError("the bundled scanner returned malformed JSON")
    score = report.get("score")
    if not isinstance(score, int) or isinstance(score, bool) or score < 0:
        raise ActionError("the bundled scanner returned malformed JSON")
    for finding in findings:
        if not isinstance(finding, dict):
            raise ActionError("the bundled scanner returned malformed JSON")
        if finding.get("severity") not in SEVERITY_WEIGHT:
            raise ActionError("the bundled scanner returned malformed JSON")
        if not isinstance(finding.get("category"), str):
            raise ActionError("the bundled scanner returned malformed JSON")
        if not isinstance(finding.get("check_id"), str):
            raise ActionError("the bundled scanner returned malformed JSON")
        if not isinstance(finding.get("file"), str):
            raise ActionError("the bundled scanner returned malformed JSON")
        line = finding.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 0:
            raise ActionError("the bundled scanner returned malformed JSON")
        if finding.get("check_id") == "read-error":
            raise ActionError("the scanner could not read every selected file")
    return report


def safe_display(value):
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def write_outputs(layer1_verdict):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        raise ActionError("GITHUB_OUTPUT is not set")
    verdict = LAYER1_TO_ACTION[layer1_verdict]
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"verdict={verdict}\n")
        output.write(f"layer1_verdict={layer1_verdict}\n")
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
    completed = subprocess.run(
        [sys.executable, str(SCANNER), str(target)],
        env=scanner_environment,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ActionError("the bundled scanner could not complete")
    report = validated_report(completed.stdout)

    findings = report["findings"]
    layer1_verdict = worst_file_verdict(findings)
    print(
        f"Canary layer 1: files={report['files_scanned']} "
        f"findings={len(findings)} verdict={layer1_verdict}"
    )
    for finding in findings:
        print(
            "Canary finding: "
            f"category={safe_display(finding['category'])} "
            f"severity={safe_display(finding['severity'])} "
            f"file={safe_display(finding['file'])} "
            f"line={safe_display(finding['line'])}"
        )
    verdict = write_outputs(layer1_verdict)
    return 1 if FAIL_RANK[fail_on] <= VERDICT_RANK[layer1_verdict] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ActionError, KeyError, OSError) as exc:
        print(f"Canary action error: {safe_display(exc)}", file=sys.stderr)
        raise SystemExit(2)
