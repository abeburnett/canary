#!/usr/bin/env python3
"""Verify a SkillCanary badge against a skill folder and the signed revocation list.

Only badges signed by the production SkillCanary key verify. The key id is
built in; a key file shipped next to a badge cannot replace it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
import urllib.parse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


UTC = dt.timezone.utc
BADGE_SCHEMA = "skillcanary.badge.v2"  # v2: skill.sha256 is the skill-folder digest
REVOCATIONS_SCHEMA = "skillcanary.revocations.v1"
REVOCATION_REASONS = frozenset({"withdrawn", "changed-content", "review-invalidated"})
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
GITHUB_HANDLE_RE = re.compile(r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")


# The production SkillCanary signing key (SHA-256 of its raw Ed25519 bytes).
TRUSTED_KEY_ID = "e714d1ced919daeea358e9b0d384b083d4d0bdea3aa99b115c64db0d47a47841"
# A revocation list may claim freshness for at most this long after signing.
MAX_REVOCATION_WINDOW = dt.timedelta(days=7)
TREE_DIGEST_PREFIX = b"skillcanary.tree.v1\n"


class VerificationError(RuntimeError):
    """A public artifact or required trust input failed verification."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise VerificationError("required input file could not be read") from exc


def skill_digest(path: Path) -> str:
    """Digest of every file in a skill folder; files, links and unlistable folders refused.

    Must match skill_digest() in the issuer (canary-pro badges/canary_badges.py).
    """
    lines = []
    if path.is_symlink() or not path.is_dir():
        raise VerificationError("the skill path must be a folder, not a file or link")

    def unreadable(exc: OSError) -> None:
        raise VerificationError("the skill folder could not be read completely") from exc

    for root, dirs, files in os.walk(path, onerror=unreadable):
        for name in dirs + files:
            full = Path(root) / name
            if full.is_symlink() or not (full.is_dir() or full.is_file()):
                raise VerificationError("the skill folder contains a link or special file")
        for name in files:
            full = Path(root) / name
            lines.append(f"{full.relative_to(path).as_posix()}\0{sha256_file(full)}\n")
    if not lines:
        raise VerificationError("the skill folder is empty")
    return sha256_bytes(TREE_DIGEST_PREFIX + "".join(sorted(lines)).encode("utf-8"))


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not readable JSON") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise VerificationError(f"{label} has missing or unsupported fields")


def timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerificationError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise VerificationError(f"{label} must be an RFC 3339 UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise VerificationError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def validate_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise VerificationError(f"{label} must be a stable identifier")
    return value


def validate_handle(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GITHUB_HANDLE_RE.fullmatch(value):
        raise VerificationError(f"{label} must be a GitHub handle")
    return value


def validate_public_url(value: Any, label: str) -> str:
    if not isinstance(value, str) or "@" in urllib.parse.unquote(value):
        raise VerificationError(f"{label} must be a public HTTPS URL without contact data")
    parsed = urllib.parse.urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise VerificationError(f"{label} must be a public HTTPS URL without contact data")
    return value


def validate_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise VerificationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise VerificationError("public key file is not a PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("public key must be Ed25519")
    return key


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_bytes(raw)


def verify_document(
    document: dict[str, Any],
    expected_schema: str,
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    exact_keys(document, {"schema", "payload", "signature"}, "signed document")
    if document["schema"] != expected_schema or not isinstance(document["payload"], dict):
        raise VerificationError("signed document schema is invalid")
    signature = document["signature"]
    if not isinstance(signature, dict):
        raise VerificationError("signature block is invalid")
    exact_keys(signature, {"algorithm", "key_id", "value"}, "signature block")
    if signature["algorithm"] != "Ed25519" or signature["key_id"] != key_id(public_key):
        raise VerificationError("signature does not use the trusted public key")
    try:
        signature_bytes = base64.b64decode(signature["value"], validate=True)
        public_key.verify(
            signature_bytes,
            canonical({"schema": document["schema"], "payload": document["payload"]}),
        )
    except (InvalidSignature, binascii.Error, TypeError, ValueError) as exc:
        raise VerificationError("signature verification failed") from exc
    return document["payload"]


def validate_badge_payload(payload: dict[str, Any]) -> None:
    exact_keys(
        payload,
        {"badge_id", "skill", "publisher", "scan_evidence", "issued_at", "expires_at"},
        "badge payload",
    )
    validate_identifier(payload["badge_id"], "badge_id")
    skill = payload["skill"]
    if not isinstance(skill, dict):
        raise VerificationError("skill record is invalid")
    exact_keys(skill, {"id", "version", "sha256"}, "skill record")
    validate_identifier(skill["id"], "skill.id")
    validate_identifier(skill["version"], "skill.version")
    skill_hash = validate_hash(skill["sha256"], "skill.sha256")

    publisher = payload["publisher"]
    if not isinstance(publisher, dict):
        raise VerificationError("publisher record is invalid")
    exact_keys(
        publisher,
        {"github_handle", "repository_url", "control_evidence_url"},
        "publisher record",
    )
    validate_handle(publisher["github_handle"], "publisher.github_handle")
    validate_public_url(publisher["repository_url"], "publisher.repository_url")
    validate_public_url(publisher["control_evidence_url"], "publisher.control_evidence_url")

    evidence = payload["scan_evidence"]
    if not isinstance(evidence, dict):
        raise VerificationError("scan evidence is invalid")
    exact_keys(
        evidence,
        {"binding", "skill_sha256", "layer1", "layer2"},
        "scan evidence",
    )
    if evidence["binding"] != "operator-attested":
        raise VerificationError("scan evidence binding is invalid")
    if validate_hash(evidence["skill_sha256"], "scan evidence skill hash") != skill_hash:
        raise VerificationError("scan evidence is bound to different skill content")
    for name in ("layer1", "layer2"):
        layer = evidence[name]
        if not isinstance(layer, dict):
            raise VerificationError(f"{name} evidence is invalid")
        exact_keys(layer, {"verdict", "report_sha256"}, f"{name} evidence")
        if layer["verdict"] != "SAFE":
            raise VerificationError(f"{name} evidence is not SAFE")
        validate_hash(layer["report_sha256"], f"{name} report hash")

    issued_at = timestamp(payload["issued_at"], "issued_at")
    expires_at = timestamp(payload["expires_at"], "expires_at")
    now = dt.datetime.now(tz=UTC)
    if issued_at > now:
        raise VerificationError("badge issue time is in the future")
    if expires_at <= now or expires_at <= issued_at:
        raise VerificationError("badge is expired or has invalid dates")


def validate_revocations(payload: dict[str, Any]) -> list[dict[str, Any]]:
    exact_keys(payload, {"issued_at", "next_update", "entries"}, "revocation payload")
    issued_at = timestamp(payload["issued_at"], "revocations.issued_at")
    next_update = timestamp(payload["next_update"], "revocations.next_update")
    now = dt.datetime.now(tz=UTC)
    if issued_at > now:
        raise VerificationError("revocation list issue time is in the future")
    if next_update <= issued_at or next_update <= now:
        raise VerificationError("revocation list is stale")
    if next_update - issued_at > MAX_REVOCATION_WINDOW:
        raise VerificationError("revocation list claims freshness for more than 7 days")
    entries = payload["entries"]
    if not isinstance(entries, list):
        raise VerificationError("revocation entries are invalid")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise VerificationError("revocation entry is invalid")
        exact_keys(
            entry,
            {"badge_id", "badge_sha256", "revoked_at", "reason"},
            "revocation entry",
        )
        badge_id = validate_identifier(entry["badge_id"], "revocation badge_id")
        badge_hash = validate_hash(entry["badge_sha256"], "revocation badge hash")
        revoked_at = timestamp(entry["revoked_at"], "revoked_at")
        if revoked_at > now or revoked_at > issued_at:
            raise VerificationError("revocation time is invalid")
        if entry["reason"] not in REVOCATION_REASONS:
            raise VerificationError("revocation reason is invalid")
        if badge_id in seen_ids or badge_hash in seen_hashes:
            raise VerificationError("revocation list contains a duplicate")
        seen_ids.add(badge_id)
        seen_hashes.add(badge_hash)
    return entries


def verify(args: argparse.Namespace) -> None:
    public_key = load_public_key(args.public_key)
    if key_id(public_key) != TRUSTED_KEY_ID:
        raise VerificationError("public key is not the SkillCanary signing key")
    badge_document = load_json(args.badge, "badge")
    badge = verify_document(badge_document, BADGE_SCHEMA, public_key)
    validate_badge_payload(badge)
    if skill_digest(args.skill) != badge["skill"]["sha256"]:
        raise VerificationError("skill content does not match the badge")

    revocation_document = load_json(args.revocations, "revocation list")
    revocations = verify_document(revocation_document, REVOCATIONS_SCHEMA, public_key)
    entries = validate_revocations(revocations)
    if timestamp(revocations["issued_at"], "revocations.issued_at") < timestamp(
        badge["issued_at"],
        "badge.issued_at",
    ):
        raise VerificationError("revocation list predates the badge")
    badge_hash = sha256_bytes(canonical(badge_document))
    if any(
        entry["badge_id"] == badge["badge_id"]
        or entry["badge_sha256"] == badge_hash
        for entry in entries
    ):
        raise VerificationError("badge is revoked")
    print(f"VALID (signed by SkillCanary key {TRUSTED_KEY_ID})")


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--badge", type=Path, required=True)
    argument_parser.add_argument("--public-key", type=Path, required=True)
    argument_parser.add_argument("--skill", type=Path, required=True)
    argument_parser.add_argument("--revocations", type=Path, required=True)
    return argument_parser


def main() -> int:
    try:
        verify(parser().parse_args())
    except VerificationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
