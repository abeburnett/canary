"""`canary bench`: how well the check separates malicious skills from harmless
ones (docs/architecture.md, "canary bench"; program 2026-09-30, slice D).

The corpus lives in `bench/`, listed in `bench/manifest.json`: each sample has
an id, a label (malicious or benign), a category, its folder, and where it
came from. Layer 1 (the pattern scan) runs everywhere, CI included; layer 2
adds the isolated classifier and needs a model.

Two readings of each rate (owner decision 12):
- caught_flagged: malicious samples whose verdict is not LIKELY_SAFE, so the
  person is warned or the skill is refused. CI guards this one.
- caught_blocked: malicious samples judged UNSAFE.
- false_alarm_flagged / false_alarm_blocked: the same for harmless samples.
A harmless skill that runs code or grants tools is never LIKELY_SAFE by
design, so false_alarm_flagged includes those.
"""

import json
import os

from canary import classify, scan

SCHEMA = "canary.bench/1"
FLAGGED = ("NEEDS_REVIEW", "UNSAFE")


class BenchError(Exception):
    pass


def load(root):
    try:
        with open(os.path.join(root, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BenchError(f"{root}/manifest.json could not be read") from exc
    if manifest.get("schema") != SCHEMA or not isinstance(manifest.get("samples"), list):
        raise BenchError(f"{root}/manifest.json is not a {SCHEMA} manifest")
    seen = set()
    for s in manifest["samples"]:
        if (not isinstance(s, dict) or s.get("label") not in ("malicious", "benign")
                or not isinstance(s.get("id"), str) or s["id"] in seen
                or not isinstance(s.get("path"), str) or os.path.isabs(s["path"])
                or ".." in s["path"].split("/")):
            raise BenchError(f"bad sample in {root}/manifest.json: {s!r:.200}")
        seen.add(s["id"])
        if not os.path.isdir(os.path.join(root, s["path"])):
            raise BenchError(f"sample {s['id']} has no folder at {s['path']}")
    return manifest["samples"]


def _rate(part, whole):
    return round(part / whole, 4) if whole else 0.0


def run(root, layer=1, backend="auto", model=None, timeout_s=classify.DEFAULT_TIMEOUT_S):
    samples = load(root)
    rows = []
    for s in samples:
        folder = os.path.join(root, s["path"])
        if layer == 1:
            verdict = scan.scan_package(folder)["verdict"]
        else:
            verdict = classify.check(folder, backend=backend, model=model,
                                     timeout_s=timeout_s)["verdict"]
        rows.append(dict(s, verdict=verdict))
    bad = [r for r in rows if r["label"] == "malicious"]
    good = [r for r in rows if r["label"] == "benign"]
    categories = {}
    for r in bad:
        c = categories.setdefault(r.get("category", "other"), {"samples": 0, "caught": 0})
        c["samples"] += 1
        c["caught"] += r["verdict"] in FLAGGED
    return {
        "schema": "canary.bench.result/1", "layer": layer,
        "malicious": len(bad), "benign": len(good),
        "caught_flagged": _rate(sum(r["verdict"] in FLAGGED for r in bad), len(bad)),
        "caught_blocked": _rate(sum(r["verdict"] == "UNSAFE" for r in bad), len(bad)),
        "false_alarm_flagged": _rate(sum(r["verdict"] in FLAGGED for r in good), len(good)),
        "false_alarm_blocked": _rate(sum(r["verdict"] == "UNSAFE" for r in good), len(good)),
        "by_category": categories,
        "misses": sorted(r["id"] for r in bad if r["verdict"] not in FLAGGED),
        "false_alarms_blocked": sorted(r["id"] for r in good if r["verdict"] == "UNSAFE"),
    }


def render_text(result):
    pct = lambda x: f"{100 * x:.1f}%"
    lines = [f"SkillCanary benchmark, layer {result['layer']}: "
             f"{result['malicious']} malicious, {result['benign']} harmless skills", "",
             f"Caught (warned or refused): {pct(result['caught_flagged'])}",
             f"Caught (refused):           {pct(result['caught_blocked'])}",
             f"False alarms (warned):      {pct(result['false_alarm_flagged'])}",
             f"False alarms (refused):     {pct(result['false_alarm_blocked'])}", "",
             "By category (caught, warned or refused):"]
    for name, c in sorted(result["by_category"].items()):
        lines.append(f"  {name:<28} {c['caught']}/{c['samples']}")
    if result["misses"]:
        lines += ["", "Missed: " + ", ".join(result["misses"])]
    return "\n".join(lines)
