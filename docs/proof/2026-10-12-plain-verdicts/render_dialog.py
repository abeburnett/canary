"""Render the canary add dialog for the README's example fixture, with the
pattern scan only (no model call), from the repository root."""
import sys
sys.path.insert(0, ".")
from canary import add, classify
snap = "docs/proof/2026-10-12-plain-verdicts/fixture/notes-helper"
r = classify.check(snap, backend="none", log_dir=sys.argv[1])
print(add.dialog_text({
    "verdict": r["verdict"], "reasons": r["reasons"], "name": "notes-helper",
    "owner": "someone", "repo": "skills", "commit": "a1b2c3d4e5", "hosts": ["claude"],
    "capabilities": [], "_snapshot": snap, "headline": r["headline"],
    "next_steps": r["next_steps"], "recommendation": r["recommendation"], "risks": r["risks"]}))
