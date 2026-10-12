"""Per-sample CSV from layer2.py's output folder (both layers) plus a
pattern-scan-only run, using this branch's explain.recommend."""
import csv, glob, json, os, sys
sys.path.insert(0, sys.argv[1]); from canary import classify, explain
out = csv.writer(sys.stdout)
out.writerow(["id", "label", "category", "verdict", "ai_review", "ai_confidence",
              "recommendation", "pattern_scan_only_recommendation"])
for p in sorted(glob.glob(os.path.join(sys.argv[2], "*.json"))):
    d = json.load(open(p)); r, s = d["result"], d["sample"]
    l1 = classify.check(os.path.join(sys.argv[3], s["path"]), backend="none", log_dir=sys.argv[4])
    c = r["classifier"]
    out.writerow([s["id"], s["label"], s["category"], r["verdict"], c.get("verdict") or c["status"],
                  c.get("confidence", ""), explain.recommend(r, d["confident"])["action"],
                  l1["recommendation"]["action"]])
