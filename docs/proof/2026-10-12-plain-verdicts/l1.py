import json, sys, os, collections
sys.path.insert(0, sys.argv[1]); from canary import classify
B = sys.argv[2]; m = json.load(open(os.path.join(B, "manifest.json")))
rows = collections.defaultdict(collections.Counter)
for s in m["samples"]:
    r = classify.check(os.path.join(B, s["path"]), backend="none", log_dir=os.path.join(sys.argv[3]))
    c = rows[(s["label"], s["category"])]; c["n"] += 1; c["rec_" + r["recommendation"]["action"]] += 1
    for risk in r["risks"]: rows[("risks", s["label"])][risk[:40]] += 1
for k in sorted(rows): print(k, dict(sorted(rows[k].items())))
