import json, sys, os, concurrent.futures as cf
sys.path.insert(0, sys.argv[1]); from canary import classify
B, OUT = sys.argv[2], sys.argv[3]
os.makedirs(OUT, exist_ok=True)
m = json.load(open(os.path.join(B, "manifest.json")))
def one(s):
    dest = os.path.join(OUT, s["id"].replace("/", "__") + ".json")
    if os.path.exists(dest): return
    r, conf = classify._check(os.path.join(B, s["path"]), backend="claude", log_dir=os.path.join(OUT, "_logs"))
    json.dump({"sample": s, "confident": conf, "result": r}, open(dest, "w"))
    print(s["id"], r["verdict"], r["classifier"].get("status"), r["classifier"].get("verdict"), flush=True)
with cf.ThreadPoolExecutor(4) as p: list(p.map(one, m["samples"]))
print("DONE", flush=True)
