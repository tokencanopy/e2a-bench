#!/usr/bin/env python3
"""Run the remaining Gemini models through the CANONICAL segment input and grade
per-surface (pi + phishing), so they slot into the same table as 2.5-flash."""
import json, os, sys, time, subprocess, shutil
import concurrent.futures as cf

REPO = os.environ.get("E2A_REPO") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "eval"))
os.chdir(REPO)
from detectors import GeminiDetector  # noqa

MODELS = ["gemini-3.1-flash-lite", "gemini-3.5-flash"]
WORKERS = 12
MAN = "eval/paper_manifest.jsonl"
entries = [json.loads(l) for l in open(MAN) if l.strip()]


def run(model):
    det = GeminiDetector(model=model, base_dir=REPO, task="injection")
    inj_name = det.name
    phi_name = inj_name.replace("_injection", "_phishing")
    slug = model.replace("-", "_").replace(".", "_")
    base = f"eval/runs/gemini-canonical-{slug}"
    inj_dir, phi_dir = f"{base}/injection", f"{base}/phishing"
    os.makedirs(inj_dir, exist_ok=True); os.makedirs(phi_dir, exist_ok=True)

    def predict_one(e, retries=2):
        for a in range(retries + 1):
            p = det.predict(e)
            if not p.error:
                return p
            if a < retries:
                time.sleep(1.5 * (a + 1))
        return p

    res = {}; t0 = time.monotonic(); n = 0
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(predict_one, e): e for e in entries}
        for fut in cf.as_completed(futs):
            p = fut.result(); cats = p.categories[0] if p.categories else {}
            res[p.id] = {"inj": cats.get("injection_confidence", p.score),
                         "phi": cats.get("phishing_confidence", 0.0), "err": p.error, "lat": p.latency_ms}
            n += 1
            if n % 1000 == 0:
                print(f"[{model}] {n}/{len(entries)} {n/(time.monotonic()-t0):.1f}/s", flush=True)
    errs = sum(1 for r in res.values() if r["err"])
    print(f"[{model}] DONE preds={len(res)} errors={errs}", flush=True)
    for name, key, d in ((inj_name, "inj", inj_dir), (phi_name, "phi", phi_dir)):
        with open(f"{d}/{name}.jsonl", "w") as f:
            for e in entries:
                r = res.get(e["id"])
                if r:
                    f.write(json.dumps({"id": e["id"], "detector": name, "score": r[key],
                                        "flagged": r[key] >= 0.5, "error": r["err"], "latency_ms": r["lat"]}) + "\n")
        shutil.copy(MAN, f"{d}/manifest_used.jsonl")
    subprocess.run([sys.executable, "eval/grade.py", "--run-dir", inj_dir, "--task", "pi", "--slice", "surface"], cwd=REPO, stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, "eval/grade.py", "--run-dir", phi_dir, "--task", "phishing", "--slice", "surface"], cwd=REPO, stdout=subprocess.DEVNULL)
    print(f"[{model}] GRADED", flush=True)


for m in MODELS:
    run(m)
print("MULTI_DONE", flush=True)
