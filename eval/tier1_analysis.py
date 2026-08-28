#!/usr/bin/env python3
"""tier1_analysis.py — single-population Table 1, payload-grouped dev/test split,
payload-clustered bootstrap CIs, and the DMARC trust-prior stratification.

Fixes three protocol gaps in the first paper draft:
  1. Judges and baselines were reported on different populations (judge: stratified
     test half, PDF excluded; baselines: full corpus incl. PDF). Here EVERY detector
     is scored on the identical text population (the 5,955 ids the judge matrix
     covers), and headline metrics are read on the held-out test half only.
  2. The old dev/test split alternated individual ids, so the same base payload
     (rendered across ~8 surfaces) appeared on both sides. Here the split unit is
     base_payload_id: all renderings of one lure land on one side.
  3. No uncertainty was reported. Here every metric gets a payload-clustered
     bootstrap CI (resample groups, not rows, so surface-correlated renderings of
     one lure are not treated as independent).

Also runs the sender-auth (DMARC) stratification: PI positives carry a balanced
1/3-1/3-1/3 verified/spoofed/unauthenticated assignment BY CONSTRUCTION, so
sender auth is deliberately uninformative as a standalone PI feature on this
corpus. The honest questions are conditional: (a) is detection harder inside the
verified stratum, and (b) what does a two-tier threshold policy (loosen on
DMARC-aligned senders) buy at matched overall FPR.

Reads only committed/on-disk per-entry predictions — no API calls.
Outputs: eval/results/tier1-analysis/{table1_aligned,dmarc_stratified}.json + stdout tables.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict

import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)

# One shared stream, drawn from in detector order: a run that scores fewer
# detectors (baseline predictions absent) reaches the later tasks at a different
# stream position, so recomputed bootstrap CIs move in the 3rd-4th decimal. Point
# estimates are unaffected. Seeding per (task, detector) would make CIs invariant
# but would move every currently published interval, so the stream is left alone.
RNG = np.random.default_rng(20260702)
N_BOOT = 1000

JUDGES = {  # display name -> matrix per-entry file (N=1, strict-PI / base-phishing prompts)
    "judge:flash-lite": "llm-judge/results/matrix/gemini_3_1_flash_lite_N1.jsonl",
    "judge:2.5-flash": "llm-judge/results/matrix/gemini_2_5_flash_N1.jsonl",
    "judge:3.5-flash": "llm-judge/results/matrix/gemini_3_5_flash_N1.jsonl",
}
BASELINES = {  # display name -> per-entry predictions (canonical segment view, full corpus)
    "deberta-v3": "runs/offline-oss/hf_deberta_v3_base_prompt_injection_v2.jsonl",
    "injecguard": "runs/offline-oss/hf_InjecGuard.jsonl",
    "llama-pg2": "runs/offline-oss/hf_Llama_Prompt_Guard_2_86M.jsonl",
    "distilbert": "runs/offline-oss/hf_distilbert_prompt_injection.jsonl",
    "piguard": "runs/offline-oss/piguard.jsonl",
    "ensemble": "runs/offline-oss/ensemble_mean.jsonl",
    "modelarmor": "runs/modelarmor/modelarmor.jsonl",
    "lakera": "runs/lakera/lakera.jsonl",
    "scamguard": "runs/scamguard/scamguard.jsonl",
}
THRESH = 0.35  # e2a review action band, same fixed cut as the paper


def load_manifest():
    rows = [json.loads(l) for l in open("combined_manifest.jsonl")]
    return {r["id"]: r for r in rows}


# SpamAssassin's spam split is stamped threat_type="spam"; earlier corpus
# revisions used "scam". Both are Track-B (phishing-task) positives — the
# balanced 1,500/1,500 phishing split is 1,000 Nazario + 500 SpamAssassin spam.
PHISH_POSITIVE_TYPES = {"phishing", "spam", "scam"}


def pi_label(entry):
    tt = entry["label"].get("threat_type", "benign")
    if tt.startswith("prompt_injection"):
        return 1
    return 0 if tt == "benign" else None  # phishing excluded from PI task


def phish_label(entry):
    tt = entry["label"].get("threat_type", "benign")
    if tt in PHISH_POSITIVE_TYPES:
        return 1
    return 0 if tt == "benign" else None


def group_of(entry):
    return entry.get("provenance", {}).get("base_payload_id") or entry["id"]


def _read_json(path):
    """Previous run's output, or None when absent/unreadable."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def load_scores(path, judge=False):
    out = {}
    for line in open(path):
        d = json.loads(line)
        if judge:
            out[d["id"]] = {"pi": float(d["pi_score"]), "phish": float(d["phi_score"])}
        else:
            s = d.get("score")
            if s is None:
                s = 1.0 if d.get("flagged") else 0.0
            out[d["id"]] = {"pi": float(s), "phish": float(s)}
    return out


def tpr_at_fpr(y, s, target=0.01):
    y = np.asarray(y)
    s = np.asarray(s)
    neg = np.sort(s[y == 0])[::-1]
    if len(neg) == 0:
        return float("nan")
    k = int(np.floor(target * len(neg)))  # strictest threshold admitting <= target FPR
    thr = neg[k] if k < len(neg) else neg[-1]
    # threshold must EXCEED thr if using >=; use > on the tied value to keep FPR <= target
    pred = s > thr
    fpr = pred[y == 0].mean()
    if fpr > target:  # ties pushed us over; back off one step
        pred = s > (thr + 1e-12)
    return float(pred[y == 1].mean())


def point_metrics(y, s, thresh):
    y = np.asarray(y)
    s = np.asarray(s)
    m = {}
    m["n"] = int(len(y))
    m["n_pos"] = int((y == 1).sum())
    m["n_neg"] = int((y == 0).sum())
    m["auc"] = float(roc_auc_score(y, s)) if len(set(y.tolist())) > 1 else float("nan")
    m["tpr_at_1pct_fpr"] = tpr_at_fpr(y, s, 0.01)
    pred = s >= thresh
    m["recall_at_t"] = float(pred[y == 1].mean()) if m["n_pos"] else float("nan")
    m["fpr_at_t"] = float(pred[y == 0].mean()) if m["n_neg"] else float("nan")
    return m


def cluster_bootstrap(ids, groups, y_by_id, s_by_id, thresh, n_boot=N_BOOT):
    """Resample payload groups with replacement; CI on AUC and TPR@1%FPR."""
    by_group = defaultdict(list)
    for i in ids:
        by_group[groups[i]].append(i)
    keys = sorted(by_group)
    aucs, tprs = [], []
    for _ in range(n_boot):
        pick = RNG.choice(len(keys), size=len(keys), replace=True)
        y, s = [], []
        for gi in pick:
            for i in by_group[keys[gi]]:
                y.append(y_by_id[i])
                s.append(s_by_id[i])
        y = np.asarray(y)
        if len(set(y.tolist())) < 2:
            continue
        s = np.asarray(s)
        aucs.append(roc_auc_score(y, s))
        tprs.append(tpr_at_fpr(y, s, 0.01))
    q = lambda a: [float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5))]
    return {"auc_ci": q(aucs), "tpr_at_1pct_fpr_ci": q(tprs)}


def main():
    man = load_manifest()
    # Per-message prediction files may be absent in a fresh checkout: the judge
    # scores ship with the repo, the baseline runs are regenerated via
    # run_eval.py (README step 3). Skip what is missing rather than crash.
    judge_scores = {k: load_scores(v, judge=True)
                    for k, v in JUDGES.items() if os.path.exists(v)}
    if not judge_scores:
        sys.exit("no judge prediction files found under llm-judge/results/matrix/")
    base_scores = {k: load_scores(v)
                   for k, v in BASELINES.items() if os.path.exists(v)}
    for k in sorted(set(JUDGES) - set(judge_scores) | set(BASELINES) - set(base_scores)):
        print(f"NOTE: {k}: predictions missing, skipped (regenerate via run_eval.py)")

    # ---- population: text corpus the judges cover (PDF surface excluded) ----
    text_ids = set.intersection(*[set(v) for v in judge_scores.values()])
    missing = {k: len(text_ids - set(v)) for k, v in base_scores.items()}
    assert all(v == 0 for v in missing.values()), f"baseline coverage gap: {missing}"
    pdf_ids = {i for i, e in man.items() if "pdf_attachment" in (e.get("surface") or [])}
    # The manifest is a superset: the PDF surface belongs to the vision track and
    # the GCG supplement is reported separately, so neither is in the judge
    # matrix. Name the remainder rather than printing a bare "match: NO", which
    # reads as a failure when it is the expected shape of the population.
    outside = (set(man) - pdf_ids) - text_ids
    print(f"population: {len(text_ids)} text ids scored by every judge "
          f"(manifest {len(man)}, pdf surface held out to the vision track "
          f"{len(pdf_ids)}, outside the judge matrix {len(outside)})")
    if outside:
        by_src = Counter(man[i].get("provenance", {}).get("source", "?")
                         for i in outside)
        print("  outside: " + ", ".join(f"{k}={v}" for k, v in by_src.most_common()))

    # ---- payload-grouped 50/50 split, stratified by (task-class, source) ----
    groups = {i: group_of(man[i]) for i in man}
    strata = defaultdict(set)
    for i in sorted(text_ids):
        e = man[i]
        tt = e["label"].get("threat_type", "benign")
        cls = "pi" if tt.startswith("prompt_injection") else ("phish" if tt in PHISH_POSITIVE_TYPES else "benign")
        src = e.get("provenance", {}).get("source", "?")
        strata[(cls, src)].add(groups[i])
    dev_g, test_g = set(), set()
    for k in sorted(strata):
        for j, g in enumerate(sorted(strata[k])):
            (dev_g if j % 2 == 0 else test_g).add(g)
    both = dev_g & test_g  # a group whose strata straddle classes would collide; forbid
    assert not both, f"groups in both halves: {list(both)[:5]}"
    dev_ids = {i for i in text_ids if groups[i] in dev_g}
    test_ids = {i for i in text_ids if groups[i] in test_g}
    print(f"grouped split: {len(dev_ids)} dev / {len(test_ids)} test "
          f"({len(dev_g)} / {len(test_g)} payload groups)")

    all_scores = {**judge_scores, **base_scores}
    out = {"population": {"text_ids": len(text_ids), "dev": len(dev_ids), "test": len(test_ids)},
           "tasks": {}}

    for task, label_fn, key in (("pi", pi_label, "pi"), ("phishing", phish_label, "phish")):
        y_by_id = {i: label_fn(man[i]) for i in text_ids}
        task_test = [i for i in sorted(test_ids) if y_by_id[i] is not None]
        task_dev = [i for i in sorted(dev_ids) if y_by_id[i] is not None]
        task_full = [i for i in sorted(text_ids) if y_by_id[i] is not None]
        rows = {}
        print(f"\n===== task={task}: test n={len(task_test)} "
              f"(pos={sum(y_by_id[i] for i in task_test)}) =====")
        hdr = f"{'detector':<18}{'AUC':>7}{'CI':>16}{'TPR@1%':>8}{'CI':>16}{'R@.35':>7}{'FPR@.35':>8}"
        print(hdr)
        for name, sc in all_scores.items():
            s_by_id = {i: sc[i][key] for i in task_full}
            m = point_metrics([y_by_id[i] for i in task_test], [s_by_id[i] for i in task_test], THRESH)
            m.update(cluster_bootstrap(task_test, groups, y_by_id, s_by_id, THRESH))
            m["full_corpus"] = point_metrics(
                [y_by_id[i] for i in task_full], [s_by_id[i] for i in task_full], THRESH)
            if name.startswith("judge:"):
                # dev-tuned threshold at FPR<=1% (frozen prompt), read once on test
                yd = np.asarray([y_by_id[i] for i in task_dev])
                sd = np.asarray([s_by_id[i] for i in task_dev])
                best_t, best_r = 1.0, -1.0
                for t in sorted(set(sd.tolist())):
                    pred = sd >= t
                    if pred[yd == 0].mean() <= 0.01 and pred[yd == 1].mean() > best_r:
                        best_r, best_t = pred[yd == 1].mean(), t
                yt = np.asarray([y_by_id[i] for i in task_test])
                st = np.asarray([s_by_id[i] for i in task_test])
                pred = st >= best_t
                m["dev_tuned"] = {"threshold": float(best_t),
                                  "recall": float(pred[yt == 1].mean()),
                                  "fpr": float(pred[yt == 0].mean())}
            rows[name] = m
            ci = m["auc_ci"]
            tci = m["tpr_at_1pct_fpr_ci"]
            print(f"{name:<18}{m['auc']:>7.3f} [{ci[0]:.3f},{ci[1]:.3f}] "
                  f"{m['tpr_at_1pct_fpr']:>7.3f} [{tci[0]:.3f},{tci[1]:.3f}] "
                  f"{m['recall_at_t']:>6.3f}{m['fpr_at_t']:>8.3f}")
        out["tasks"][task] = rows

    # ---- DMARC / sender-auth stratification (PI task, full text population) ----
    print("\n===== sender-auth stratification (PI task, full text population) =====")
    print("NOTE: PI positives are auth-balanced BY CONSTRUCTION (1/3 each); only")
    print("conditional detection quality and the two-tier policy are meaningful.")
    y_by_id = {i: pi_label(man[i]) for i in text_ids}
    task_ids = [i for i in sorted(text_ids) if y_by_id[i] is not None]
    auth = {i: man[i].get("sender_auth_condition", "?") for i in task_ids}
    dmarc = {}
    for name in ("judge:flash-lite", "deberta-v3", "piguard", "scamguard"):
        if name not in all_scores:
            print(f"{name}: predictions missing, skipped")
            continue
        sc = all_scores[name]
        s_by_id = {i: sc[i]["pi"] for i in task_ids}
        per = {}
        for cond in ("verified", "spoofed", "unauthenticated"):
            ids = [i for i in task_ids if auth[i] == cond]
            per[cond] = point_metrics([y_by_id[i] for i in ids], [s_by_id[i] for i in ids], THRESH)
        # two-tier policy: sweep (t_verified, t_other) on the grouped DEV half only
        # (maximize dev recall s.t. dev overall FPR <= 1%), then read once on TEST.
        # The single-threshold comparator is dev-tuned the same way.
        def arrs(ids):
            return (np.asarray([y_by_id[i] for i in ids]),
                    np.asarray([s_by_id[i] for i in ids]),
                    np.asarray([auth[i] == "verified" for i in ids]))
        dev_task = [i for i in sorted(dev_ids) if y_by_id.get(i) is not None]
        test_task = [i for i in sorted(test_ids) if y_by_id.get(i) is not None]
        yd, sd, vd = arrs(dev_task)
        yt, st, vt = arrs(test_task)
        cand = lambda s: sorted(set(np.round(s, 3).tolist()))[::4] + [1.1]
        best = {"dev_recall": -1.0}
        for tv in cand(sd[vd]):
            for tn in cand(sd[~vd]):
                pred = np.where(vd, sd >= tv, sd >= tn)
                if pred[yd == 0].mean() <= 0.01:
                    r = pred[yd == 1].mean()
                    if r > best["dev_recall"]:
                        best = {"dev_recall": float(r), "t_verified": float(tv), "t_other": float(tn)}
        pred = np.where(vt, st >= best["t_verified"], st >= best["t_other"])
        best["test_recall"] = float(pred[yt == 1].mean())
        best["test_fpr"] = float(pred[yt == 0].mean())
        # dev-tuned single threshold at the same budget, read on test
        best_t1, best_r1 = 1.1, -1.0
        for t in cand(sd):
            pred1 = sd >= t
            if pred1[yd == 0].mean() <= 0.01 and pred1[yd == 1].mean() > best_r1:
                best_r1, best_t1 = pred1[yd == 1].mean(), t
        pred1 = st >= best_t1
        single = {"threshold": float(best_t1), "test_recall": float(pred1[yt == 1].mean()),
                  "test_fpr": float(pred1[yt == 0].mean())}
        dmarc[name] = {"per_condition": per, "two_tier": best, "single_tier": single}
        print(f"\n{name}: dev-tuned@1%FPR on TEST: single {single['test_recall']:.3f} "
              f"(FPR {single['test_fpr']:.3f})  two-tier {best['test_recall']:.3f} "
              f"(FPR {best['test_fpr']:.3f}, t_v={best['t_verified']}, t_o={best['t_other']})")
        for cond, m in per.items():
            print(f"  {cond:<16} n={m['n']:<5} AUC={m['auc']:.3f}  R@.35={m['recall_at_t']:.3f}  FPR@.35={m['fpr_at_t']:.3f}")

    # ---- view ablation: canonical segment view vs naive text/plain-first parse ----
    # (same harness, same population; the only change is PIGUARD_SEGMENTS pointing
    # at segments-naive.jsonl. Judge naive scores from llm-judge/results/matrix-naive.)
    NAIVE = {
        "deberta-v3": "runs/offline-naive/hf_deberta_v3_base_prompt_injection_v2.jsonl",
        "injecguard": "runs/offline-naive/hf_InjecGuard.jsonl",
        "llama-pg2": "runs/offline-naive/hf_Llama_Prompt_Guard_2_86M.jsonl",
        "distilbert": "runs/offline-naive/hf_distilbert_prompt_injection.jsonl",
        "judge:flash-lite": "llm-judge/results/matrix-naive/gemini_3_1_flash_lite_N1.jsonl",
    }
    ablation = {}
    y_by_id = {i: pi_label(man[i]) for i in text_ids}
    task_ids = [i for i in sorted(text_ids) if y_by_id[i] is not None]
    print("\n===== view ablation (PI task, full text population) =====")
    for name, path in NAIVE.items():
        if not os.path.exists(path):
            print(f"{name}: naive run missing, skipped")
            continue
        naive_sc = load_scores(path, judge=name.startswith("judge:"))
        if any(i not in naive_sc for i in task_ids):
            print(f"{name}: naive run incomplete, skipped")
            continue
        key = "pi"
        pair = {}
        for cond, sc in (("canonical", all_scores[name]), ("naive", naive_sc)):
            y = [y_by_id[i] for i in task_ids]
            s = [sc[i][key] for i in task_ids]
            pair[cond] = point_metrics(y, s, THRESH)
        ablation[name] = pair
        print(f"{name:<18} canonical AUC={pair['canonical']['auc']:.3f} "
              f"TPR@1%={pair['canonical']['tpr_at_1pct_fpr']:.3f}   "
              f"naive AUC={pair['naive']['auc']:.3f} "
              f"TPR@1%={pair['naive']['tpr_at_1pct_fpr']:.3f}")
    out["view_ablation"] = ablation

    os.makedirs("results/tier1-analysis", exist_ok=True)
    t1_path = "results/tier1-analysis/table1_aligned.json"
    dm_path = "results/tier1-analysis/dmarc_stratified.json"

    # A run without the OSS/commercial per-message predictions can only recompute
    # the judge rows. Committed reference files carry every detector's row, so a
    # plain overwrite would silently delete the rows this run could not compute —
    # gutting the very file the README calls "the JSON behind Table 1". Carry the
    # missing rows forward instead, but ONLY when the previous file was written
    # for the same population; otherwise its numbers describe a different corpus.
    prev = _read_json(t1_path)
    same_pop = bool(prev) and prev.get("population") == out["population"]
    if prev and not same_pop:
        print(f"\nNOTE: {t1_path} was written for a different population "
              f"({prev.get('population')} != {out['population']}); its rows are "
              "NOT carried forward — rerun the missing detectors to refill them.")
    if same_pop:
        carried = []
        for task, rows in (prev.get("tasks") or {}).items():
            for det, row in rows.items():
                if det not in out["tasks"].setdefault(task, {}):
                    out["tasks"][task][det] = row
                    carried.append(f"{task}/{det}")
        for det, row in (prev.get("view_ablation") or {}).items():
            if det not in out["view_ablation"]:
                out["view_ablation"][det] = row
                carried.append(f"view_ablation/{det}")
        prev_dm = _read_json(dm_path)
        for det, row in (prev_dm or {}).items():
            if det not in dmarc:
                dmarc[det] = row
                carried.append(f"dmarc/{det}")
        if carried:
            print(f"\ncarried forward {len(carried)} row(s) from the previous "
                  "file (same population, predictions not regenerated here):")
            print("  " + ", ".join(sorted(carried)))

    with open(t1_path, "w") as f:
        json.dump(out, f, indent=1)
    with open(dm_path, "w") as f:
        json.dump(dmarc, f, indent=1)
    print("\nwrote results/tier1-analysis/{table1_aligned,dmarc_stratified}.json")


if __name__ == "__main__":
    main()
