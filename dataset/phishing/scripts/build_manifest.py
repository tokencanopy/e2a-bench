"""Build the Phase-1 phishing/benign benchmark: dedup -> categorize -> stratify ->
sample, extract URLs/surfaces, assign sender-auth, emit manifest.jsonl + corpus/.
Seeded -> reproducible. Run from anywhere: python3 scripts/build_manifest.py

Labels:
- threat_type preserves `benign`, Nazario `phishing`, and SpamAssassin `spam`.
  Both malicious types map to the benchmark's phishing-family positive role.
- `category` is the CONTENT type (keyword-derived, not source): credential / financial /
  advance_fee / lottery_prize / gift_card / delivery / other.
"""
import os, re, json, glob, random, hashlib, shutil, collections
from parse_eml import parse_eml
from dedup import signature as sig, dedup

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
random.seed(42)
BENIGN_TARGET, NAZ_TARGET, SA_TARGET = 1500, 1000, 500   # phishing = NAZ + SA (both malicious); tune here

SOURCES = {
    "ham":   [("ham/spamassassin_easy", "benign", "ham_easy"),
              ("ham/spamassassin_hard", "benign", "ham_hard")],
    "naz":   [("real/nazario", "phishing", "nazario")],          # credential phishing
    "sa":    [("real/spamassassin_spam", "spam", "sa_spam")],  # phishing-family positive
}
BRANDS = ["paypal", "ebay", "bank", "amazon", "irs", "apple", "microsoft", "fedex",
          "ups", "visa", "citibank", "wells fargo", "chase", "netflix", "wamu",
          "halifax", "barclays", "aol", "earthlink"]


def categorize(r):
    """Content-based lure/scam category (keyword heuristic over subject+body) — replaces
    the meaningless source-based phishing/scam split. Order matters (scam types first)."""
    s = (r["subject"] + " " + r["text"][:400]).lower()
    if any(k in s for k in ["lottery", "you have won", "you won", "winner", "prize", "award", "claim your", "congratulation"]):
        return "lottery_prize"
    if any(k in s for k in ["assistance", "next of kin", "beneficiary", "inheritance", "business proposal", "barrister", "widow", "consignment", "million usd", "million dollars"]):
        return "advance_fee"
    if any(k in s for k in ["verify", "account", "suspend", "login", "password", "confirm", "update your", "security", "safeharbor", "unusual sign"]):
        return "credential"
    if any(k in s for k in ["bank", "paypal", "ebay", "payment", "invoice", "wire", "billing", "credit card", "transaction"]):
        return "financial"
    if any(k in s for k in ["gift card", "gift", "reward", "voucher"]):
        return "gift_card"
    if any(k in s for k in ["package", "delivery", "shipment", "tracking", "parcel"]):
        return "delivery"
    return "other"


def surfaces(r):
    out = []
    if r["text"] and not r["has_html"]:
        out.append("plaintext_body")
    if r["has_html"]:
        out.append("html_body")
    if r["urls"]:
        out.append("hyperlink")
    if r["has_attachment"]:
        out.append("attachment")
    return out or ["plaintext_body"]


def assign_auth(threat):
    if threat == "benign":
        return random.choices(["verified", "unauthenticated"], [0.9, 0.1])[0]
    return random.choices(["spoofed", "unauthenticated", "verified"], [0.6, 0.25, 0.15])[0]


def load(dirs):
    recs = []
    for d, threat, src in dirs:
        for f in glob.glob(d + "/*"):
            if f.endswith(".gitkeep"):
                continue
            try:
                r = parse_eml(f)
            except Exception:
                continue
            r["_path"], r["_threat"], r["_src"] = f, threat, src
            recs.append(r)
    return recs


def stratified(recs, n):
    strata = collections.defaultdict(list)
    for r in recs:
        strata[(r["_src"], categorize(r), r["has_html"])].append(r)
    for v in strata.values():
        random.shuffle(v)
    out, keys = [], list(strata)
    while len(out) < n and any(strata[k] for k in keys):
        for k in keys:
            if strata[k] and len(out) < n:
                out.append(strata[k].pop())
    return out


print("=" * 64, "\n[DEDUP]\n", "=" * 64, sep="")
dd, RAW, UNIQ, raw_total, uniq_total = {}, {}, {}, 0, 0
for fam, dirs in SOURCES.items():
    recs = load(dirs)
    deduped, clusters = dedup(recs)
    dd[fam] = deduped
    RAW[fam], UNIQ[fam] = len(recs), len(deduped)
    raw_total += len(recs); uniq_total += len(deduped)
    drop = len(recs) - len(deduped)
    print(f"{fam:5s}: parsed {len(recs):5d} -> {len(deduped):5d} unique  ({drop} dropped as dup, {100*drop/max(len(recs),1):.0f}%)")
print(f"TOTAL : parsed {raw_total} -> {uniq_total} unique ({raw_total - uniq_total} dups removed, {100*(raw_total-uniq_total)/raw_total:.0f}%)")

mal = dd["naz"] + dd["sa"]   # all malicious (phishing), source-collapsed
print("=" * 64, "\n[OVERVIEW]  deduped malicious (phishing; Nazario + SA-spam collapsed)\n", "=" * 64, sep="")
print("category:", dict(collections.Counter(categorize(r) for r in mal).most_common()))
print(f"with html: {100*sum(r['has_html'] for r in mal)/len(mal):.0f}%  |  "
      f"with link: {100*sum(bool(r['urls']) for r in mal)/len(mal):.0f}%  |  "
      f"with attachment: {100*sum(r['has_attachment'] for r in mal)/len(mal):.0f}%")

benign = stratified(dd["ham"], BENIGN_TARGET)
phishing = stratified(dd["naz"], NAZ_TARGET) + stratified(dd["sa"], SA_TARGET)
chosen = benign + phishing

os.makedirs("corpus", exist_ok=True)
with open("manifest.jsonl", "w") as man:
    for i, r in enumerate(chosen):
        threat = r["_threat"]                      # benign | phishing | spam
        tid = f"{r['_src']}_{i:04d}"
        shutil.copy(r["_path"], f"corpus/{tid}.eml")
        rec = {
            "id": tid,
            "eml_path": f"dataset/phishing/corpus/{tid}.eml",
            "label": {
                "is_malicious": threat != "benign",
                "threat_type": threat,
                "category": categorize(r) if threat != "benign" else "none",
                "malicious_urls": list(dict.fromkeys(r["urls"]))[:10] if threat != "benign" else [],
            },
            "surface": surfaces(r),
            "detector_input": {
                "from": r["from"], "subject": r["subject"],
                "body": {"text": (r["text"][:5000] or None), "html": (r["html"][:5000] or None)},
            },
            "provenance": {
                "source": "ham_corpus" if threat == "benign" else "phishing_corpus",
                "synthetic": False,
                "source_id": os.path.basename(r["_path"]),
            },
            "sender_auth_condition": assign_auth(threat),
            "split": "test",
        }
        man.write(json.dumps(rec) + "\n")

print("=" * 64, "\n[FINAL SAMPLE -> manifest.jsonl + corpus/]\n", "=" * 64, sep="")
print(f"benign {len(benign)}  |  phishing {len(phishing)} (Nazario {NAZ_TARGET} + SA-spam {SA_TARGET})  |  TOTAL {len(chosen)}")
print(f"held-out (deduped, not sampled): {uniq_total - len(chosen)}")
print("category distribution [sampled malicious]:",
      dict(collections.Counter(categorize(r) for r in phishing).most_common()))
print("surface distribution:", dict(collections.Counter(s for r in chosen for s in surfaces(r)).most_common()))
print("sender_auth_condition (assigned):", dict(collections.Counter(
    json.loads(l)["sender_auth_condition"] for l in open("manifest.jsonl"))))


# --- live data card: regenerated every run so GitHub always shows current state ---
def _tbl(counter, total):
    return "\n".join(f"| {k} | {v} | {100*v/total:.1f}% |" for k, v in counter.most_common())

cat_sampled = collections.Counter(categorize(r) for r in phishing)
cat_natural = collections.Counter(categorize(r) for r in mal)
surf = collections.Counter(s for r in chosen for s in surfaces(r))
auth = collections.Counter(json.loads(l)["sender_auth_condition"] for l in open("manifest.jsonl"))

stats = f"""# Phishing dataset — live stats

> Auto-generated by `scripts/build_manifest.py` (seed=42). Do not edit by hand — re-run the script.
> Full corpus is gitignored; materialize with `scripts/fetch_corpora.sh`. See `README.md` / `ATTRIBUTION.md`.
>
> **Labels:** `threat_type` preserves `benign`, Nazario `phishing`, and
> SpamAssassin `spam`; both malicious types are phishing-family positives.
> `category` is the content type (keyword-derived).

## Dedup (raw .eml -> unique)
| Source | Parsed | Unique | Dups removed |
|---|---|---|---|
| ham (benign) | {RAW['ham']} | {UNIQ['ham']} | {RAW['ham']-UNIQ['ham']} ({100*(RAW['ham']-UNIQ['ham'])/RAW['ham']:.0f}%) |
| Nazario (phishing) | {RAW['naz']} | {UNIQ['naz']} | {RAW['naz']-UNIQ['naz']} ({100*(RAW['naz']-UNIQ['naz'])/RAW['naz']:.0f}%) |
| SA-spam (phishing) | {RAW['sa']} | {UNIQ['sa']} | {RAW['sa']-UNIQ['sa']} ({100*(RAW['sa']-UNIQ['sa'])/RAW['sa']:.0f}%) |
| **Total** | **{raw_total}** | **{uniq_total}** | **{raw_total-uniq_total} ({100*(raw_total-uniq_total)/raw_total:.0f}%)** |

## Final curated benchmark (`manifest.jsonl` + `corpus/`)
**{len(chosen)} records** = {len(benign)} benign + {len(phishing)} phishing-family
positive (Nazario phishing + SA-spam). Held-out (deduped, unsampled):
**{uniq_total-len(chosen)}**.

### Content category (sampled malicious, n={len(phishing)})
| Category | Count | Share |
|---|---|---|
{_tbl(cat_sampled, len(phishing))}

*(Stratified-balanced sampling — flatter than the natural prior below.)*

### Natural distribution (full deduped malicious pool, n={len(mal)})
| Category | Count | Share |
|---|---|---|
{_tbl(cat_natural, len(mal))}

### Surface coverage (sampled)
| Surface | Count |
|---|---|
""" + "\n".join(f"| {k} | {v} |" for k, v in surf.most_common()) + f"""

### sender_auth_condition (assigned, not parsed — see README)
| Condition | Count |
|---|---|
""" + "\n".join(f"| {k} | {v} |" for k, v in auth.most_common()) + "\n"

with open("STATS.md", "w") as f:
    f.write(stats)
print("\nwrote STATS.md (live data card)")
