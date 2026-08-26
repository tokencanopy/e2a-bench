"""Near-duplicate detection for .eml corpora.

Campaign blasts repeat heavily (Nazario phishing is ~38% dupes), so dedup BEFORE
sampling — otherwise near-dupes leak across splits and inflate detection metrics.

Signature = sha1(normalize(subject) + '|' + normalize(body)[:400]); normalize
lowercases and strips non-alphanumerics, so minor whitespace/markup differences
collapse to the same key. For tighter campaign-level matching (token-varied
"personalized" blasts), swap in MinHash/SimHash — this exact-normalized key is
the fast v1.

Usage:
  python3 dedup.py                 # report over the standard corpus dirs
  python3 dedup.py DIR [DIR ...]   # report over the given dirs
"""
import os, re, sys, glob, hashlib, collections
from parse_eml import parse_eml


def norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())


def signature(rec):
    return hashlib.sha1(
        (norm(rec["subject"]) + "|" + norm(rec["text"] or rec["html"])[:400]).encode()
    ).hexdigest()


def dedup(recs):
    """Return (unique_recs, clusters) where clusters is a Counter keyed by signature."""
    seen, clusters, out = set(), collections.Counter(), []
    for r in recs:
        k = signature(r)
        clusters[k] += 1
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out, clusters


def _load(dirs):
    recs = []
    for d in dirs:
        for f in glob.glob(d + "/*"):
            if f.endswith(".gitkeep"):
                continue
            try:
                r = parse_eml(f)
            except Exception:
                continue
            r["_path"] = f
            recs.append(r)
    return recs


def report(dirs):
    recs = _load(dirs)
    uniq, clusters = dedup(recs)
    drop = len(recs) - len(uniq)
    print(f"parsed {len(recs)} -> {len(uniq)} unique  ({drop} dups, {100*drop/max(len(recs),1):.0f}%)")
    bysig = {}
    for r in recs:
        bysig.setdefault(signature(r), r)
    for k, c in clusters.most_common(5):
        if c > 1:
            print(f"  x{c:4d}  {bysig[k]['subject'][:66]!r}")
    return uniq


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    dirs = sys.argv[1:] or [
        "ham/spamassassin_easy", "ham/spamassassin_hard",
        "real/nazario", "real/spamassassin_spam",
    ]
    report(dirs)
