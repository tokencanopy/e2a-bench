#!/usr/bin/env bash
# Fetch the Phase-1 phishing/ham corpora into dataset/phishing/.
# Reproducible: re-running is idempotent (skips existing downloads).
#
# Sources & licenses (see ATTRIBUTION.md):
#   - SpamAssassin public corpus  — freely redistributable (Apache project)
#   - Nazario phishing corpus      — CC-BY-4.0 (attribution required)
#
# Raw archives land in _raw/ (gitignored); individual .eml are extracted into
# ham/ and real/. NOTE: real phishing emails contain real (often dead) malicious
# URLs and, in later Nazario mailboxes, un-anonymized addresses (PII). Do NOT
# resolve the URLs; defang + scrub before any PUBLIC release.
set -euo pipefail
cd "$(dirname "$0")/.."   # operate in dataset/phishing/ (scripts live in scripts/)
mkdir -p _raw ham/spamassassin_easy ham/spamassassin_hard real/spamassassin_spam real/nazario

SA="https://spamassassin.apache.org/old/publiccorpus"
NZ="https://monkey.org/~jose/phishing"

dl() { local url="$1" out="$2"; [ -f "$out" ] || curl -fsSL "$url" -o "$out"; }

echo "[1/3] SpamAssassin tarballs..."
dl "$SA/20030228_easy_ham.tar.bz2" _raw/sa_easy_ham.tar.bz2
dl "$SA/20030228_hard_ham.tar.bz2" _raw/sa_hard_ham.tar.bz2
dl "$SA/20030228_spam.tar.bz2"     _raw/sa_spam.tar.bz2
dl "$SA/20050311_spam_2.tar.bz2"   _raw/sa_spam_2.tar.bz2

echo "[2/3] Extracting SpamAssassin..."
tar xjf _raw/sa_easy_ham.tar.bz2 -C _raw && cp -n _raw/easy_ham/*   ham/spamassassin_easy/ 2>/dev/null || true
tar xjf _raw/sa_hard_ham.tar.bz2 -C _raw && cp -n _raw/hard_ham/*   ham/spamassassin_hard/ 2>/dev/null || true
tar xjf _raw/sa_spam.tar.bz2     -C _raw && cp -n _raw/spam/*       real/spamassassin_spam/ 2>/dev/null || true
tar xjf _raw/sa_spam_2.tar.bz2   -C _raw && cp -n _raw/spam_2/*     real/spamassassin_spam/ 2>/dev/null || true

echo "[3/3] Nazario phishing mbox -> individual .eml..."
# Older 2005-era mailboxes (.mbox) + recent yearly mailboxes 2020-2023 (no extension) —
# same CC-BY-4.0 source. The recent years give MODERN phishing (real DKIM/SendGrid headers,
# current brands) so the corpus isn't stuck in 2002-2008.
NZ_FILES="phishing0.mbox phishing1.mbox phishing2.mbox phishing3.mbox 20051114.mbox phishing-2020 phishing-2021 phishing-2022 phishing-2023"
for m in $NZ_FILES; do
  dl "$NZ/$m" "_raw/nz_$m"
done
python3 - <<'PY'
import os, re, hashlib, glob
out = "real/nazario"; n = 0
for path in sorted(glob.glob("_raw/nz_*")):
    base = os.path.basename(path).replace("nz_", "").replace(".mbox", "")
    data = open(path, "rb").read()
    # mbox: split on the envelope-from line at byte level (no email parsing => no encoding errors);
    # each remaining chunk is one raw RFC822 message.
    for i, chunk in enumerate(re.split(rb'(?m)^From .*\r?\n', data)):
        if not chunk.strip():
            continue
        h = hashlib.sha1(chunk).hexdigest()[:12]
        with open(f"{out}/{base}_{i:04d}_{h}.eml", "wb") as f:
            f.write(chunk)
        n += 1
print(f"  wrote {n} Nazario .eml (2005-era + 2020-2023)")
PY

echo "Done. Counts:"
for d in ham/spamassassin_easy ham/spamassassin_hard real/spamassassin_spam real/nazario; do
  echo "  $d: $(find "$d" -type f ! -name .gitkeep | wc -l | tr -d ' ') files"
done
