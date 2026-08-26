#!/usr/bin/env python3
"""Convert Zenodo phishing CSV files to the e2a manifest format.

Supports Ling/Enron/SpamAssassin (3-col: subject, body, label) and
CEAS_08/Nazario_5 (7-col: sender, receiver, date, subject, body, label, urls)
formats.

CSV-sourced records have no RFC822 .eml file; eml_path is omitted and
detector_input is populated inline. schema.json allows this for external
corpus entries (provenance.source in {enron_zenodo, nazario5_zenodo, ling_zenodo}).

Evaluation notes:
  - ood_phishing_manifest.jsonl: phishing positives are Nazario_5 (same source
    as 1055 training examples, different samples). This is a same-source held-out
    split, NOT a true cross-dataset OOD eval. The 2401 Ling ham negatives ARE
    from a different corpus and constitute genuine OOD for the benign class.
  - ood_ling_manifest.jsonl: Ling commercial spam + Ling ham. Both sides OOD.

Usage:
    python3 dataset/ingest_zenodo.py fix-saspam
    python3 dataset/ingest_zenodo.py add-enron-ham /tmp/Enron.csv
    python3 dataset/ingest_zenodo.py ood-ling /tmp/Ling.csv
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
from pathlib import Path

csv.field_size_limit(10**7)

REPO_ROOT = Path(__file__).resolve().parent.parent
PHISHING_MANIFEST = REPO_ROOT / "dataset" / "phishing" / "manifest.jsonl"
OOD_MANIFEST = REPO_ROOT / "dataset" / "phishing" / "ood_ling_manifest.jsonl"


def _load_manifest(path: Path) -> list[dict]:
    entries = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _write_manifest(path: Path, entries: list[dict]) -> None:
    with path.open("w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    print(f"Wrote {len(entries)} entries → {path}")


def _detect_format(header: list[str]) -> str:
    if "sender" in header:
        return "rich"   # CEAS_08 / Nazario_5 style
    return "simple"     # Ling / Enron / SpamAssassin style


def _read_csv(path: str) -> tuple[str, list[dict]]:
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        fmt = _detect_format(header)
        rows = list(reader)
    return fmt, rows


def _content_hash(subject: str, body: str) -> str:
    """Reproducible 16-hex-char content fingerprint for split auditing.

    Formula: SHA256(subject + '\\x00' + body, utf-8 with errors=replace)[:16]
    The null-byte separator prevents subject/body boundary ambiguity.
    Used as provenance.source_id so train/OOD non-overlap can be verified
    externally by recomputing this hash from detector_input fields.
    """
    raw = f"{subject}\x00{body}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _make_entry(
    id_: str,
    subject: str,
    body: str,
    from_: str,
    label_int: int,
    threat_type: str,
    source: str,
) -> dict:
    return {
        "id": id_,
        "label": {
            "is_malicious": label_int == 1,
            "threat_type": threat_type,
            "category": "credential" if threat_type == "phishing" else threat_type,
            "malicious_urls": [],
        },
        "detector_input": {
            "from": from_,
            "subject": subject,
            "body": {"text": body, "html": None},
        },
        "provenance": {
            "source": source,
            "synthetic": False,
            "source_id": _content_hash(subject, body),
        },
    }


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_fix_saspam() -> None:
    """Re-label sa_spam entries from threat_type 'phishing' → 'spam'.

    SpamAssassin spam (bulk ads, advance-fee) was incorrectly labelled phishing.
    The training script's PHISHING_THREAT_TYPES set does not include 'spam', so
    re-labelled entries will be excluded from phishing training automatically.
    """
    entries = _load_manifest(PHISHING_MANIFEST)
    fixed = 0
    for e in entries:
        if e["id"].startswith("sa_spam") and e["label"]["threat_type"] == "phishing":
            e["label"]["threat_type"] = "spam"
            e["label"]["category"] = "spam"
            fixed += 1
    _write_manifest(PHISHING_MANIFEST, entries)
    print(f"Re-labelled {fixed} sa_spam entries: phishing → spam")


def cmd_add_enron_ham(csv_path: str, n: int = 1500, seed: int = 42) -> None:
    """Add n Enron business emails (label=0) to the phishing manifest as benign.

    These are real Enron corporate emails — much harder negatives than the
    SpamAssassin developer mailing lists already in the dataset.
    """
    fmt, rows = _read_csv(csv_path)
    ham_rows = [r for r in rows if r.get("label", "").strip() == "0"]
    print(f"Found {len(ham_rows)} Enron ham rows in {csv_path}")

    import random
    rng = random.Random(seed)
    sampled = rng.sample(ham_rows, min(n, len(ham_rows)))

    entries = _load_manifest(PHISHING_MANIFEST)
    existing_ids = {e["id"] for e in entries}

    added = 0
    for i, row in enumerate(sampled):
        id_ = f"enron_ham_{i:04d}"
        while id_ in existing_ids:
            i += 1
            id_ = f"enron_ham_{i:04d}"
        subject = (row.get("subject") or "").strip()
        body = (row.get("body") or "").strip()
        from_ = (row.get("sender") or "").strip()
        entry = _make_entry(id_, subject, body, from_, 0, "benign", "enron_zenodo")
        entries.append(entry)
        existing_ids.add(id_)
        added += 1

    _write_manifest(PHISHING_MANIFEST, entries)
    print(f"Added {added} Enron ham entries as benign")


def cmd_add_nazario5_phishing(csv_path: str, n: int = 500, seed: int = 42) -> None:
    """Add n Nazario_5 phishing emails (label=1) to the phishing manifest."""
    fmt, rows = _read_csv(csv_path)
    phish_rows = [r for r in rows if r.get("label", "").strip() == "1"]
    print(f"Found {len(phish_rows)} Nazario_5 phishing rows")

    import random
    rng = random.Random(seed)
    sampled = rng.sample(phish_rows, min(n, len(phish_rows)))

    entries = _load_manifest(PHISHING_MANIFEST)
    existing_ids = {e["id"] for e in entries}

    added = 0
    for i, row in enumerate(sampled):
        id_ = f"nazario5_phish_{i:04d}"
        while id_ in existing_ids:
            i += 1
            id_ = f"nazario5_phish_{i:04d}"
        subject = (row.get("subject") or "").strip()
        body = (row.get("body") or "").strip()
        from_ = (row.get("sender") or "").strip()
        # Skip mailbox artifacts (MAILER-DAEMON, empty body)
        if not subject and not body:
            continue
        if "FOLDER INTERNAL DATA" in body[:80]:
            continue
        entry = _make_entry(id_, subject, body, from_, 1, "phishing", "nazario5_zenodo")
        entries.append(entry)
        existing_ids.add(id_)
        added += 1

    _write_manifest(PHISHING_MANIFEST, entries)
    print(f"Added {added} Nazario_5 phishing entries")


def cmd_ood_ling(csv_path: str) -> None:
    """Create an OOD eval manifest from the Ling-Spam dataset.

    Ling-Spam is a completely separate corpus from the training data
    (Nazario / SpamAssassin / Enron). Using it as a held-out test set
    checks genuine distribution generalization.

    label=0 → benign, label=1 → spam (commercial unsolicited email, NOT phishing).
    Ling-Spam spam is used as a cross-fire / false-positive stress test for the
    phishing detector: the flag_rate on these entries should stay near zero.
    """
    _, rows = _read_csv(csv_path)

    entries = []
    for i, row in enumerate(rows):
        label_int = int(row.get("label", 0))
        threat_type = "spam" if label_int == 1 else "benign"
        subject = (row.get("subject") or "").strip()
        body = (row.get("body") or "").strip()
        entry = _make_entry(
            f"ling_ood_{i:04d}", subject, body, "", label_int, threat_type, "ling_zenodo"
        )
        entries.append(entry)

    _write_manifest(OOD_MANIFEST, entries)
    pos = sum(1 for e in entries if e["label"]["is_malicious"])
    neg = len(entries) - pos
    print(f"OOD eval: {pos} malicious, {neg} benign → {OOD_MANIFEST}")


CEAS_OOD_MANIFEST = REPO_ROOT / "dataset" / "phishing" / "ood_ceas_manifest.jsonl"


def cmd_add_ceas08(csv_path: str, n_phish: int = 3000, n_ham: int = 2000,
                   n_ood_phish: int = 500, n_ood_ham: int = 500, seed: int = 42) -> None:
    """Add CEAS_08 emails to phishing manifest and create OOD test manifest.

    CEAS_08 (Zenodo 8339691) is a diverse "spam" corpus including commercial spam,
    advance-fee fraud, malware delivery, and some credential phishing. Using it
    as additional training data substantially improves cross-corpus generalization
    beyond the Nazario bank-credential distribution.

    label=1 → malicious (phishing/spam/fraud), label=0 → benign

    Splits:
      - n_ood_phish + n_ood_ham are held out → ood_ceas_manifest.jsonl
      - n_phish + n_ham go to training manifest
      - content-fingerprinted to exclude any overlap with existing manifests
    """
    import random
    fmt, rows = _read_csv(csv_path)
    rng = random.Random(seed)

    phish_rows = [r for r in rows if r.get("label", "").strip() == "1"]
    ham_rows   = [r for r in rows if r.get("label", "").strip() == "0"]
    print(f"CEAS_08 raw: {len(phish_rows)} malicious, {len(ham_rows)} ham")

    # Load existing hashes to avoid overlap with any existing manifest
    existing_hashes: set[str] = set()
    for mf in [PHISHING_MANIFEST,
               REPO_ROOT / "dataset" / "phishing" / "ood_phishing_manifest.jsonl",
               REPO_ROOT / "dataset" / "phishing" / "ood_ling_manifest.jsonl"]:
        if mf.exists():
            for e in _load_manifest(mf):
                di = e.get("detector_input", {})
                s = (di.get("subject") or "").strip()
                b = ((di.get("body") or {}).get("text") or "").strip()
                existing_hashes.add(_content_hash(s, b))

    def dedupe(pool: list[dict], seen: set[str]) -> list[tuple[dict, str]]:
        out = []
        for r in pool:
            s = (r.get("subject") or "").strip()
            b = (r.get("body") or "").strip()
            if len(b) < 20:
                continue
            h = _content_hash(s, b)
            if h not in seen:
                seen.add(h)
                out.append((r, h))
        return out

    all_hashes: set[str] = set(existing_hashes)
    clean_phish = dedupe(phish_rows, all_hashes)
    clean_ham   = dedupe(ham_rows,   all_hashes)
    rng.shuffle(clean_phish)
    rng.shuffle(clean_ham)
    print(f"After dedup: {len(clean_phish)} malicious, {len(clean_ham)} ham available")

    ood_phish  = clean_phish[:n_ood_phish]
    ood_ham    = clean_ham[:n_ood_ham]
    train_phish = clean_phish[n_ood_phish:n_ood_phish + n_phish]
    train_ham   = clean_ham[n_ood_ham:n_ood_ham + n_ham]

    # Build OOD manifest
    ood_entries = []
    for i, (r, h) in enumerate(ood_phish):
        ood_entries.append(_make_entry(
            f"ceas_ood_phish_{i:04d}", (r.get("subject") or "").strip(),
            (r.get("body") or "").strip(), (r.get("sender") or "").strip(),
            1, "phishing", "ceas08_zenodo"))
    for i, (r, h) in enumerate(ood_ham):
        ood_entries.append(_make_entry(
            f"ceas_ood_ham_{i:04d}", (r.get("subject") or "").strip(),
            (r.get("body") or "").strip(), (r.get("sender") or "").strip(),
            0, "benign", "ceas08_zenodo"))
    _write_manifest(CEAS_OOD_MANIFEST, ood_entries)
    print(f"OOD CEAS: {len(ood_phish)} phishing, {len(ood_ham)} ham → {CEAS_OOD_MANIFEST}")

    # Add to training manifest
    existing = _load_manifest(PHISHING_MANIFEST)
    existing_ids = {e["id"] for e in existing}
    new_entries = []
    for i, (r, h) in enumerate(train_phish):
        new_entries.append(_make_entry(
            f"ceas_train_phish_{i:04d}", (r.get("subject") or "").strip(),
            (r.get("body") or "").strip(), (r.get("sender") or "").strip(),
            1, "phishing", "ceas08_zenodo"))
    for i, (r, h) in enumerate(train_ham):
        new_entries.append(_make_entry(
            f"ceas_train_ham_{i:04d}", (r.get("subject") or "").strip(),
            (r.get("body") or "").strip(), (r.get("sender") or "").strip(),
            0, "benign", "ceas08_zenodo"))
    _write_manifest(PHISHING_MANIFEST, existing + new_entries)
    print(f"Added {len(new_entries)} CEAS entries to training manifest")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0]
    if cmd == "fix-saspam":
        cmd_fix_saspam()
    elif cmd == "add-enron-ham":
        if len(args) < 2:
            sys.exit("Usage: ingest_zenodo.py add-enron-ham <Enron.csv>")
        n = int(args[2]) if len(args) > 2 else 1500
        cmd_add_enron_ham(args[1], n=n)
    elif cmd == "add-nazario5":
        if len(args) < 2:
            sys.exit("Usage: ingest_zenodo.py add-nazario5 <Nazario_5.csv>")
        n = int(args[2]) if len(args) > 2 else 500
        cmd_add_nazario5_phishing(args[1], n=n)
    elif cmd == "ood-ling":
        if len(args) < 2:
            sys.exit("Usage: ingest_zenodo.py ood-ling <Ling.csv>")
        cmd_ood_ling(args[1])
    elif cmd == "add-ceas08":
        if len(args) < 2:
            sys.exit("Usage: ingest_zenodo.py add-ceas08 <CEAS_08.csv>")
        cmd_add_ceas08(args[1])
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
