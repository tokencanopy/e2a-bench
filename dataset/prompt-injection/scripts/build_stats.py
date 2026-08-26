#!/usr/bin/env python3
"""Generate prompt-injection/STATS.md from the current JSONL artifacts."""
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = ROOT.parent
REPO_ROOT = DATASET_ROOT.parent
OUT = ROOT / "STATS.md"


def load_jsonl(path):
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


def count_values(rows, getter):
    return collections.Counter(getter(row) for row in rows)


def count_surfaces(rows):
    return collections.Counter(
        surface for row in rows for surface in row.get("surface", [])
    )


def table(counter, total=None, label="Value"):
    lines = [f"| {label} | Count |" + (" Share |" if total else "")]
    lines.append("|---|---:|" + ("---:|" if total else ""))
    for key, count in counter.most_common():
        share = f" {100 * count / total:.1f}% |" if total else ""
        lines.append(f"| {key} | {count} |{share}")
    return "\n".join(lines)


def source_name(source):
    return {
        "injecagent": "InjecAgent",
        "llmail-inject": "LLMail-Inject",
        "agentdojo": "AgentDojo",
        "canonical": "Canonical handcrafted",
        "handcrafted": "Handcrafted",
        "synthetic": "Synthetic",
        "ham_corpus": "SpamAssassin ham",
        "notinject": "NotInject",
        "phishing_corpus": "Phishing corpus (non-PI negative)",
        "JailbreakBench/artifacts": "JailbreakBench real GCG",
        "MatanBT/gcg-evaluated-data": "HF real GCG",
    }.get(source, source)


def named_counter(counter):
    return collections.Counter(
        {source_name(key): value for key, value in counter.items()}
    )


def main():
    payloads = load_jsonl(ROOT / "payloads.jsonl")
    main_rows = load_jsonl(ROOT / "manifest.jsonl")
    adaptive = load_jsonl(ROOT / "adaptive-supplement/manifest.jsonl")
    gcg = load_jsonl(ROOT / "gcg-supplement/manifest.jsonl")
    real_gcg = load_jsonl(ROOT / "gcg-supplement/real/manifest.jsonl")
    hf_gcg = load_jsonl(ROOT / "gcg-supplement/hf-gcg/manifest.jsonl")
    visual = load_jsonl(ROOT / "visual-supplement/manifest.jsonl")
    benign = load_jsonl(ROOT / "benign/manifest.jsonl")
    notinject = load_jsonl(DATASET_ROOT / "notinject/manifest.jsonl")
    combined = load_jsonl(REPO_ROOT / "eval/combined_manifest.jsonl")
    agentdojo_bases = load_jsonl(ROOT / "agentdojo_email_scenarios.jsonl")

    payload_sources = named_counter(
        count_values(payloads, lambda row: row["source"])
    )
    main_sources = named_counter(
        count_values(main_rows, lambda row: row["provenance"]["source"])
    )
    threat_types = count_values(
        main_rows, lambda row: row["label"]["threat_type"]
    )
    techniques = count_values(
        main_rows, lambda row: row["label"].get("injection_technique", "none")
    )
    scenarios = count_values(
        main_rows, lambda row: row["label"].get("scenario", "unknown")
    )
    main_surfaces = count_surfaces(main_rows)
    main_auth = count_values(
        main_rows, lambda row: row["sender_auth_condition"]
    )
    benign_categories = count_values(
        benign, lambda row: row["label"].get("scenario", "unknown")
    )
    benign_surfaces = count_surfaces(benign)
    adaptive_scenarios = count_values(
        adaptive, lambda row: row["label"].get("scenario", "unknown")
    )
    adaptive_variants = count_values(
        adaptive, lambda row: row.get("source_metadata", {}).get("variant", "unknown")
    )
    all_gcg = gcg + real_gcg + hf_gcg
    gcg_classes = collections.Counter(
        "positive" if row["label"]["is_malicious"] else "negative"
        for row in all_gcg
    )
    gcg_surfaces = count_surfaces(all_gcg)
    real_gcg_models = count_values(
        real_gcg,
        lambda row: row.get("provenance", {}).get("source_model", "unknown"),
    )
    hf_gcg_models = count_values(
        hf_gcg,
        lambda row: row.get("provenance", {}).get("source_model", "unknown"),
    )
    visual_surfaces = count_surfaces(visual)
    combined_classes = collections.Counter(
        "positive" if row["label"]["is_malicious"] else "negative"
        for row in combined
    )
    combined_sources = named_counter(
        count_values(combined, lambda row: row["provenance"]["source"])
    )

    agentdojo_payloads = [
        row for row in payloads if row["source"] == "agentdojo"
    ]
    agentdojo_formulations = count_values(
        agentdojo_payloads, lambda row: row["technique"]
    )
    agentdojo_emails = [
        row
        for row in main_rows
        if row["provenance"]["source"] == "agentdojo"
    ]

    main_positive = sum(
        row["label"]["is_malicious"] for row in main_rows
    )
    direct = threat_types["prompt_injection_direct"]
    indirect = threat_types["prompt_injection_indirect"]
    standalone_pi_files = (
        len(main_rows)
        + len(adaptive)
        + len(gcg)
        + len(real_gcg)
        + len(hf_gcg)
        + len(visual)
        + len(benign)
    )

    text = f"""# Prompt-injection dataset - live stats

> Auto-generated by `scripts/build_stats.py`. Do not edit by hand; re-run the
> script after rebuilding any prompt-injection manifest.
>
> **Counting rule:** a payload is malicious instruction content before email
> packaging. One main payload is rendered into eight `.eml` instances. Rendered
> variants are controlled test instances, not independent tasks.

## Dataset map

| Component | Role | Base items | Rendered `.eml` | Included in default combined eval |
|---|---|---:|---:|---|
| Main prompt-injection benchmark | malicious positives | {len(payloads)} payloads | {len(main_rows)} | yes |
| Adaptive complex supplement | malicious positives | {len(set(row["provenance"]["base_payload_id"] for row in adaptive))} scenarios | {len(adaptive)} | yes |
| GCG-style suffix supplement | mixed positives + hard negatives | {len(set(row["provenance"]["base_payload_id"] for row in gcg))} seeds | {len(gcg)} | yes |
| Real GCG challenge supplement | malicious positives | {len(set(row["provenance"]["base_payload_id"] for row in real_gcg))} seeds | {len(real_gcg)} | yes |
| HF real GCG supplement | malicious positives | {len(hf_gcg)} evaluated rows | {len(hf_gcg)} | yes |
| Visual supplement | malicious positives | {len(set(row["provenance"]["base_payload_id"] for row in visual))} scenarios | {len(visual)} | no |
| Structurally matched benign controls | benign negatives | {len(set(row["provenance"]["base_payload_id"] for row in benign))} seeds | {len(benign)} | yes |
| NotInject controls | benign negatives | {len(notinject)} source texts | {len(notinject)} | yes |

The prompt-injection directory currently contains **{standalone_pi_files} `.eml`
files** across the main set and its local supplements. The default combined
evaluation additionally imports phishing-family email controls.

## Main benchmark (`manifest.jsonl` + `eml/`)

**{len(main_rows)} malicious records** = {direct} direct + {indirect} indirect.
They come from **{len(payloads)} payload rows x 8 structural surfaces**.

### Payload sources (before structural rendering, n={len(payloads)})
{table(payload_sources, len(payloads), "Source")}

### Rendered instances by source (n={len(main_rows)})
{table(main_sources, len(main_rows), "Source")}

The difference between these two tables is the structural multiplier: each
payload becomes eight `.eml` files.

### Threat type
{table(threat_types, len(main_rows), "Threat type")}

AgentDojo content is always labeled indirect because the instruction is carried
by untrusted external email data. For other sources, quoted-thread and PDF
placements are indirect; body, HTML, header, and encoded placements are direct.

### Structural surface coverage
{table(main_surfaces, None, "Surface")}

Surface counts can exceed record counts because multipart records can carry
more than one surface label.

### Injection technique
{table(techniques, len(main_rows), "Technique")}

`raw` includes source-native InjecAgent and LLMail wording. The six AgentDojo
formulations are recorded separately. Canonical handcrafted templates cover
additional simple phrasing families.

### Goal/scenario tag
{table(scenarios, len(main_rows), "Scenario")}

### Sender authentication condition
{table(main_auth, len(main_rows), "Condition")}

Authentication is assigned for controlled slicing; it is not parsed from the
`.eml` and is never used as the ground-truth label.

## AgentDojo expansion

**{len(agentdojo_bases)} base email scenarios x
{len(agentdojo_formulations)} attack formulations x 8 surfaces =
{len(agentdojo_emails)} rendered AgentDojo `.eml` files.**

{table(agentdojo_formulations, len(agentdojo_payloads), "Attack formulation")}

These are {len(agentdojo_emails)} rendered instances, not
{len(agentdojo_emails)} independent AgentDojo tasks. Group train/test splits by
`provenance.base_scenario_id`.

## Adaptive complex supplement

**{len(adaptive)} records** from
{len(set(row["provenance"]["base_payload_id"] for row in adaptive))} hand-authored
multi-stage scenarios. All are `prompt_injection_indirect`, `difficulty=hard`,
and `split=adaptive`.

### Complex scenario
{table(adaptive_scenarios, len(adaptive), "Scenario")}

### Combined MIME variant
{table(adaptive_variants, len(adaptive), "Variant")}

This supplement tests conditional execution, delayed triggers, data-dependent
tool chains, authority laundering, covert side effects, and instruction
reassembly across multiple email locations. Report it separately from
AgentDojo and public-source payloads.

## GCG-style suffix supplement

**{len(gcg)} synthetic records** from
{len(set(row["provenance"]["base_payload_id"] for row in gcg))} hand-authored
seeds. This slice targets adversarial suffix attacks where natural email text is
followed by high-entropy punctuation/noise resembling GCG optimizer output. It
also includes benign hard negatives with technical-looking tails.

The default combined evaluation also includes **{len(real_gcg)} real GCG
challenge records** from JailbreakBench/artifacts and **{len(hf_gcg)} real GCG
evaluated rows** from MatanBT/gcg-evaluated-data filtered to
`strongreject_finetuned >= 0.5`. These are malicious positives and are
intentionally reported with the synthetic suffix slice so real optimized
suffixes cannot be hidden from default metrics.

### GCG supplement class, synthetic + real challenge
{table(gcg_classes, len(all_gcg), "Class")}

### Real GCG source model
{table(real_gcg_models, len(real_gcg), "Source model")}

### HF real GCG source model
{table(hf_gcg_models, len(hf_gcg), "Source model")}

### GCG surface coverage, synthetic + real challenge
{table(gcg_surfaces, None, "Surface")}

## Visual supplement

**{len(visual)} records** from
{len(set(row["provenance"]["base_payload_id"] for row in visual))} synthetic
scenarios. This slice requires image extraction or OCR and is excluded from the
default combined manifest.

{table(visual_surfaces, None, "Surface")}

## Structurally matched benign controls

**{len(benign)} benign records** =
{len(set(row["provenance"]["base_payload_id"] for row in benign))} content seeds
x 8 matched surfaces. These messages contain normal instructions, authorized
actions, security discussions, and benign uses of attack-like words.

### Benign content category
{table(benign_categories, len(benign), "Category")}

### Benign surface coverage
{table(benign_surfaces, None, "Surface")}

This set measures whether the detector mistakes complex MIME packaging or words
such as `SYSTEM`, `TODO`, `ignore`, and `send_email` for an attack.

## Default combined PI evaluation

`eval/combined_manifest.jsonl` currently contains **{len(combined)} records**:

{table(combined_classes, len(combined), "PI-eval class")}

### Combined source accounting
{table(combined_sources, len(combined), "Source")}

For this PI-specific evaluation, only `prompt_injection_direct` and
`prompt_injection_indirect` are positive. Phishing emails are intentionally
treated as non-PI controls, so the PI detector must distinguish prompt injection
from other malicious-email families rather than flagging every suspicious
message.

## Regenerate

```bash
cd dataset/prompt-injection
python3 scripts/build_stats.py
```

Rebuild the manifests before refreshing stats when source data changes:

```bash
python3 scripts/expand_agentdojo_attacks.py
python3 scripts/render_pi.py
python3 benign/render_benign.py
python3 adaptive-supplement/render_adaptive.py
python3 gcg-supplement/render_gcg.py
python3 gcg-supplement/real/render_real_gcg.py
python3 gcg-supplement/hf-gcg/render_hf_gcg.py
python3 ../../eval/combine_manifests.py --base-dir ../..
python3 scripts/build_stats.py
```
"""
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(REPO_ROOT)}")
    print(
        f"main={len(main_rows)} adaptive={len(adaptive)} gcg={len(gcg)} visual={len(visual)} "
        f"real_gcg={len(real_gcg)} hf_gcg={len(hf_gcg)} benign={len(benign)} "
        f"combined={len(combined)}"
    )


if __name__ == "__main__":
    main()
