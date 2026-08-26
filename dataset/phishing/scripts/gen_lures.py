#!/usr/bin/env python3
"""Stage A of synthetic generation: LLM-write phishing lures into lures.jsonl
(Stage B = render_surfaces.py renders these into .eml across the 8 surfaces).

Run ONCE to (re)generate/expand the committed lures.jsonl seed; rendering is then
deterministic and offline. Requires ANTHROPIC_API_KEY (`pip install anthropic`).

  python3 scripts/gen_lures.py --n 40 [--append]

Safety: URLs are REALISTIC (combosquat/typosquat/RFC-5737-IP/shortener) but stored
DEFANGED ('hxxp://', '[.]') and NEVER resolved; eval re-fangs in memory (parse_eml.refang)
so the detector sees a realistic string. Fully synthetic — no PII. Defensive benchmark only."""
import os, sys, json, argparse, itertools

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
MODEL = "claude-sonnet-4-6"   # current cost-effective model for bulk generation
LURES = "synthetic/lures.jsonl"

SCENARIOS = ["credential_account", "mfa", "doc_share", "delivery", "gift_card",
             "financial", "crypto", "invoice"]
BRANDS = ["Microsoft 365", "Google", "DocuSign", "Amazon", "FedEx", "PayPal",
          "Coinbase", "QuickBooks", "a regional bank", "Starbucks"]
TONES = ["urgency", "authority", "reward"]

SYSTEM = (
    "You generate SYNTHETIC phishing email lures for a DEFENSIVE detection benchmark. "
    "Output STRICT JSON only (no prose). Required keys: scenario, brand, tone, "
    "sender_name, sender_domain, subject, body_text, body_html, malicious_url. "
    "Hard rules: malicious_url and sender_domain MUST be REALISTIC phishing-style — a "
    "combosquat/typosquat (e.g. microsoft365-security[.]com), an IP-literal from RFC 5737 "
    "test ranges (e.g. 198[.]51[.]100[.]23), or a shortener (e.g. bit[.]ly/xxxx) — AND "
    "DEFANGED: scheme as 'hxxp://' or 'hxxps://' and EVERY dot as '[.]'. NEVER emit a "
    "fanged ('http://', real '.') or live URL. body_text and body_html MUST each contain "
    "the literal token {{URL}} exactly once (do NOT inline the url). Realistic but concise."
)


def gen_one(client, scenario, brand, tone):
    prompt = (f"Write one realistic phishing lure. scenario={scenario}, brand={brand}, "
              f"tone={tone}. Return JSON only.")
    msg = client.messages.create(
        model=MODEL, max_tokens=900, system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    text = text[text.find("{"): text.rfind("}") + 1]   # strip any stray fencing
    d = json.loads(text)
    # enforce safety invariants: realistic but defanged + never fanged/live
    mu = d.get("malicious_url", "")
    if "[.]" not in mu or not mu.startswith("hxxp"):
        raise ValueError(f"malicious_url not defanged-realistic: {mu!r}")
    if "http://" in mu or "https://" in mu:
        raise ValueError(f"malicious_url is fanged/live: {mu!r}")
    if "[.]" not in d.get("sender_domain", ""):
        raise ValueError(f"sender_domain not defanged: {d.get('sender_domain')!r}")
    assert "{{URL}}" in d["body_text"] and "{{URL}}" in d["body_html"], "missing {{URL}} token"
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40, help="number of lures to generate")
    ap.add_argument("--append", action="store_true", help="append to lures.jsonl instead of overwriting")
    args = ap.parse_args()
    try:
        import anthropic
    except ImportError:
        sys.exit("pip install anthropic; and set ANTHROPIC_API_KEY")
    if not os.getenv("ANTHROPIC_API_KEY"):
        sys.exit("set ANTHROPIC_API_KEY")
    client = anthropic.Anthropic()

    start = 0
    if args.append and os.path.exists(LURES):
        start = sum(1 for _ in open(LURES))
    combos = itertools.cycle(itertools.product(SCENARIOS, BRANDS, TONES))
    out, seen = [], set()
    for i in range(args.n):
        sc, br, to = next(combos)
        try:
            d = gen_one(client, sc, br, to)
        except Exception as e:
            print(f"  skip ({sc}/{br}): {e}", file=sys.stderr)
            continue
        d["id"] = f"lure_{start + len(out) + 1:04d}"
        key = (d["subject"], d["malicious_url"])
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
        print(f"  {d['id']}  {sc}/{br}/{to}")
    mode = "a" if args.append else "w"
    with open(LURES, mode) as f:
        for d in out:
            f.write(json.dumps(d) + "\n")
    print(f"wrote {len(out)} lures -> {LURES} (mode={mode}). Next: python3 scripts/render_surfaces.py")


if __name__ == "__main__":
    main()
