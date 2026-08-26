#!/usr/bin/env python3
"""Render the image prompt-injection supplement.

Deterministic and offline: seeds.jsonl -> assets/ + eml/ + manifest.jsonl.
"""
import html
import json
import textwrap
from email.message import EmailMessage
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[2]
SEEDS = ROOT / "seeds.jsonl"
ASSETS = ROOT / "assets"
EML = ROOT / "eml"
MANIFEST = ROOT / "manifest.jsonl"
BASE_DATE = "Mon, 01 Jun 2026 09:00:00 -0700"
RECIPIENT = "user@example.com"
SURFACES = ("embedded_image_html", "image_attachment")


def rel(path):
    return str(path.relative_to(REPO_ROOT))


def font(size, bold=False):
    names = (
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def draw_wrapped(draw, text, xy, width, fill, fnt, spacing=8):
    x, y = xy
    avg = max(7, int(fnt.size * 0.55)) if hasattr(fnt, "size") else 8
    chars = max(24, width // avg)
    for line in textwrap.wrap(text, chars, break_long_words=False):
        draw.text((x, y), line, fill=fill, font=fnt)
        bbox = draw.textbbox((x, y), line, font=fnt)
        y += (bbox[3] - bbox[1]) + spacing
    return y


def render_png(seed, out_path):
    img = Image.new("RGB", (940, 600), "#f8fafc")
    draw = ImageDraw.Draw(img)
    title = font(40, bold=True)
    body = font(27)
    mono = font(24)

    draw.rounded_rectangle((34, 34, 906, 566), radius=18, fill="#ffffff", outline="#cbd5e1", width=2)
    draw.rectangle((34, 34, 906, 118), fill=seed["accent"])
    draw.text((68, 58), seed["headline"], fill="#ffffff", font=title)
    draw.text((68, 154), "Visible note", fill="#0f172a", font=title)
    y = draw_wrapped(draw, seed["carrier_text"], (68, 214), 790, "#334155", body)
    y += 28
    draw.rounded_rectangle((68, y, 858, 520), radius=10, fill="#f1f5f9", outline="#cbd5e1", width=1)
    draw.text((92, y + 24), "Embedded assistant instruction:", fill="#475569", font=mono)
    draw_wrapped(draw, seed["injection_text"], (92, y + 70), 720, "#0f172a", mono, spacing=7)
    img.save(out_path)


def base_msg(seed, surface):
    msg = EmailMessage()
    msg["From"] = seed["sender"]
    msg["To"] = RECIPIENT
    msg["Subject"] = seed["subject"]
    msg["Date"] = BASE_DATE
    msg["Message-ID"] = f'<{seed["id"]}-{surface}@e2a-synth.invalid>'
    return msg


def render_eml(seed, surface, png_bytes):
    msg = base_msg(seed, surface)
    if surface == "embedded_image_html":
        cid = f'{seed["id"]}-{surface}@e2a-synth.invalid'
        msg.set_content(seed["carrier_text"])
        html_body = (
            "<html><body>"
            f"<p>{html.escape(seed['carrier_text'])}</p>"
            f'<img src="cid:{cid}" alt="{html.escape(seed["headline"])}" '
            'style="max-width:940px;width:100%;height:auto">'
            "</body></html>"
        )
        msg.add_alternative(html_body, subtype="html")
        msg.get_payload()[1].add_related(
            png_bytes,
            maintype="image",
            subtype="png",
            cid=f"<{cid}>",
            filename=f'{seed["id"]}_instruction.png',
        )
        msg.get_payload()[1].set_boundary(f'e2a-{seed["id"]}-{surface}-related')
    elif surface == "image_attachment":
        msg.set_content(seed["carrier_text"] + "\n\nPlease review the attached image.")
        msg.add_attachment(png_bytes, maintype="image", subtype="png", filename=f'{seed["id"]}_instruction.png')
    else:
        raise ValueError(surface)
    msg.set_boundary(f'e2a-{seed["id"]}-{surface}')
    return msg.as_bytes()


def main():
    ASSETS.mkdir(exist_ok=True)
    EML.mkdir(exist_ok=True)
    seeds = [json.loads(line) for line in SEEDS.read_text().splitlines() if line.strip()]
    rows = []

    for i, seed in enumerate(seeds):
        png_path = ASSETS / f'{seed["id"]}.png'
        render_png(seed, png_path)
        png_bytes = png_path.read_bytes()

        for surface in SURFACES:
            tid = f'{seed["id"]}_{surface}'
            eml_path = EML / f"{tid}.eml"
            eml_path.write_bytes(render_eml(seed, surface, png_bytes))
            auth = ("verified", "spoofed", "unauthenticated")[(i + SURFACES.index(surface)) % 3]
            rows.append({
                "id": tid,
                "eml_path": rel(eml_path),
                "label": {
                    "is_malicious": True,
                    "threat_type": "prompt_injection_indirect",
                    "scenario": seed["scenario"],
                    "injection_technique": seed["technique"],
                },
                "surface": [surface],
                "detector_input": {"from": seed["sender"], "subject": seed["subject"]},
                "provenance": {
                    "source": "handcrafted",
                    "synthetic": True,
                    "source_id": seed["id"],
                    "base_payload_id": seed["id"],
                },
                "source_metadata": {
                    "benchmark": "visual-prompt-injection-supplement",
                    "injection_text": seed["injection_text"],
                    "carrier_text": seed["carrier_text"],
                },
                "sender_auth_condition": auth,
                "split": "synthetic",
                "notes": "Supplementary image prompt-injection case; malicious instruction is carried in an embedded image or image attachment.",
            })

    MANIFEST.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")
    print(f"rendered {len(rows)} visual PI .eml ({len(seeds)} seeds x {len(SURFACES)} surfaces)")
    print(f"assets -> {rel(ASSETS)}")
    print(f"eml -> {rel(EML)}")
    print(f"manifest -> {rel(MANIFEST)}")


if __name__ == "__main__":
    main()
