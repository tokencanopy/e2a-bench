# Visual prompt-injection supplement

This is a small supplementary benchmark for prompt injection carried by image
email surfaces. It is separate from the main LLMail/InjecAgent/AgentDojo build so
the paper can report it as an optional robustness slice.

The malicious content is still prompt injection, not phishing: the payload is an
instruction that tries to hijack the email agent. There is no malicious URL.

## Contents

- `seeds.jsonl` - 4 hand-authored synthetic prompt-injection scenarios.
- `scripts/render_visual_pi.py` - deterministic renderer; no API needed.
- `assets/` - generated PNG visual payloads.
- `eml/` - generated RFC822 emails.
- `manifest.jsonl` - one `EmailRecord` per `.eml`.

## Surfaces

Each seed is rendered into two variants:

1. `embedded_image_html` - the injected instruction is inside an image embedded
   in the HTML email body via CID.
2. `image_attachment` - the injected instruction is inside an attached PNG.

All records are labeled `prompt_injection_indirect`: the instruction is
untrusted email content that the agent may ingest as data, not a user-authored
instruction.

## Regenerate

From the repo root:

```bash
python3 dataset/prompt-injection/visual-supplement/scripts/render_visual_pi.py
```
