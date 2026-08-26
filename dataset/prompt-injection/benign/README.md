# Prompt-injection benign controls

This directory contains structurally matched negative cases for the
prompt-injection detector:

```text
25 benign content seeds x 8 email surfaces = 200 benign .eml files
```

The messages include ordinary instructions, authorized workplace actions,
security discussions, quoted attack examples, and email-format test language.
Some contain words such as `ignore`, `SYSTEM`, `TODO`, `send_email`, or
`important`, but none instructs the receiving agent to perform an unauthorized
or unrelated action.

The same eight structural surfaces used by the malicious prompt-injection set
are represented. This allows false-positive rate to be compared by surface
instead of using only simple plaintext ham.

Regenerate deterministically:

```bash
cd dataset/prompt-injection
python3 benign/render_benign.py
```

The generated cases are loaded automatically by
`eval/combine_manifests.py`.
