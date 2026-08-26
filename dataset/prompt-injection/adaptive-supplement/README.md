# Adaptive complex prompt-injection supplement

This is a small hand-authored robustness slice that is intentionally more
complex than the adapted AgentDojo examples:

```text
6 base scenarios x 3 multi-surface variants = 18 .eml files
```

Complexity comes from behavior rather than length:

- conditional and data-dependent execution;
- multi-step search-then-send or verify-then-act chains;
- authority laundering through quoted third-party context;
- delayed triggers and attempted session persistence;
- preserving the benign user-visible answer while performing a side effect;
- instructions distributed across MIME alternatives, threads, and attachments.

Each base scenario has three variants:

1. `nested_thread_html` - stages are nested inside an HTML quoted thread;
2. `cross_mime_split` - the attack is split across plain text and fragmented
   HTML alternatives;
3. `pdf_body_chain` - the precondition is in the body and the action is in a
   PDF attachment.

These cases are synthetic and hand-authored. They are not AgentDojo cases and
must be reported separately as an adaptive robustness slice.

Regenerate:

```bash
python3 dataset/prompt-injection/adaptive-supplement/render_adaptive.py
```
