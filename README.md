# Breaking Weak RSA Keys at Realistic Sizes

This course project demonstrates two ways a large RSA modulus can fail when
key generation or parameter selection is wrong:

1. **Shared-prime attack**: a faulty RNG reuses one prime across two keys.
2. **Wiener's attack**: the private exponent `d` is chosen too small.

The project generates every key locally and attacks only these controlled
examples. It is educational code, not production cryptography.

## Quick start

```bash
cd SC6104_Weak_RSA_Project
python3 -m unittest discover -s tests -v
python3 -m src.demo --bits 2048
python3 -m experiments.run_experiments
```

`src.demo` runs the live demonstration. It creates vulnerable keys, derives a
private key using only public keys, and decrypts a test message.

## Deliverables

- `src/`: RSA primitives and both attacks.
- `tests/`: automated correctness tests.
- `experiments/`: reproducible timing study and chart generator.
- `results/`: generated CSV and PNG figures.
- `slides/Weak_RSA_Project_Seafoam_Academic.pptx`: eight-minute presentation.
- `PRESENTATION_SCRIPT.md`: speaker notes and demo cue.
- `Q_AND_A.md`: concise answers for likely questions.

## Ethics

Run this only on keys and systems that you own or are explicitly authorized to
test. The repository contains no scanning, network, or external-key features.

