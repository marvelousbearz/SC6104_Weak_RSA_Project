# Breaking Weak RSA Keys at Realistic Sizes

This course project demonstrates two ways a large RSA modulus can fail when
key generation or parameter selection is wrong:

1. **Common-modulus attack**: two public keys `(N, e1)` and `(N, e2)` reuse one
   modulus `N`, use coprime exponents, and encrypt the same message.
2. **Wiener's attack**: the private exponent `d` is chosen too small.

The project generates every key locally and attacks only these controlled
examples. It is educational code, not production cryptography.

## Quick start

```bash
cd SC6104_Weak_RSA_Project
python3 -m unittest discover -s tests -v
python3 -m src.demo --bits 2048
python3 -m experiments.run_experiments
python3 -m experiments.run_advanced_experiments
```

`src.demo` runs the live demonstration. It creates controlled vulnerable keys,
recovers a test message from public parameters, and verifies the result.

## Deliverables

- `src/`: RSA primitives and both attacks.
- `tests/`: automated correctness tests.
- `experiments/`: reproducible timing study and chart generator.
- `results/`: generated CSV and PNG figures.
- `slides/Weak_RSA_Project_Seafoam_Academic_Timer.pptx`: eight-minute presentation with an 08:00 timer marker.
- `PRESENTATION_SCRIPT.md`: speaker notes and demo cue.
- `Q_AND_A.md`: concise answers for likely questions.

## Advanced experiments

`run_advanced_experiments` adds two extensions for the final presentation:

1. It compares a naive all-pairs scan against an index-by-`N` scan on locally
   generated public-key collections. Exactly one controlled pair reuses `N`.
2. It varies `d / N^(1/4)` across five trials per ratio and reports the
   success rate of Wiener's attack. The classic `1/3` condition is a
   sufficient-condition guide, not a sharp success/failure boundary.

## Ethics

Run this only on keys and systems that you own or are explicitly authorized to
test. The repository contains no scanning, network, or external-key features.

