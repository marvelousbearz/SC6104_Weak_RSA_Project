# PRESENTATION_SCRIPT.md
Short speaking notes for a slow speaker. Pause briefly between sections.

---

## Slide 1 — What Is the Bleichenbacher Attack?

The Bleichenbacher attack was published in 1998. It targets how a server handles RSA PKCS#1 v1.5 padding, not RSA mathematics itself.

RSA has a useful property: multiplying a ciphertext by \(s^e\) changes the decrypted message to \(m \cdot s \bmod n\).

A padding oracle tells the attacker whether the result has valid padding. By repeating this process, the attacker narrows down the possible plaintext without learning the private key.

---

## Slide 2 — The Algorithm

The attack has four main steps.

**First, blinding:** find a multiplier that produces a ciphertext accepted by the oracle.

**Second, searching:** find more multipliers that produce valid padding. The algorithm uses different search strategies depending on how many candidate intervals remain.

**Third, narrowing:** use each valid response to reduce the possible plaintext range.

**Finally, recovery:** once one candidate remains, reverse the initial blinding step to recover the original message.

---

## Slide 3 — Why It Works

A valid oracle response means the transformed plaintext lies within a known numeric range:

```text
2B ≤ m₀ · s mod n < 3B
```

Each response gives us a new constraint.

The algorithm intersects these constraints with the candidate intervals from previous rounds. If the implementation is correct, the true plaintext remains in the candidate set.

Eventually, the candidates can narrow to one value. We then undo the blinding step to recover the original message.

---

## Slide 4 — Experimental Results

These results come from separate runs. The timings can vary significantly, so they describe this implementation rather than every possible attack.

**First valid padding response:** For 1024-bit RSA, the average was **23.2 seconds and 61,423 oracle calls**. For 2048-bit RSA, it was **144.5 seconds and 41,914 calls**.

**Full recovery:** For 1024-bit RSA, the average was **188.7 seconds and 307,869 calls**. One trial took much longer than the others, affecting the average.

For 2048-bit RSA, the average was **138.1 seconds and 28,021 calls**. The single 4096-bit trial took **about 29.9 minutes** and used **61,505 calls**.

In a separate cross-scheme experiment, the PKCS#1 v1.5, raw RSA, and OAEP cases reported recovery. These were single trials, so the results need further testing.

For OAEP, we must distinguish recovering the RSA encoded message from decoding it to the original plaintext.

---

## Slide 5 — Beyond PKCS#1 v1.5

The attack uses RSA's multiplication property, but it still needs a useful padding oracle.

Raw RSA has no padding and is not secure for general encryption. A shared PKCS#1 v1.5 oracle may help recover a raw RSA message.

OAEP is designed to resist this type of attack. However, reusing the same RSA key with a vulnerable PKCS#1 v1.5 oracle can create a cross-scheme risk.

This does not mean OAEP was directly broken. Manger's attack is a different attack that relies on different oracle leakage.

The lesson is to use separate keys for different schemes and avoid leaking decryption errors.

---

## Slide 6 — Takeaway

RSA itself was not broken. The problem was the information leaked by the server.

Use RSA-OAEP correctly, keep keys separate across schemes, and make decryption failures as indistinguishable as possible.

The same principle applies to other cryptographic systems: error messages and timing should not reveal secret information.

---

## Slide 7 — Contribution

Our server generates RSA keys, creates ciphertexts, and provides the oracle interface.

The oracle checks whether padding is valid. The attack sends modified ciphertexts and tracks responses.

My implementation covers blinding, multiplier searching, interval narrowing, and final plaintext recovery.

Only mention the components you personally implemented.
