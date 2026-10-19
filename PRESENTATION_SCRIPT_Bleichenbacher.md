# PRESENTATION_SCRIPT.md
Short speaking notes for a slow speaker. Pause briefly between sections.

---

## Slide 1 — What Is the Bleichenbacher Attack?

hello, I will be talking about the bleichenbacher attack. A padding-oracle attack that recovers RSA PKCS#1 v1.5 plaintext without ever learning the private key.
The attack uses the homographic properity of RSA, and the padding oracle can provide bounds of the plaintext.
Together, the plaintext can be cracked without private key. 

---

## Slide 2 — The Algorithm

The attack has four main steps.

**First, blinding:** find a multiplier that produces a ciphertext accepted by the oracle.

**Second, searching:** find more multipliers that produce valid padding.

**Third, narrowing:** use each valid response to reduce the possible plaintext range.

**Finally, recovery:** once one candidate remains, reverse the initial blinding step to recover the original message.

---

## Slide 3 — Why It Works

A valid oracle response implies the transformed plaintext lies within a known bound:

```text
2B ≤ m₀ · s mod n < 3B
```

Each response gives us a new constraint.

The algorithm intersects these constraints with the candidate intervals from previous rounds. If the implementation is correct, the true plaintext remains in the candidate set.

Eventually, the candidates can narrow to one value. We then undo the blinding step to recover the original message.

---

## Slide 4 — Experimental Results


The attack can crack 4096-bit RSA in feasible time.
The estimated first-hit time is 2^16, however oracle checking follows the geometric distribution thus can vary very much.
As the results, each iteration in the attack can reduce around 1 bit of entropy.

---

## Slide 5 — Beyond PKCS#1 v1.5

The server may not communicate in plain PKCS1.5, we can use blinding to convert the ciphertext.
As long as, the same public key is used. Different RSA schemes are still vunerable.

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
