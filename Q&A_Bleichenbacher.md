# Q&A.md
Anticipated questions, grouped by topic, with answers that go deeper
than the slides. Use this to prep, not to read aloud.

---

## Algorithm mechanics

**Q: Why does step 2a start searching at `s₁ = ⌈n/(3B)⌉`, not 1 or 2?**
A: Because for any `s < n/(3B)`, the product `m₀·s` (where `m₀ < 3B`)
can never reach `n`, so it can never wrap around via the mod operation.
Without wraparound, `m₀·s mod n = m₀·s`, and for any `s ≥ 2` that value
is always `> 3B` — provably unable to land back in the conforming range
`[2B, 3B)`. So every `s` below this threshold is guaranteed to fail
(aside from the trivial `s=1` case already resolved by blinding).
`⌈n/(3B)⌉` is the smallest `s` where wraparound — and therefore
success — first becomes mathematically possible. This is a *tight,
provable* lower bound, not a heuristic.

**Q: Why is 2c's search formula so much more complex than 2a/2b?**
A: It's the same oracle condition (`2B ≤ m₀·s − rn < 3B`), just solved
differently depending on how wide the current interval is. When the
interval is wide (2a/2b), the valid-`s` windows for consecutive `r`
overlap almost completely, so there's no gap worth skipping — plain
increment is already near-optimal. When the interval is narrow (2c,
after several rounds of narrowing), the windows become narrow and
widely spaced, with large dead zones between them that a linear scan
would waste huge numbers of oracle calls probing. 2c explicitly
computes, for each `r`, the exact bounds `s_lower = ⌈(2B+rn)/b⌉` and
`s_upper = ⌊(3B−1+rn)/a⌋`, and only tests `s` inside that window —
skipping everything that's provably dead.

**Q: Is there a proof for the factor of 2 in step 2c's starting
condition (`rᵢ ≥ 2(b·sᵢ₋₁ − 2B)/n`)?**
A: No — checked directly against Bleichenbacher's original 1998 paper,
and it states this as part of the algorithm's definition without
deriving why the constant is 2. The *provably necessary* minimum
(to guarantee the new search doesn't retest anything already covered)
is actually `r > (b·sᵢ₋₁ − 2B)/n` — no factor of 2 required. The
paper's `2×` appears to be a conservative safety margin chosen by the
original author, not a tightly derived necessary bound. Worth noting
explicitly if asked, rather than presenting it as something with a
known derivation.

**Q: How do you derive which `r` values are valid in step 3?**
A: Fix the `s` you just confirmed conforming. The oracle condition
`2B ≤ m₀·s − rn < 3B` rearranges to bound `r` directly:
`(m₀·s − 3B + 1)/n ≤ r ≤ (m₀·s − 2B)/n`. Since the exact `m₀` is
unknown (only `m₀ ∈ [a,b]`), take the union over the extremes:
substitute `m₀ = a` for the lower bound and `m₀ = b` for the upper
bound, giving `r_lower = ⌈(a·s − 3B + 1)/n⌉` and
`r_upper = ⌊(b·s − 2B)/n⌋`. This is the same inequality step 2c
solves — just isolating `r` instead of `s`.

---

## Correctness and edge cases

**Q: Can the interval set ever become empty?**
A: Not if the implementation is correct. Step 3 ranges over *every*
`r` consistent with the previous interval, and the true `m₀` satisfies
the oracle's constraint by construction — so it's guaranteed to land in
one of the intersected windows every round. If intervals do go empty
in practice, that's a sign of a bug (an off-by-one in `r_lower`/
`r_upper`, or a mismatch between the assumed `B` and the oracle's
actual padding-check definition), not a legitimate outcome.

**Q: Does the blinding factor need to be invertible?**
A: Yes — recovering `m = m₀·s₀⁻¹ mod n` at the end requires
`gcd(s₀, n) = 1`. For a random `s₀` and `n = p·q` with large primes,
the failure probability is about `1/p + 1/q`, negligible at real RSA
key sizes. Worth an explicit `gcd` check only if testing against a
small/toy modulus.

**Q: Why does step 1 (blinding) sometimes take 1 call and sometimes
hundreds of thousands?**
A: If the target ciphertext already decrypts to a PKCS-conforming
block (as happens when the project's test harness encrypts a message
through the standard PKCS#1 v1.5 helper), `s₀ = 1` succeeds
immediately. If the target is an arbitrary/raw ciphertext with no such
guarantee, blinding becomes a full search with the same ~2⁻¹⁶
per-trial success probability as step 2a — that's exactly why the
raw-ciphertext and OAEP-ciphertext experiments show much higher oracle
call counts than the native PKCS#1 v1.5 target.

---

## Scope and other schemes

**Q: Can this attack crack an OAEP-encrypted ciphertext?**
A: Only under a specific condition: a PKCS#1 v1.5-checking oracle must
exist *for the same key pair* that produced the OAEP ciphertext. The
attack has no awareness of encoding scheme — it just recovers
`c^d mod n`. If that condition holds, the attack succeeds but recovers
the raw OAEP-encoded block `EM`, not the final message; a separate
OAEP-decode step (MGF1 unmasking, `lHash` check) is required
afterward. If no PKCS#1 v1.5 oracle exists for that key at all, this
attack has nothing to query against — Manger's attack (which targets
OAEP-specific error distinctions) would be the relevant alternative,
and it is algorithmically different, not a variant of this code.

**Q: Why does the recovered OAEP block look like random noise?**
A: That's by design, not a bug. OAEP masks its internal structure via
MGF1 (a hash-based mask generation function) specifically so the
encoded block is indistinguishable from random bytes except for a
single leading `0x00`. Successfully recovering that noise-looking
block means the attack worked correctly — decoding it into the actual
message is a separate, final step.

**Q: Is "padding after encryption" a realistic scenario, and can this
attack solve it?**
A: For RSA specifically, no — padding must happen *before* encryption
by mathematical necessity; there's no post-ciphertext structure to
attack. But the general *pattern* — checking structural validity only
after decrypting — is extremely common historically in symmetric/CBC-
mode cryptography (PKCS#5/7 padding), and a structurally analogous
chosen-ciphertext attack (Vaudenay's, mechanically different from
Bleichenbacher's since the underlying primitive differs) does solve
it. This is exactly why encrypt-then-MAC / authenticated encryption is
recommended over pad-then-encrypt: authentication failure short-
circuits before the padding check is ever reachable.

---

## Performance and optimization

**Q: Why can't a CSPRNG speed up step 2a?**
A: Each trial `s` is an independent Bernoulli trial with a fixed
success probability (~2⁻¹⁶, from the probability that two random
leading bytes happen to equal `0x00 0x02`). That probability is a
property of the padding scheme's math, not of the order candidates are
tried in. Random vs. sequential sampling doesn't change the expected
number of trials needed — both have the same expected value for a
geometric distribution. Randomization only matters if the oracle
itself behaves non-randomly for structured/sequential input (e.g.
caching or rate-limiting side channels), which doesn't apply to a
local, stateless test oracle.

**Q: What actually sped up this implementation?**
A: Three independent levers, in order of impact for this project:
1. **Fixing correctness bugs** (an infinite loop in step 2c, and a
   `gmpy2.mpz` vs. Python `int` type mismatch that silently broke the
   oracle check entirely) — necessary before any speed optimization
   mattered.
2. **`gmpy2.powmod`** instead of Python's built-in `pow()` for modular
   exponentiation — meaningfully faster for RSA-sized integers.
3. **Multiprocessing** across the oracle-check step (not just
   candidate generation) — real parallelism across CPU cores, needed
   because this is a CPU-bound workload where Python threads don't
   reliably help due to the GIL.

**Q: What about the Bardou et al. trimming optimization?**
A: It specifically targets step 2a's cost (via "trimming `M₀`" and
"hole-skipping," using small-fraction multiplier relationships to
prove large ranges of `s` can't work) and extends to running step 2c-
style searches in parallel across multiple surviving intervals
(replacing step 2b). It does **not** reduce the fundamental ~2⁻¹⁶
per-trial probability floor — no reordering of candidates changes
that. The paper's own benchmark reports roughly a 4.4x reduction in
total oracle calls when combining these techniques on a 1024-bit
target. Not implemented in the current version of this project; noted
as a documented, citable next step rather than attempted under time
constraints.

---

## Big-picture

**Q: What's the real takeaway — is RSA insecure?**
A: No. The attack never breaks RSA's underlying hardness assumption —
it exploits a side channel in how a specific protocol handles
decryption errors. The fix (OAEP, or any construction where decryption
failure reveals nothing about *why* it failed) removes the attack's
only foothold without changing RSA itself. The broader lesson — never
let error handling leak information about *why* something failed —
generalizes well beyond RSA.
