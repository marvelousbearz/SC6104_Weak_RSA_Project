# 8-minute presentation script

## Slide 1 - Title (0:00-0:25)

Our question is simple: can a 2048-bit RSA key still fail even when nobody can
factor a normal 2048-bit modulus? Yes, if an implementation reuses a modulus or if
the private exponent is dangerously small.

## Slide 2 - Threat model (0:25-1:10)

The attacker receives public keys only. We generate all test keys locally. The
attacker never brute-forces a normal RSA modulus. Instead, the attacker finds a
mistake in how the key was generated.

## Slide 3 - Common-modulus attack (1:10-2:15)

If the same message is encrypted with the same N under coprime exponents e1 and
e2, Extended Euclid finds a and b such that a*e1+b*e2=1. Therefore c1^a*c2^b
equals the original message modulo N. No factorisation is needed.

## Slide 4 - Common-modulus demo (2:15-3:05)

Run `python3 -m src.demo --bits 2048`. The program first creates four public
keys, then indexes them by N. Only one pair shares N and has coprime exponents.
It uses the two corresponding ciphertexts to recover the message without a
private key.

## Slide 5 - Wiener attack (3:05-4:15)

RSA requires e*d = 1 mod phi(N). When d is very small, k/d becomes a convergent
of e/N. Continued fractions expose candidate values for d. We verify each
candidate by reconstructing p and q.

## Slide 6 - Wiener demo (4:15-5:00)

The same command creates a deliberately small-d 2048-bit key. The attack
recovers d and decrypts a second message.

## Slide 7 - Experiments (5:00-6:25)

The graph compares naive all-pairs scanning with indexing the key collection by
N. The indexed method avoids comparisons between unrelated moduli. Common-
modulus recovery uses arithmetic structure rather than factoring N. Wiener recovery
remains quick because it
uses arithmetic structure rather than factoring N.

## Slide 8 - Defenses and conclusion (6:25-8:00)

Use a reviewed cryptographic library and the operating system CSPRNG. Do not
choose d manually. Validate generated key material. Large key size protects
against generic factoring, but it does not repair faulty randomness or unsafe
parameters.

