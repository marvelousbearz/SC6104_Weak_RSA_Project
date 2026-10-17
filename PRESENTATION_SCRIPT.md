# 8-minute presentation script

## Slide 1 - Title (0:00-0:25)

Our question is simple: can a 2048-bit RSA key still fail even when nobody can
factor a normal 2048-bit modulus? Yes, if key generation reuses a prime or if
the private exponent is dangerously small.

## Slide 2 - Threat model (0:25-1:10)

The attacker receives public keys only. We generate all test keys locally. The
attacker never brute-forces a normal RSA modulus. Instead, the attacker finds a
mistake in how the key was generated.

## Slide 3 - Shared-prime attack (1:10-2:15)

If two moduli are N1 = p*q1 and N2 = p*q2, their greatest common divisor is p.
Once p is known, phi(N) and then d follow immediately.

## Slide 4 - Shared-prime demo (2:15-3:05)

Run `python3 -m src.demo --bits 2048`. Point out that the program knows only
the public key collection during the attack. The recovered private key decrypts
the demonstration message.

## Slide 5 - Wiener attack (3:05-4:15)

RSA requires e*d = 1 mod phi(N). When d is very small, k/d becomes a convergent
of e/N. Continued fractions expose candidate values for d. We verify each
candidate by reconstructing p and q.

## Slide 6 - Wiener demo (4:15-5:00)

The same command creates a deliberately small-d 2048-bit key. The attack
recovers d and decrypts a second message.

## Slide 7 - Experiments (5:00-6:25)

The graph shows the measured time for the controlled tests. The batch GCD scan
grows with the number of public keys. Wiener recovery remains quick because it
uses arithmetic structure rather than factoring N.

## Slide 8 - Defenses and conclusion (6:25-8:00)

Use a reviewed cryptographic library and the operating system CSPRNG. Do not
choose d manually. Validate generated key material. Large key size protects
against generic factoring, but it does not repair faulty randomness or unsafe
parameters.

