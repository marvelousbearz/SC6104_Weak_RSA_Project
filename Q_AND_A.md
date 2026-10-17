# Likely questions and concise answers

## Why does a 2048-bit modulus not save the vulnerable keys?

Neither attack factors a normal 2048-bit modulus. The shared-prime attack finds
a common factor with gcd. Wiener uses the relationship between e, d, and phi(N)
when d is too small.

## Does shared-prime reuse occur outside a classroom?

It can occur when devices have insufficient entropy during key generation or
when an implementation mishandles randomness. Our project does not claim that
it is common in any named product; it demonstrates the mathematical impact.

## What is the Wiener vulnerability condition?

The classical sufficient condition is approximately d < N^(1/4) / 3. It is not
an if-and-only-if rule, so the experiment treats it as a vulnerable range.

## Why choose e = 65537 for normal RSA?

It is a conventional public exponent: large enough to avoid simple small-e
mistakes and efficient enough for encryption and signature verification.

## What should developers do?

Use established libraries, seed from a CSPRNG, avoid custom RSA parameter
selection, and test key-generation pipelines for repeated factors.

