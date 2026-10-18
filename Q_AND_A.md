# Likely questions and concise answers

## Why does a 2048-bit modulus not save the vulnerable keys?

Neither attack factors a normal 2048-bit modulus. The common-modulus attack uses
two ciphertexts and Bézout coefficients. Wiener uses the relationship between e, d, and phi(N)
when d is too small.

## Does common-modulus reuse occur outside a classroom?

It can occur when an implementation generates one modulus and incorrectly uses
it for multiple RSA key pairs or recipients. Our project does not claim that it
is common in any named product; it demonstrates the mathematical impact.

## What is the Wiener vulnerability condition?

The classical sufficient condition is approximately d < N^(1/4) / 3. It is not
an if-and-only-if rule, so the experiment treats it as a vulnerable range.

## Why choose e = 65537 for normal RSA?

It is a conventional public exponent: large enough to avoid simple small-e
mistakes and efficient enough for encryption and signature verification.

## What should developers do?

Use established libraries, generate an independent modulus for every RSA key
pair, avoid custom RSA parameter selection, and test key-generation pipelines.

