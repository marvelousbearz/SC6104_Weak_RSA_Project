"""Wiener's continued-fraction attack on deliberately small RSA exponents."""

from math import gcd, isqrt
from typing import Iterator, Optional, Tuple

from .rsa_utils import PrivateKey, PublicKey, generate_prime, mod_inverse


def continued_fraction(numerator: int, denominator: int) -> Iterator[int]:
    while denominator:
        quotient, remainder = divmod(numerator, denominator)
        yield quotient
        numerator, denominator = denominator, remainder


def convergents(terms: Iterator[int]) -> Iterator[Tuple[int, int]]:
    h_minus2, h_minus1 = 0, 1
    k_minus2, k_minus1 = 1, 0
    for term in terms:
        h = term * h_minus1 + h_minus2
        k = term * k_minus1 + k_minus2
        yield h, k
        h_minus2, h_minus1 = h_minus1, h
        k_minus2, k_minus1 = k_minus1, k


def _square_roots_for_phi(n: int, phi: int) -> Optional[Tuple[int, int]]:
    # p + q = n - phi + 1, so p and q solve x^2 - (p+q)x + n = 0.
    total = n - phi + 1
    discriminant = total * total - 4 * n
    if discriminant < 0:
        return None
    root = isqrt(discriminant)
    if root * root != discriminant or (total + root) % 2:
        return None
    p, q = (total + root) // 2, (total - root) // 2
    return (p, q) if p * q == n else None


def wiener_attack(public_key: PublicKey) -> Optional[PrivateKey]:
    """Recover the key if its private exponent lies in Wiener's vulnerable range."""
    for k, d in convergents(continued_fraction(public_key.e, public_key.n)):
        if k == 0 or (public_key.e * d - 1) % k:
            continue
        phi = (public_key.e * d - 1) // k
        roots = _square_roots_for_phi(public_key.n, phi)
        if roots is not None:
            p, q = roots
            return PrivateKey(public_key.n, d, p, q)
    return None


def generate_wiener_vulnerable_key(bits: int = 2048) -> Tuple[PublicKey, PrivateKey]:
    """Generate a local RSA key satisfying the classical small-d condition."""
    half = bits // 2
    while True:
        p, q = generate_prime(half), generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # Choose an odd d well below n^(1/4) / 3.
        bound = isqrt(isqrt(n)) // 4
        for d in range(3, min(bound, 100_003), 2):
            if gcd(d, phi) == 1:
                e = mod_inverse(d, phi)
                return PublicKey(n, e), PrivateKey(n, d, p, q)


def generate_wiener_key_at_ratio(
    ratio: float, bits: int = 512
) -> Tuple[PublicKey, PrivateKey, float]:
    """Generate a local RSA key with d close to ratio * N^(1/4).

    The function deliberately permits ratios above Wiener's classical
    sufficient bound so experiments can measure where recovery stops working.
    """
    if ratio <= 0:
        raise ValueError("ratio must be positive")
    half = bits // 2
    while True:
        p, q = generate_prime(half), generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        fourth_root = isqrt(isqrt(n))
        target = max(3, int(ratio * fourth_root)) | 1
        # Search nearby odd values so d remains invertible modulo phi(N).
        for offset in range(0, 10_000, 2):
            for candidate in (target + offset, target - offset):
                if 1 < candidate < phi and candidate % 2 and gcd(candidate, phi) == 1:
                    e = mod_inverse(candidate, phi)
                    return PublicKey(n, e), PrivateKey(n, candidate, p, q), candidate / fourth_root

