"""Minimal RSA primitives for controlled classroom experiments only."""

from dataclasses import dataclass
from math import gcd
import secrets
from typing import Tuple


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: int
    q: int


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a: int, modulus: int) -> int:
    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % modulus


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("at least 16 bits required")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def private_from_factor(n: int, e: int, p: int) -> PrivateKey:
    if not 1 < p < n or n % p:
        raise ValueError("factor does not divide modulus")
    q = n // p
    phi = (p - 1) * (q - 1)
    return PrivateKey(n=n, d=mod_inverse(e, phi), p=p, q=q)


def generate_rsa_key(bits: int = 2048, e: int = 65537) -> Tuple[PublicKey, PrivateKey]:
    if bits < 64:
        raise ValueError("at least 64 bits required")
    left_bits = bits // 2
    right_bits = bits - left_bits
    while True:
        p, q = generate_prime(left_bits), generate_prime(right_bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            n = p * q
            return PublicKey(n, e), PrivateKey(n, mod_inverse(e, phi), p, q)


def encrypt_int(message: int, key: PublicKey) -> int:
    if not 0 <= message < key.n:
        raise ValueError("message must be between 0 and n - 1")
    return pow(message, key.e, key.n)


def decrypt_int(ciphertext: int, key: PrivateKey) -> int:
    return pow(ciphertext, key.d, key.n)


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


def int_to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

