"""Shared-prime RSA attack against a controlled public-key collection."""

from itertools import combinations
from math import gcd
from typing import Dict, Iterable, List, Tuple

from .rsa_utils import PrivateKey, PublicKey, generate_prime, private_from_factor


def generate_vulnerable_keyset(
    count: int, bits: int = 2048, e: int = 65537
) -> Tuple[List[PublicKey], Dict[int, PrivateKey], Tuple[int, int]]:
    """Return public keys where exactly two moduli share a prime.

    The returned private-key mapping exists only to verify the local experiment.
    """
    if count < 2:
        raise ValueError("need at least two public keys")
    half = bits // 2
    shared_p = generate_prime(half)
    public_keys: List[PublicKey] = []
    private_keys: Dict[int, PrivateKey] = {}

    for index in range(count):
        p = shared_p if index in (0, 1) else generate_prime(half)
        while True:
            q = generate_prime(bits - half)
            if q != p and gcd(e, (p - 1) * (q - 1)) == 1:
                break
        n = p * q
        key = private_from_factor(n, e, p)
        public_keys.append(PublicKey(n=n, e=e))
        private_keys[n] = key
    return public_keys, private_keys, (0, 1)


def find_shared_prime_pairs(keys: Iterable[PublicKey]) -> List[Tuple[int, int, int]]:
    """Return (first index, second index, shared factor) for vulnerable pairs."""
    key_list = list(keys)
    findings = []
    for i, j in combinations(range(len(key_list)), 2):
        factor = gcd(key_list[i].n, key_list[j].n)
        if 1 < factor < key_list[i].n:
            findings.append((i, j, factor))
    return findings


def recover_shared_prime_private_keys(
    keys: Iterable[PublicKey], findings: Iterable[Tuple[int, int, int]]
) -> Dict[int, PrivateKey]:
    key_list = list(keys)
    recovered: Dict[int, PrivateKey] = {}
    for i, j, factor in findings:
        for index in (i, j):
            key = key_list[index]
            recovered[key.n] = private_from_factor(key.n, key.e, factor)
    return recovered

