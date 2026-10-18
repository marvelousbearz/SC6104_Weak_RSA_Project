"""Shared-prime RSA attack against a controlled public-key collection."""

from itertools import combinations
from math import gcd
from typing import Dict, Iterable, List, Sequence, Tuple

from .rsa_utils import PrivateKey, PublicKey, generate_prime, private_from_factor


def generate_vulnerable_keyset(
    count: int, bits: int = 2048, e: int = 65537
) -> Tuple[List[PublicKey], Dict[int, PrivateKey], Tuple[int, int]]:
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


def _product_tree(values: Sequence[int]) -> List[List[int]]:
    """Build a balanced product tree for an RSA modulus collection."""
    if not values:
        return []
    levels = [list(values)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append([
            current[index] * current[index + 1]
            if index + 1 < len(current)
            else current[index]
            for index in range(0, len(current), 2)
        ])
    return levels


def batch_gcd_findings(keys: Iterable[PublicKey]) -> List[Tuple[int, int]]:
    """Find shared factors with a product tree and a remainder tree.

    At each leaf, P mod n_i^2 equals n_i times the product of all other
    moduli modulo n_i. Therefore gcd(n_i, (P mod n_i^2) / n_i) exposes a
    factor shared with at least one other key. This is an offline audit of a
    local key collection; it does not fetch or scan keys from any network.
    """
    key_list = list(keys)
    moduli = [key.n for key in key_list]
    if len(moduli) < 2:
        return []
    products = _product_tree(moduli)
    remainders: List[List[int]] = [[products[-1][0]]]

    for level_index in range(len(products) - 2, -1, -1):
        children = products[level_index]
        parent_remainders = remainders[0]
        current_remainders = []
        for parent_index, parent_remainder in enumerate(parent_remainders):
            left_index = parent_index * 2
            for child_index in (left_index, left_index + 1):
                if child_index < len(children):
                    child_product = children[child_index]
                    current_remainders.append(parent_remainder % (child_product * child_product))
        remainders.insert(0, current_remainders)

    findings = []
    for index, (modulus, remainder) in enumerate(zip(moduli, remainders[0])):
        factor = gcd(modulus, remainder // modulus)
        if 1 < factor < modulus:
            findings.append((index, factor))
    return findings


def recover_batch_gcd_private_keys(
    keys: Iterable[PublicKey], findings: Iterable[Tuple[int, int]]
) -> Dict[int, PrivateKey]:
    """Recover each locally vulnerable private key reported by batch GCD."""
    key_list = list(keys)
    return {
        key_list[index].n: private_from_factor(key_list[index].n, key_list[index].e, factor)
        for index, factor in findings
    }


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

