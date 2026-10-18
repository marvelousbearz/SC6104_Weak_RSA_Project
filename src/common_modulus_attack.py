"""Common-modulus RSA attack on locally generated teaching keys.

The attack applies when the *same* modulus n encrypts the same message under
two different public exponents e1 and e2 with gcd(e1, e2) = 1.
"""

from math import gcd
from itertools import combinations
from typing import Dict, Iterable, List, Sequence, Tuple

from .rsa_utils import PrivateKey, PublicKey, extended_gcd, generate_prime, generate_rsa_key, mod_inverse


def generate_common_modulus_keys(
    bits: int = 2048, e1: int = 65537, e2: int = 17
) -> Tuple[PublicKey, PublicKey, PrivateKey]:
    """Generate two public keys sharing n, solely for the controlled demo."""
    if bits < 64:
        raise ValueError("at least 64 bits required")
    if e1 <= 1 or e2 <= 1 or gcd(e1, e2) != 1:
        raise ValueError("public exponents must be greater than one and coprime")

    left_bits = bits // 2
    right_bits = bits - left_bits
    while True:
        p = generate_prime(left_bits)
        q = generate_prime(right_bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e1, phi) == 1 and gcd(e2, phi) == 1:
            n = p * q
            private_key = PrivateKey(n, mod_inverse(e1, phi), p, q)
            return PublicKey(n, e1), PublicKey(n, e2), private_key


def generate_common_modulus_keyset(
    count: int, bits: int = 2048, e1: int = 65537, e2: int = 17
) -> Tuple[List[PublicKey], Tuple[int, int]]:
    """Generate a collection where exactly two public keys reuse the same n.

    The first two entries have identical n and coprime exponents e1 and e2.
    Every later key has an independently generated modulus and acts as a
    non-vulnerable control. This mirrors an offline audit of a large key set.
    """
    if count < 2:
        raise ValueError("need at least two public keys")
    first_key, second_key, _ = generate_common_modulus_keys(bits, e1, e2)
    keys = [first_key, second_key]
    while len(keys) < count:
        key, _ = generate_rsa_key(bits=bits, e=e1)
        keys.append(key)
    return keys, (0, 1)


def find_common_modulus_pairs(keys: Iterable[PublicKey]) -> List[Tuple[int, int]]:
    """Locate pairs with the same n and coprime public exponents.

    Moduli are indexed in one pass, so independent moduli are never compared
    with one another. Only a repeated-n group needs exponent-pair checks.
    """
    groups: Dict[int, List[Tuple[int, PublicKey]]] = {}
    for index, key in enumerate(keys):
        groups.setdefault(key.n, []).append((index, key))
    findings = []
    for group in groups.values():
        for (left_index, left_key), (right_index, right_key) in combinations(group, 2):
            if gcd(left_key.e, right_key.e) == 1:
                findings.append((left_index, right_index))
    return findings


def recover_messages_from_pairs(
    keys: Sequence[PublicKey], ciphertexts: Sequence[int], findings: Iterable[Tuple[int, int]]
) -> Dict[Tuple[int, int], int]:
    """Recover one same-message plaintext for every reported vulnerable pair."""
    if len(keys) != len(ciphertexts):
        raise ValueError("keys and ciphertexts must have the same length")
    return {
        (left, right): common_modulus_attack(
            keys[left], ciphertexts[left], keys[right], ciphertexts[right]
        )
        for left, right in findings
    }


def _signed_mod_power(base: int, exponent: int, modulus: int) -> int:
    """Compute base**exponent mod modulus, including negative exponents."""
    if exponent >= 0:
        return pow(base, exponent, modulus)
    return pow(mod_inverse(base, modulus), -exponent, modulus)


def common_modulus_attack(
    first_key: PublicKey, first_ciphertext: int, second_key: PublicKey, second_ciphertext: int
) -> int:
    """Recover a message encrypted under a reused modulus and two coprime e values."""
    if first_key.n != second_key.n:
        raise ValueError("the attack requires the same RSA modulus")
    n = first_key.n
    if not (0 < first_ciphertext < n and 0 < second_ciphertext < n):
        raise ValueError("ciphertexts must be nonzero residues modulo n")

    divisor, a, b = extended_gcd(first_key.e, second_key.e)
    if divisor != 1:
        raise ValueError("the public exponents must be coprime")

    # a*e1 + b*e2 = 1, so c1^a * c2^b = m^(a*e1+b*e2) = m mod n.
    return (_signed_mod_power(first_ciphertext, a, n) * _signed_mod_power(second_ciphertext, b, n)) % n
