"""Single-command live demo for the presentation."""

import argparse
from math import isqrt

from .rsa_utils import bytes_to_int, decrypt_int, encrypt_int, int_to_bytes
from .shared_prime_attack import (
    find_shared_prime_pairs,
    generate_vulnerable_keyset,
    recover_shared_prime_private_keys,
)
from .wiener_attack import generate_wiener_vulnerable_key, wiener_attack


def shared_prime_demo(bits: int) -> None:
    print("\n[1/2] Shared-prime attack")
    keys, _, expected_pair = generate_vulnerable_keyset(count=4, bits=bits)
    message = bytes_to_int(b"RSA keys need independent primes")
    ciphertext = encrypt_int(message, keys[expected_pair[0]])
    findings = find_shared_prime_pairs(keys)
    recovered = recover_shared_prime_private_keys(keys, findings)
    key = recovered[keys[expected_pair[0]].n]
    plaintext = int_to_bytes(decrypt_int(ciphertext, key)).decode()
    print(f"Generated {len(keys)} public moduli of about {bits} bits.")
    print(f"Public gcd scan found {len(findings)} shared-prime pair(s).")
    print(f"Recovered plaintext: {plaintext}")


def wiener_demo(bits: int) -> None:
    print("\n[2/2] Wiener small-d attack")
    public_key, private_key = generate_wiener_vulnerable_key(bits)
    message = bytes_to_int(b"Small d breaks RSA")
    ciphertext = encrypt_int(message, public_key)
    recovered = wiener_attack(public_key)
    if recovered is None:
        raise RuntimeError("Wiener attack did not recover the deliberately weak key")
    plaintext = int_to_bytes(decrypt_int(ciphertext, recovered)).decode()
    bound = isqrt(isqrt(public_key.n)) // 3
    print(f"Generated a {public_key.n.bit_length()}-bit modulus with d = {private_key.d}.")
    print(f"Classical threshold estimate: d < {bound}.")
    print(f"Attack recovered d correctly: {recovered.d == private_key.d}")
    print(f"Recovered plaintext: {plaintext}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bits", type=int, default=2048)
    args = parser.parse_args()
    shared_prime_demo(args.bits)
    wiener_demo(args.bits)


if __name__ == "__main__":
    main()

