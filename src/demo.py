"""Single-command live demo for the presentation."""

import argparse
from math import isqrt

from .rsa_utils import bytes_to_int, decrypt_int, encrypt_int, int_to_bytes
from .common_modulus_attack import (
    find_common_modulus_pairs,
    generate_common_modulus_keyset,
    recover_messages_from_pairs,
)
from .wiener_attack import generate_wiener_vulnerable_key, wiener_attack


def common_modulus_demo(bits: int) -> None:
    print("\n[1/2] Common-modulus attack (same N, different e)")
    keys, expected_pair = generate_common_modulus_keyset(count=4, bits=bits)
    message = bytes_to_int(b"Never reuse an RSA modulus")
    ciphertexts = [encrypt_int(message, key) for key in keys]
    findings = find_common_modulus_pairs(keys)
    recovered_message = recover_messages_from_pairs(keys, ciphertexts, findings)[expected_pair]
    plaintext = int_to_bytes(recovered_message).decode()
    print(f"Generated {len(keys)} public keys of about {bits} bits.")
    print(f"Two keys reuse one {keys[0].n.bit_length()}-bit modulus with e1={keys[0].e} and e2={keys[1].e}.")
    print(f"Indexed scan found {len(findings)} same-N, coprime-e pair(s).")
    print("Extended Euclid found a, b such that a*e1 + b*e2 = 1.")
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
    common_modulus_demo(args.bits)
    wiener_demo(args.bits)


if __name__ == "__main__":
    main()

