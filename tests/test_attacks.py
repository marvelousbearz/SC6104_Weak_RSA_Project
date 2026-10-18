import unittest

from src.rsa_utils import bytes_to_int, decrypt_int, encrypt_int
from src.common_modulus_attack import (
    common_modulus_attack,
    find_common_modulus_pairs,
    generate_common_modulus_keys,
    generate_common_modulus_keyset,
    recover_messages_from_pairs,
)
from src.wiener_attack import (
    generate_wiener_key_at_ratio,
    generate_wiener_vulnerable_key,
    wiener_attack,
)


class WeakRsaAttackTests(unittest.TestCase):
    def test_common_modulus_attack_recovers_message(self):
        first_key, second_key, _ = generate_common_modulus_keys(bits=128)
        message = bytes_to_int(b"test")
        recovered = common_modulus_attack(
            first_key,
            encrypt_int(message, first_key),
            second_key,
            encrypt_int(message, second_key),
        )
        self.assertEqual(recovered, message)

    def test_indexed_collection_scan_recovers_same_n_message(self):
        keys, expected_pair = generate_common_modulus_keyset(count=8, bits=128)
        message = bytes_to_int(b"test")
        ciphertexts = [encrypt_int(message, key) for key in keys]
        findings = find_common_modulus_pairs(keys)
        recovered = recover_messages_from_pairs(keys, ciphertexts, findings)
        self.assertEqual(findings, [expected_pair])
        self.assertEqual(recovered[expected_pair], message)

    def test_wiener_attack_recovers_small_private_exponent(self):
        public_key, original = generate_wiener_vulnerable_key(bits=256)
        recovered = wiener_attack(public_key)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.d, original.d)

    def test_wiener_ratio_generator_produces_requested_scale(self):
        public_key, private_key, actual_ratio = generate_wiener_key_at_ratio(0.10, bits=256)
        self.assertGreater(actual_ratio, 0.09)
        self.assertLess(actual_ratio, 0.12)
        self.assertEqual(wiener_attack(public_key).d, private_key.d)


if __name__ == "__main__":
    unittest.main()

