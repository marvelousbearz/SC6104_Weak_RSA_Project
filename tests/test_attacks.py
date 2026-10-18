import unittest

from src.rsa_utils import bytes_to_int, decrypt_int, encrypt_int
from src.shared_prime_attack import (
    batch_gcd_findings,
    find_shared_prime_pairs,
    generate_vulnerable_keyset,
    recover_batch_gcd_private_keys,
    recover_shared_prime_private_keys,
)
from src.wiener_attack import (
    generate_wiener_key_at_ratio,
    generate_wiener_vulnerable_key,
    wiener_attack,
)


class WeakRsaAttackTests(unittest.TestCase):
    def test_shared_prime_attack_recovers_two_keys(self):
        keys, private_keys, pair = generate_vulnerable_keyset(count=4, bits=128)
        findings = find_shared_prime_pairs(keys)
        recovered = recover_shared_prime_private_keys(keys, findings)
        self.assertEqual(len(findings), 1)
        for index in pair:
            self.assertEqual(recovered[keys[index].n].d, private_keys[keys[index].n].d)

    def test_shared_prime_attack_decrypts_message(self):
        keys, _, pair = generate_vulnerable_keyset(count=3, bits=128)
        ciphertext = encrypt_int(bytes_to_int(b"test"), keys[pair[0]])
        recovered = recover_shared_prime_private_keys(keys, find_shared_prime_pairs(keys))
        self.assertEqual(decrypt_int(ciphertext, recovered[keys[pair[0]].n]), bytes_to_int(b"test"))

    def test_wiener_attack_recovers_small_private_exponent(self):
        public_key, original = generate_wiener_vulnerable_key(bits=256)
        recovered = wiener_attack(public_key)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.d, original.d)

    def test_batch_gcd_recovers_shared_prime_keys(self):
        keys, private_keys, pair = generate_vulnerable_keyset(count=8, bits=128)
        findings = batch_gcd_findings(keys)
        recovered = recover_batch_gcd_private_keys(keys, findings)
        self.assertEqual({index for index, _ in findings}, set(pair))
        for index in pair:
            self.assertEqual(recovered[keys[index].n].d, private_keys[keys[index].n].d)

    def test_wiener_ratio_generator_produces_requested_scale(self):
        public_key, private_key, actual_ratio = generate_wiener_key_at_ratio(0.10, bits=256)
        self.assertGreater(actual_ratio, 0.09)
        self.assertLess(actual_ratio, 0.12)
        self.assertEqual(wiener_attack(public_key).d, private_key.d)


if __name__ == "__main__":
    unittest.main()

