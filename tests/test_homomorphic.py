import unittest
from cryptography.homomorphic_encryption import (
    ECElGamalHomomorphicEngine,
    is_on_curve,
)


class TestHomomorphicEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.he = ECElGamalHomomorphicEngine(bsgs_max_bound=65536)
        self.kp = self.he.generate_keypair("dev-he-01")

    def test_key_generation_on_curve(self) -> None:
        self.assertTrue(is_on_curve(self.kp.public_key_q))
        self.assertFalse(self.kp.public_key_q.is_infinity)

    def test_encrypt_decrypt_single_value(self) -> None:
        for val in [0, 1, 42, 1337, -250]:
            ct = self.he.encrypt(val, self.kp.public_key_q)
            recovered = self.he.decrypt(ct, self.kp.private_key_d)
            self.assertEqual(recovered, val)

    def test_homomorphic_addition_equations_7_to_12(self) -> None:
        m1, m2, m3 = 415, 890, 1205
        c1 = self.he.encrypt(m1, self.kp.public_key_q)
        c2 = self.he.encrypt(m2, self.kp.public_key_q)
        c3 = self.he.encrypt(m3, self.kp.public_key_q)

        agg = self.he.homomorphic_sum([c1, c2, c3])
        self.assertEqual(agg.operations_count, 3)
        decrypted_sum = self.he.decrypt(agg, self.kp.private_key_d)
        self.assertEqual(decrypted_sum, m1 + m2 + m3)

    def test_homomorphic_scalar_mul_and_rerandomization(self) -> None:
        ct = self.he.encrypt(125, self.kp.public_key_q)
        scaled = self.he.homomorphic_scalar_mul(6, ct)
        rerand = self.he.rerandomize_ciphertext(scaled, self.kp.public_key_q)
        self.assertNotEqual(scaled.c1, rerand.c1)
        self.assertEqual(self.he.decrypt(rerand, self.kp.private_key_d), 750)

    def test_precomputed_blinding_pool_encryption(self) -> None:
        count = self.he.precompute_blinding_pool(
            "dev-he-01", self.kp.public_key_q, pool_size=4
        )
        self.assertEqual(count, 4)
        ct1 = self.he.encrypt(
            310, self.kp.public_key_q, owner_id="dev-he-01", use_precomputed_pool=True
        )
        ct2 = self.he.encrypt(
            190, self.kp.public_key_q, owner_id="dev-he-01", use_precomputed_pool=True
        )
        agg = self.he.homomorphic_add(ct1, ct2)
        self.assertEqual(self.he.decrypt(agg, self.kp.private_key_d), 500)


if __name__ == "__main__":
    unittest.main()
