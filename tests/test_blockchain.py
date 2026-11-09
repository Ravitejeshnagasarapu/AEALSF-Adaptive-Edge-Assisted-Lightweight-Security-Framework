import unittest
from blockchain.blockchain_client import BlockchainClient
from cryptography.key_manager import KeyManager


class TestBlockchainAndDVRC(unittest.TestCase):
    def setUp(self) -> None:
        self.km = KeyManager()
        self.bc = BlockchainClient(self.km)

    def test_dvrc_asymmetric_reputation_update(self) -> None:
        self.bc.dvrc.register_participant("dev-rep-01", initial_score=75.0)
        p_after_ok = self.bc.dvrc.update_reputation("dev-rep-01", success=True)
        score_after_ok = p_after_ok.reputation_score
        p_after_err = self.bc.dvrc.update_reputation("dev-rep-01", success=False)
        self.assertLess(p_after_err.reputation_score, score_after_ok - 5.0)

    def test_smart_contract_registration_and_chain_integrity(self) -> None:
        wallet = self.km.provision_device_wallet("dev-chain-01")
        tx = self.bc.tx_manager.create_signed_transaction(
            sender_device_id="dev-chain-01",
            contract_name="DeviceRegistry",
            method_name="registerDevice",
            payload={
                "deviceId": "dev-chain-01",
                "deviceName": "L610-CN",
                "deviceDescription": "Test Node",
                "walletAddress": wallet.blockchain_address,
                "nizkPkFingerprint": wallet.nizk_keypair.pk_fingerprint,
                "hePublicKeyHash": "0xabc123",
            },
            tx_type="SET",
        )
        ok, receipt, round_res, msg = self.bc.submit_and_execute_transaction(tx)
        self.assertTrue(ok, msg)
        self.assertIsNotNone(receipt)
        self.assertTrue(round_res.reached_consensus)

        chain_ok, chain_msg = self.bc.integrity_verifier.verify_chain(self.bc.chain)
        self.assertTrue(chain_ok, chain_msg)


if __name__ == "__main__":
    unittest.main()
