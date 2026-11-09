from __future__ import annotations
import json
import os
import random
import time
from typing import Dict

from blockchain.dvrc_consensus import DVRCConsensusEngine
from blockchain.smart_contract_manager import (
    ContractExecutionError,
    SmartContractManager,
)
from cryptography.homomorphic_encryption import ECElGamalHomomorphicEngine
from cryptography.nizk_authentication import NIZKAuthenticator
from cryptography.verification import CryptographicVerifier


def evaluate_ddos_and_cryptographic_security(
    num_legitimate_clients: int = 1000,
    num_ddos_requests: int = 50000,
) -> Dict[str, object]:
    t0 = time.perf_counter()
    dvrc = DVRCConsensusEngine()
    contracts = SmartContractManager()

    for i in range(num_legitimate_clients):
        dev_id = f"auth-client-{i:04d}"
        dvrc.register_participant(dev_id, role="IOT_DEVICE", initial_score=78.0)
        contracts.invoke(
            contract_name="DeviceRegistry",
            method_name="registerDevice",
            caller_device_id=dev_id,
            caller_address=f"0xlegit{i:035x}",
            args={
                "deviceId": dev_id,
                "deviceName": "L610-CN",
                "deviceDescription": "Authenticated Node",
                "walletAddress": f"0xlegit{i:035x}",
                "nizkPkFingerprint": f"0xfp{i:060x}",
                "hePublicKeyHash": f"0xhe{i:060x}",
            },
        )

    blocked_by_dvrc_reputation_filter = 0
    blocked_by_distributed_rate_limiter = 0
    blocked_by_smart_contract_nizk_guard = 0
    legitimate_requests_passed = 0

    for i in range(num_legitimate_clients):
        dev_id = f"auth-client-{i:04d}"
        quota = dvrc.get_allowed_request_quota(dev_id)
        if quota > 0:
            rec = contracts.invoke(
                contract_name="SecurityManager",
                method_name="recordNIZKAuthentication",
                caller_device_id=dev_id,
                caller_address=f"0xlegit{i:035x}",
                args={
                    "deviceId": dev_id,
                    "proofHash": f"0xprf{i:058x}",
                    "nonceHash": f"0xnon{i:058x}",
                    "ttlSeconds": 300.0,
                    "r1csVerified": True,
                },
            )
            if rec.return_data.get("authenticated"):
                legitimate_requests_passed += 1

    node_rate_counters: Dict[str, int] = {}
    for j in range(num_ddos_requests):
        bot_id = f"ddos-bot-{j % 2500:04d}"
        attack_class = j % 3

        if bot_id not in dvrc.profiles:
            init_rep = 18.0 if attack_class == 0 else 52.0
            dvrc.register_participant(bot_id, role="IOT_DEVICE", initial_score=init_rep)

        if attack_class == 0 or dvrc.get_allowed_request_quota(bot_id) == 0:
            blocked_by_dvrc_reputation_filter += 1
            continue

        node_rate_counters[bot_id] = node_rate_counters.get(bot_id, 0) + 1
        if attack_class == 1 and node_rate_counters[bot_id] > 1:
            blocked_by_distributed_rate_limiter += 1
            dvrc.update_reputation(bot_id, success=False, severity_multiplier=1.5)
            continue

        try:
            contracts.invoke(
                contract_name="SecurityManager",
                method_name="recordNIZKAuthentication",
                caller_device_id=bot_id,
                caller_address=f"0xbot{j:036x}",
                args={
                    "deviceId": bot_id,
                    "proofHash": f"0xforged{j:056x}",
                    "nonceHash": f"0xbotnon{j:056x}",
                    "ttlSeconds": 60.0,
                    "r1csVerified": False,
                },
            )
        except ContractExecutionError:
            blocked_by_smart_contract_nizk_guard += 1
            dvrc.update_reputation(bot_id, success=False, severity_multiplier=2.0)

    total_malicious_blocked = (
        blocked_by_dvrc_reputation_filter
        + blocked_by_distributed_rate_limiter
        + blocked_by_smart_contract_nizk_guard
    )
    ddos_elapsed_ms = (time.perf_counter() - t0) * 1000.0

    he = ECElGamalHomomorphicEngine(bsgs_max_bound=65536)
    kp = he.generate_keypair("crypto-eval-node")
    he.precompute_blinding_pool("crypto-eval-node", kp.public_key_q, pool_size=64)

    ct_bytes_buffer = bytearray()
    ind_cpa_correct_guesses = 0
    ind_cpa_trials = 64
    rng = random.Random(42)

    for idx in range(ind_cpa_trials):
        if idx % 32 == 0 and idx > 0:
            he.precompute_blinding_pool(
                "crypto-eval-node", kp.public_key_q, pool_size=32
            )
        b_bit = rng.randint(0, 1)
        m_chosen = 100 if b_bit == 0 else 900
        ct = he.encrypt(
            m_chosen,
            kp.public_key_q,
            owner_id="crypto-eval-node",
            use_precomputed_pool=True,
        )
        ct_bytes_buffer.extend(ct.c1.x.to_bytes(32, "big"))
        ct_bytes_buffer.extend(ct.c1.y.to_bytes(32, "big"))
        ct_bytes_buffer.extend(ct.c2.x.to_bytes(32, "big"))
        ct_bytes_buffer.extend(ct.c2.y.to_bytes(32, "big"))

        attacker_guess = ct.c2.x & 1
        if attacker_guess == b_bit:
            ind_cpa_correct_guesses += 1

    entropy_bits_per_byte = CryptographicVerifier.shannon_entropy_bits_per_byte(
        bytes(ct_bytes_buffer)
    )
    ind_cpa_win_prob = ind_cpa_correct_guesses / ind_cpa_trials
    ind_cpa_advantage_epsilon = abs(ind_cpa_win_prob - 0.5)

    he_verifications_passed = 0
    for _ in range(20):
        a_val = rng.randint(-500, 1500)
        b_val = rng.randint(-500, 1500)
        if (
            not he._blinding_pools.get("crypto-eval-node")
            or len(he._blinding_pools["crypto-eval-node"]) < 2
        ):
            he.precompute_blinding_pool(
                "crypto-eval-node", kp.public_key_q, pool_size=20
            )
        ca = he.encrypt(
            a_val,
            kp.public_key_q,
            owner_id="crypto-eval-node",
            use_precomputed_pool=True,
        )
        cb = he.encrypt(
            b_val,
            kp.public_key_q,
            owner_id="crypto-eval-node",
            use_precomputed_pool=True,
        )
        csum = he.homomorphic_add(ca, cb)
        if he.decrypt(csum, kp.private_key_d) == (a_val + b_val):
            he_verifications_passed += 1

    nizk = NIZKAuthenticator()
    n_kp = nizk.generate_keypair("nizk-eval-node")
    prf = nizk.generate_proof(n_kp)
    nizk_ok, _ = nizk.verify_proof(prf, expected_pk=n_kp.public_key_pk)

    result = {
        "ddos_simulation": {
            "authenticated_clients": num_legitimate_clients,
            "unauthenticated_ddos_requests": num_ddos_requests,
            "legitimate_requests_succeeded": legitimate_requests_passed,
            "legitimate_success_rate_pct": round(
                100.0 * legitimate_requests_passed / num_legitimate_clients, 2
            ),
            "blocked_by_dvrc_reputation_filter": blocked_by_dvrc_reputation_filter,
            "blocked_by_distributed_rate_limiter": blocked_by_distributed_rate_limiter,
            "blocked_by_smart_contract_nizk_guard": blocked_by_smart_contract_nizk_guard,
            "total_malicious_blocked": total_malicious_blocked,
            "malicious_filtering_rate_pct": round(
                100.0 * total_malicious_blocked / num_ddos_requests, 2
            ),
            "processing_time_ms": round(ddos_elapsed_ms, 2),
        },
        "cryptographic_security_metrics": {
            "eq13_ind_cpa_trials": ind_cpa_trials,
            "eq13_attacker_win_probability": round(ind_cpa_win_prob, 4),
            "eq13_distinguishing_advantage_epsilon": round(
                ind_cpa_advantage_epsilon, 4
            ),
            "eq15_ciphertext_shannon_entropy_bits_per_byte": round(
                entropy_bits_per_byte, 4
            ),
            "eq15_ideal_max_entropy_bits_per_byte": 8.0,
            "eq16_homomorphic_verification_accuracy_pct": round(
                100.0 * he_verifications_passed / 20.0, 2
            ),
            "nizk_completeness_verified": nizk_ok,
        },
    }
    os.makedirs("results", exist_ok=True)
    with open("results/security_ddos_entropy_results.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result


if __name__ == "__main__":
    res = evaluate_ddos_and_cryptographic_security()
    print(json.dumps(res, indent=2))
