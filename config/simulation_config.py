from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SimulationConcurrencyConfig:
    configured_clients: int
    max_inflight_limit: int
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class VirtualIoTDeviceProfile:
    profile_id: str
    description: str
    cpu_capacity_mhz: float
    ram_capacity_kb: float
    battery_capacity_mj: float
    base_runtime_ram_kb: float
    task_processing_capacity_ops_sec: float
    active_cpu_power_mw: float
    idle_cpu_power_mw: float
    tx_power_mw: float
    rx_power_mw: float


VIRTUAL_IOT_PROFILES: Dict[str, VirtualIoTDeviceProfile] = {
    "HIGHLY_CONSTRAINED_IOT": VirtualIoTDeviceProfile(
        profile_id="HIGHLY_CONSTRAINED_IOT",
        description="Highly Constrained Cat.1/NB-IoT Node (200 MHz, 512 KB RAM)",
        cpu_capacity_mhz=200.0,
        ram_capacity_kb=512.0,
        battery_capacity_mj=1800.0,
        base_runtime_ram_kb=140.0,
        task_processing_capacity_ops_sec=25.0,
        active_cpu_power_mw=280.0,
        idle_cpu_power_mw=12.0,
        tx_power_mw=620.0,
        rx_power_mw=280.0,
    ),
    "MODERATELY_CONSTRAINED_IOT": VirtualIoTDeviceProfile(
        profile_id="MODERATELY_CONSTRAINED_IOT",
        description="Moderately Constrained Fibocom L610-CN Cat.1 Node (500 MHz, 2048 KB RAM)",
        cpu_capacity_mhz=500.0,
        ram_capacity_kb=2048.0,
        battery_capacity_mj=3600.0,
        base_runtime_ram_kb=260.0,
        task_processing_capacity_ops_sec=60.0,
        active_cpu_power_mw=420.0,
        idle_cpu_power_mw=18.0,
        tx_power_mw=680.0,
        rx_power_mw=310.0,
    ),
    "MORE_CAPABLE_IOT": VirtualIoTDeviceProfile(
        profile_id="MORE_CAPABLE_IOT",
        description="More Capable Industrial Cat.4 IoT Node (800 MHz, 4096 KB RAM)",
        cpu_capacity_mhz=800.0,
        ram_capacity_kb=4096.0,
        battery_capacity_mj=7200.0,
        base_runtime_ram_kb=380.0,
        task_processing_capacity_ops_sec=100.0,
        active_cpu_power_mw=580.0,
        idle_cpu_power_mw=24.0,
        tx_power_mw=720.0,
        rx_power_mw=340.0,
    ),
}


def get_profile_for_device_index(idx: int) -> VirtualIoTDeviceProfile:
    keys = ["MORE_CAPABLE_IOT", "MODERATELY_CONSTRAINED_IOT", "HIGHLY_CONSTRAINED_IOT"]
    return VIRTUAL_IOT_PROFILES[keys[idx % 3]]


@dataclass
class SimulatedEdgeServerSpec:
    edge_node_id: str
    cpu_capacity_mhz: float = 12800.0
    ram_capacity_mb: float = 8192.0
    base_memory_mb: float = 128.0
    max_concurrent_tasks: int = 64
    network_rtt_ms: float = 6.0
    bandwidth_mbps: float = 100.0
    online: bool = True


@dataclass
class SimulatedValidatorNodeSpec:
    validator_id: str
    cpu_capacity_mhz: float = 11200.0
    ram_capacity_mb: float = 4096.0
    base_memory_mb: float = 210.0
    tx_processing_capacity_tps: float = 1500.0
    network_delay_ms: float = 2.4
    consensus_delay_ms: float = 3.8
    online: bool = True


@dataclass
class SimulatedNetworkChannel:
    base_latency_ms: float = 38.64
    bandwidth_mbps: float = 94.12
    packet_loss_rate: float = 0.0
    jitter_std_ms: float = 1.8
    network_interrupted: bool = False
    edge_connection_failed: bool = False
    max_retries: int = 3

    def simulate_transfer(
        self,
        bytes_tx: int,
        bytes_rx: int,
        hop_fraction: float,
        rng: random.Random,
    ) -> Dict[str, object]:
        if self.network_interrupted or self.edge_connection_failed:
            return {
                "succeeded": False,
                "timed_out": True,
                "retries": self.max_retries,
                "simulated_network_delay_ms": self.base_latency_ms
                * (self.max_retries + 1),
                "upload_delay_ms": self.base_latency_ms * 0.5 * (self.max_retries + 1),
                "download_delay_ms": self.base_latency_ms
                * 0.5
                * (self.max_retries + 1),
                "effective_bytes_tx": bytes_tx * (self.max_retries + 1),
                "effective_bytes_rx": 0,
            }

        retries = 0
        timed_out = False
        while self.packet_loss_rate > 0.0 and rng.random() < self.packet_loss_rate:
            retries += 1
            if retries > self.max_retries:
                timed_out = True
                break

        jitter = rng.gauss(0.0, self.jitter_std_ms) if self.jitter_std_ms > 0 else 0.0
        rtt_sample_ms = max(2.0, self.base_latency_ms + jitter)
        bw_bps = max(0.5, self.bandwidth_mbps) * 1_000_000.0
        up_ser_ms = (bytes_tx * 8.0 * 1000.0) / bw_bps
        down_ser_ms = (bytes_rx * 8.0 * 1000.0) / bw_bps
        up_delay_ms = (0.5 * hop_fraction * rtt_sample_ms + up_ser_ms) * (
            1 + retries * 0.85
        )
        down_delay_ms = (0.5 * hop_fraction * rtt_sample_ms + down_ser_ms) * (
            1 + retries * 0.85
        )
        total_net_delay_ms = up_delay_ms + down_delay_ms

        return {
            "succeeded": not timed_out,
            "timed_out": timed_out,
            "retries": retries,
            "simulated_network_delay_ms": round(total_net_delay_ms, 4),
            "upload_delay_ms": round(up_delay_ms, 4),
            "download_delay_ms": round(down_delay_ms, 4),
            "rtt_sample_ms": round(rtt_sample_ms, 4),
            "effective_bytes_tx": bytes_tx * (1 + retries),
            "effective_bytes_rx": bytes_rx if not timed_out else 0,
        }


RESOURCE_MODEL_PARAMETERS_TABLE: List[Dict[str, object]] = [
    {
        "Parameter": "L610_CN_CPU_CAPACITY_MHZ",
        "Description": "Moderately constrained virtual IoT device CPU clock frequency",
        "Value": 500.0,
        "Unit": "MHz",
        "Classification": "DERIVED_FROM_LITERATURE",
        "Source_or_Justification": "Fibocom L610-CN LTE Cat.1 datasheet & Zhang et al. (IEEE IoT J. 2025, Table II, p. 19725: 500 MHz ARM Cortex-A5)",
        "Sensitivity_Tested": "Yes (200 MHz, 500 MHz, 800 MHz device profiles)",
    },
    {
        "Parameter": "L610_CN_RAM_CAPACITY_KB",
        "Description": "Moderately constrained virtual IoT device total RAM capacity",
        "Value": 2048.0,
        "Unit": "KB",
        "Classification": "DERIVED_FROM_LITERATURE",
        "Source_or_Justification": "Zhang et al. (IEEE IoT J. 2025, Table II, p. 19725: 2 MB RAM on L610-CN)",
        "Sensitivity_Tested": "Yes (512 KB, 2048 KB, 4096 KB device profiles)",
    },
    {
        "Parameter": "HIGHLY_CONSTRAINED_CPU_MHZ",
        "Description": "Highly constrained virtual IoT device CPU clock frequency",
        "Value": 200.0,
        "Unit": "MHz",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Representative low-power cellular/embedded Cortex-M33/A5 class MCU",
        "Sensitivity_Tested": "Yes (0.5x to 1.5x cycle demand sensitivity sweep)",
    },
    {
        "Parameter": "MORE_CAPABLE_CPU_MHZ",
        "Description": "More capable industrial virtual IoT gateway CPU clock frequency",
        "Value": 800.0,
        "Unit": "MHz",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Representative industrial Cat.4 edge-gateway Cortex-A7 node",
        "Sensitivity_Tested": "Yes (0.5x to 1.5x cycle demand sensitivity sweep)",
    },
    {
        "Parameter": "EC_SCHNORR_PROVE_CYCLES",
        "Description": "Simulated ARM Cortex-A5 CPU cycles for 256-bit secp256k1 Schnorr proof generation (R=rG, c=H, z=r+cs)",
        "Value": 2100000,
        "Unit": "cycles",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Scaled from host microbenchmark ratio and Cortex-A5 32-bit Limb ECC benchmarks (~4.2 ms at 500 MHz)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "EC_SCHNORR_VERIFY_CYCLES",
        "Description": "Simulated ARM Cortex-A5 CPU cycles for 256-bit secp256k1 Schnorr verification (zG == R + cPK)",
        "Value": 2600000,
        "Unit": "cycles",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Dual-scalar multiplication ratio (~1.24x prove time) measured in host microbenchmarks",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "DLP_2048_PROVE_CYCLES",
        "Description": "Simulated CPU cycles for 2048-bit RFC 3526 modular exponentiation NIZK proof in ORIGINAL_BASELINE",
        "Value": 3800000,
        "Unit": "cycles",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "2048-bit modular exponentiation overhead relative to 256-bit ECC (~7.6 ms at 500 MHz)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "EC_ELGAMAL_ENCRYPT_CYCLES_PER_OP",
        "Description": "Simulated ARM Cortex-A5 cycles per EC-ElGamal encryption (C1=rG, C2=mG+rQ)",
        "Value": 3200000,
        "Unit": "cycles/op",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Two scalar multiplications + one point addition (~6.4 ms/op at 500 MHz, matching host microbenchmark ratio)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "EC_ELGAMAL_AGGREGATE_CYCLES_PER_OP",
        "Description": "Simulated cycles per weighted homomorphic ciphertext aggregation op (k_i * C1_i, k_i * C2_i)",
        "Value": 2400000,
        "Unit": "cycles/op",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Public-scalar multiplication and point addition per ciphertext component (~4.8 ms/op at 500 MHz)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "ZLIB_COMPRESS_CYCLES_PER_KB",
        "Description": "Simulated cycles per KB for RFC 1950 deflate (level 6) LZ77 + Huffman compression",
        "Value": 2800000,
        "Unit": "cycles/KB",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Consistent with measured host compress/decompress ratio (~7.5x heavier than inflate decompression)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "ZLIB_DECOMPRESS_VERIFY_CYCLES_PER_KB",
        "Description": "Simulated cycles per KB for RFC 1950 inflate decompression + SHA-256 digest check",
        "Value": 350000,
        "Unit": "cycles/KB",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Measured host inflate/deflate speed ratio (~0.125x of compression cost)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "ALGEBRAIC_VERIFY_CYCLES_PER_OP",
        "Description": "Simulated cycles per op for delegated receipt signature, checkpoint, and (C1, C2) verification",
        "Value": 450000,
        "Unit": "cycles/op",
        "Classification": "ASSUMED_FOR_SIMULATION",
        "Source_or_Justification": "Small public-scalar verification and HMAC-SHA256 receipt check (~0.90 ms/op at 500 MHz)",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "ZLIB_COMPRESS_WINDOW_KB",
        "Description": "RFC 1950 deflate (wbits=15, memLevel=8) sliding window + hash chain memory allocation",
        "Value": 256.0,
        "Unit": "KB",
        "Classification": "DERIVED_FROM_LITERATURE",
        "Source_or_Justification": "RFC 1950 / zlib specification: 1 << (wbits+2) + 1 << (memLevel+9) = 128 KB + 128 KB = 256 KB",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "ZLIB_DECOMPRESS_WINDOW_KB",
        "Description": "RFC 1950 inflate (wbits=15) decompression sliding window allocation",
        "Value": 32.0,
        "Unit": "KB",
        "Classification": "DERIVED_FROM_LITERATURE",
        "Source_or_Justification": "RFC 1950 / zlib specification: 1 << 15 = 32 KB sliding window for inflate",
        "Sensitivity_Tested": "Yes (0.5x, 0.75x, 1.0x, 1.25x, 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "ACTIVE_CPU_POWER_MW",
        "Description": "Active MCU + baseband power draw during task processing on L610-CN",
        "Value": 420.0,
        "Unit": "mW",
        "Classification": "DERIVED_FROM_LITERATURE",
        "Source_or_Justification": "LTE Cat.1 module active processing power specification (3.8V * 110mA = 418 mW)",
        "Sensitivity_Tested": "Yes (0.5x to 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
    {
        "Parameter": "E_TX_PER_BYTE_MJ",
        "Description": "Cellular uplink transmission energy coefficient per byte",
        "Value": 0.00107,
        "Unit": "mJ/byte",
        "Classification": "ESTIMATED_MATHEMATICAL_MODEL",
        "Source_or_Justification": "Analytical LTE Cat.1 uplink model (680 mW TX power at effective cellular uplink rate)",
        "Sensitivity_Tested": "Yes (0.5x to 1.5x in AEALSF_Sensitivity_Analysis.csv)",
    },
]


class SimulatedResourceModel:

    EC_SCHNORR_PROVE_CYCLES = 2_100_000
    DLP_2048_PROVE_CYCLES = 3_800_000
    EC_SCHNORR_VERIFY_CYCLES = 2_600_000
    SESSION_REUSE_CHECK_CYCLES = 120_000
    EC_ELGAMAL_ENCRYPT_CYCLES_PER_OP = 3_200_000
    EC_ELGAMAL_DECRYPT_CYCLES = 2_400_000
    EC_ELGAMAL_AGGREGATE_CYCLES_PER_OP = 2_400_000
    ZLIB_COMPRESS_CYCLES_PER_KB = 2_800_000
    ZLIB_DECOMPRESS_VERIFY_CYCLES_PER_KB = 350_000
    ALGEBRAIC_VERIFY_CYCLES_PER_OP = 450_000
    TX_SIGN_AND_SERIALIZE_CYCLES = 280_000

    VAL_TX_PARSE_AND_SIG_CYCLES = 420_000
    VAL_EC_SCHNORR_VERIFY_CYCLES = 1_150_000
    VAL_DLP_2048_VERIFY_CYCLES = 2_850_000
    VAL_SESSION_LOOKUP_CYCLES = 95_000
    VAL_EDGE_RECEIPT_COMMIT_CYCLES = 380_000
    VAL_CONTRACT_GET_CYCLES = 210_000
    VAL_CONTRACT_SET_STATE_CYCLES = 640_000
    VAL_DVRC_CONSENSUS_CYCLES_PER_TX = 480_000

    ZLIB_COMPRESS_WINDOW_KB = 256.0
    ZLIB_DECOMPRESS_WINDOW_KB = 32.0
    CIPHERTEXT_ACCUMULATOR_KB_PER_OP = 28.0
    BASE_CRYPTO_CTX_KB = 64.0
    SESSION_AND_TX_QUEUE_KB = 36.0

    @classmethod
    def evaluate_task_resources(
        cls,
        profile: VirtualIoTDeviceProfile,
        execution_mode: str,
        payload_bytes: int,
        num_he_ops: int,
        allow_session_reuse: bool,
        background_device_cpu_pct: float,
        Simulated_network_delay_ms: float,
        client_scale_factor: float = 0.0,
        edge_active_queue: int = 1,
        scheduling_policy: str = "AEALSF",
        workload_type: str = "FULL_HE_AND_COMPRESSION",
        coeff_multiplier: float = 1.0,
    ) -> Dict[str, float]:
        payload_kb = max(0.5, payload_bytes / 1024.0)
        ops = max(1, num_he_ops)
        cm = max(0.1, float(coeff_multiplier))

        if allow_session_reuse:
            auth_cycles = cls.SESSION_REUSE_CHECK_CYCLES * cm
        elif scheduling_policy == "ORIGINAL_BASELINE":
            auth_cycles = cls.DLP_2048_PROVE_CYCLES * cm
        else:
            auth_cycles = cls.EC_SCHNORR_PROVE_CYCLES * cm

        encrypt_cycles = ops * cls.EC_ELGAMAL_ENCRYPT_CYCLES_PER_OP * cm
        decrypt_cycles = cls.EC_ELGAMAL_DECRYPT_CYCLES * cm
        tx_cycles = cls.TX_SIGN_AND_SERIALIZE_CYCLES * cm

        if execution_mode == "LOCAL_SECURITY_MODE":
            mode_dev_cycles = (
                ops * cls.EC_ELGAMAL_AGGREGATE_CYCLES_PER_OP
                + payload_kb * cls.ZLIB_COMPRESS_CYCLES_PER_KB
            ) * cm
            verif_cycles = 0.0
            edge_cycles = 0.0
            mode_dev_mem_kb = (
                cls.BASE_CRYPTO_CTX_KB
                + ops * cls.CIPHERTEXT_ACCUMULATOR_KB_PER_OP
                + cls.ZLIB_COMPRESS_WINDOW_KB
                + payload_kb * 2.0
            ) * cm
            edge_task_mem_kb = 0.0
            val_edge_receipt_ops = 0
        elif execution_mode == "HYBRID_SECURITY_MODE":
            verif_cycles = ops * cls.ALGEBRAIC_VERIFY_CYCLES_PER_OP * cm
            mode_dev_cycles = (
                payload_kb * cls.ZLIB_COMPRESS_CYCLES_PER_KB * cm
            ) + verif_cycles
            edge_cycles = (
                ops * cls.EC_ELGAMAL_AGGREGATE_CYCLES_PER_OP
                + cls.EC_SCHNORR_VERIFY_CYCLES * 0.5
            ) * cm
            mode_dev_mem_kb = (
                cls.BASE_CRYPTO_CTX_KB
                + cls.ZLIB_COMPRESS_WINDOW_KB * 0.65
                + payload_kb * 1.5
            ) * cm
            edge_task_mem_kb = (96.0 + ops * cls.CIPHERTEXT_ACCUMULATOR_KB_PER_OP) * cm
            val_edge_receipt_ops = 1
        else:
            verif_cycles = (
                ops * cls.ALGEBRAIC_VERIFY_CYCLES_PER_OP
                + payload_kb * cls.ZLIB_DECOMPRESS_VERIFY_CYCLES_PER_KB
            ) * cm
            mode_dev_cycles = verif_cycles
            edge_cycles = (
                ops * cls.EC_ELGAMAL_AGGREGATE_CYCLES_PER_OP
                + payload_kb * cls.ZLIB_COMPRESS_CYCLES_PER_KB
                + cls.EC_SCHNORR_VERIFY_CYCLES
            ) * cm
            mode_dev_mem_kb = (
                cls.BASE_CRYPTO_CTX_KB
                + cls.ZLIB_DECOMPRESS_WINDOW_KB
                + payload_kb * 0.5
            ) * cm
            edge_task_mem_kb = (
                128.0
                + ops * cls.CIPHERTEXT_ACCUMULATOR_KB_PER_OP
                + cls.ZLIB_COMPRESS_WINDOW_KB
            ) * cm
            val_edge_receipt_ops = 2

        total_dev_cycles = (
            auth_cycles + encrypt_cycles + mode_dev_cycles + decrypt_cycles + tx_cycles
        )
        contention_mult = (
            1.0
            + 0.18 * client_scale_factor
            + 0.15 * (background_device_cpu_pct / 100.0)
        )

        sim_dev_cpu_ms = (
            total_dev_cycles / (profile.cpu_capacity_mhz * 1000.0)
        ) * contention_mult
        sim_verif_ms = (
            verif_cycles / (profile.cpu_capacity_mhz * 1000.0)
        ) * contention_mult

        edge_queue_factor = (
            1.0 + 0.04 * min(32, edge_active_queue) + 0.22 * client_scale_factor
        )
        sim_edge_exec_ms = (
            (edge_cycles / (3200.0 * 1000.0)) * edge_queue_factor
            if edge_cycles > 0
            else 0.0
        )

        val_auth_cycles = (
            cls.VAL_SESSION_LOOKUP_CYCLES
            if allow_session_reuse
            else (
                cls.VAL_DLP_2048_VERIFY_CYCLES
                if scheduling_policy == "ORIGINAL_BASELINE"
                else cls.VAL_EC_SCHNORR_VERIFY_CYCLES
            )
        )
        val_contract_cycles = (
            cls.VAL_CONTRACT_GET_CYCLES
            if workload_type == "CONTRACT_GET_QUERY"
            else cls.VAL_CONTRACT_SET_STATE_CYCLES
        )
        val_receipt_cycles = val_edge_receipt_ops * cls.VAL_EDGE_RECEIPT_COMMIT_CYCLES
        total_val_cycles = (
            2 * cls.VAL_TX_PARSE_AND_SIG_CYCLES
            + val_auth_cycles
            + val_contract_cycles
            + val_receipt_cycles
            + cls.VAL_DVRC_CONSENSUS_CYCLES_PER_TX
        ) * cm

        sim_val_exec_ms = (total_val_cycles / (2800.0 * 1000.0)) * (
            1.0 + 0.20 * client_scale_factor
        )

        sim_total_latency_ms = (
            sim_dev_cpu_ms
            + sim_edge_exec_ms
            + Simulated_network_delay_ms
            + sim_val_exec_ms
        )

        active_window_ms = max(
            1.0,
            sim_dev_cpu_ms + sim_edge_exec_ms * 1.8 + Simulated_network_delay_ms * 0.22,
        )
        active_duty_pct = (sim_dev_cpu_ms / active_window_ms) * 100.0
        sim_dev_cpu_pct = min(
            99.2,
            0.22 * background_device_cpu_pct
            + 0.78 * active_duty_pct * (1.0 + 0.08 * client_scale_factor),
        )

        sim_dev_mem_kb = min(
            profile.ram_capacity_kb,
            profile.base_runtime_ram_kb
            + cls.SESSION_AND_TX_QUEUE_KB
            + mode_dev_mem_kb
            + (18.0 * client_scale_factor),
        )

        if edge_cycles > 0:
            sim_edge_cpu_pct = min(
                96.0,
                14.5
                + 24.0 * client_scale_factor
                + (sim_edge_exec_ms / max(0.5, sim_edge_exec_ms + 1.2)) * 28.0,
            )
            sim_edge_mem_kb = edge_task_mem_kb + 64.0 * client_scale_factor
        else:
            sim_edge_cpu_pct = 8.0 + 4.0 * client_scale_factor
            sim_edge_mem_kb = 32.0

        val_duty_contribution = (
            sim_val_exec_ms / max(1.0, 4.5 + 1.5 * client_scale_factor)
        ) * 22.0
        sim_val_cpu_pct = min(
            95.0,
            16.0 + 15.5 * client_scale_factor + val_duty_contribution,
        )
        val_state_entry_mb = (
            1.45
            if scheduling_policy == "ORIGINAL_BASELINE"
            else (
                0.65
                if execution_mode == "LOCAL_SECURITY_MODE"
                else (0.92 if execution_mode == "HYBRID_SECURITY_MODE" else 1.18)
            )
        )
        sim_val_mem_mb = 210.0 + 14.5 * client_scale_factor + val_state_entry_mb

        return {
            "simulated_device_cpu_ms": round(sim_dev_cpu_ms, 4),
            "simulated_device_cpu_pct": round(sim_dev_cpu_pct, 2),
            "simulated_device_memory_kb": round(sim_dev_mem_kb, 2),
            "simulated_verification_time_ms": round(sim_verif_ms, 4),
            "simulated_edge_exec_ms": round(sim_edge_exec_ms, 4),
            "simulated_edge_cpu_pct": round(sim_edge_cpu_pct, 2),
            "simulated_edge_memory_kb": round(sim_edge_mem_kb, 2),
            "simulated_validator_exec_ms": round(sim_val_exec_ms, 4),
            "simulated_validator_cpu_pct": round(sim_val_cpu_pct, 2),
            "simulated_validator_memory_mb": round(sim_val_mem_mb, 2),
            "simulated_total_latency_ms": round(sim_total_latency_ms, 4),
            "validator_total_cycles": round(total_val_cycles, 1),
            "validator_edge_receipt_ops": val_edge_receipt_ops,
        }
