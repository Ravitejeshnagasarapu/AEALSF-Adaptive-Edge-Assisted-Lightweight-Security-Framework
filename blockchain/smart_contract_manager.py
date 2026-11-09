from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class ContractExecutionError(Exception):
    pass


@dataclass(frozen=True)
class ContractReceipt:
    contract_name: str
    method_name: str
    caller_device_id: str
    caller_address: str
    success: bool
    return_data: Dict[str, object]
    events: List[Dict[str, object]]
    gas_used: int
    executed_at: float


class SmartContractManager:

    CONTRACT_ADDRESSES: Dict[str, str] = {
        "DeviceRegistry": "0xeba66001939bf456d2195a6594ca807f64bf9b00",
        "SecurityManager": "0x7c4b1fe649286651ece45b3dc2007cb8a163bf05",
        "TaskManagement": "0x98da48361c55d39a69163fa8fd24cf5f83655d23",
    }

    def __init__(self, admin_device_id: str = "system-governance-admin") -> None:
        self.admin_device_id = admin_device_id

        self._devices_by_id: Dict[str, Dict[str, object]] = {}
        self._device_id_by_wallet: Dict[str, str] = {}
        self._used_pk_fingerprints: set[str] = set()

        self._consumed_nonces: set[str] = set()
        self._active_sessions: Dict[str, Dict[str, object]] = {}
        self._authorized_edge_nodes: Dict[str, Dict[str, object]] = {}
        self._window_start_by_device: Dict[str, float] = {}
        self._request_count_by_device: Dict[str, int] = {}
        self._blocked_devices: set[str] = set()
        self.max_requests_per_window: int = 25
        self.window_duration_seconds: float = 10.0

        self._tasks_by_id: Dict[str, Dict[str, object]] = {}
        self.event_log: List[Dict[str, object]] = []

    def invoke(
        self,
        contract_name: str,
        method_name: str,
        caller_device_id: str,
        caller_address: str,
        args: Dict[str, object],
    ) -> ContractReceipt:
        now = time.time()
        events: List[Dict[str, object]] = []

        if contract_name == "DeviceRegistry":
            ret, gas = self._exec_device_registry(
                method_name, caller_device_id, caller_address, args, now, events
            )
        elif contract_name == "SecurityManager":
            ret, gas = self._exec_security_manager(
                method_name, caller_device_id, caller_address, args, now, events
            )
        elif contract_name == "TaskManagement":
            ret, gas = self._exec_task_management(
                method_name, caller_device_id, caller_address, args, now, events
            )
        else:
            raise ContractExecutionError(f"Unknown smart contract: {contract_name}")

        self.event_log.extend(events)
        return ContractReceipt(
            contract_name=contract_name,
            method_name=method_name,
            caller_device_id=caller_device_id,
            caller_address=caller_address,
            success=True,
            return_data=ret,
            events=events,
            gas_used=gas,
            executed_at=now,
        )

    def _exec_device_registry(
        self,
        method: str,
        caller_id: str,
        caller_addr: str,
        args: Dict[str, object],
        now: float,
        events: List[Dict[str, object]],
    ) -> Tuple[Dict[str, object], int]:
        if method == "registerDevice":
            device_id = str(args.get("deviceId", "")).strip()
            device_name = str(args.get("deviceName", "")).strip()
            device_desc = str(args.get("deviceDescription", "")).strip()
            wallet_addr = str(args.get("walletAddress", "")).strip()
            nizk_fp = str(args.get("nizkPkFingerprint", "")).strip()
            he_pk_hash = str(args.get("hePublicKeyHash", "")).strip()

            if not device_id or not device_name:
                raise ContractExecutionError(
                    "DeviceRegistry: empty deviceId or deviceName"
                )
            if not wallet_addr or not nizk_fp:
                raise ContractExecutionError(
                    "DeviceRegistry: missing walletAddress or NIZK fingerprint"
                )
            if caller_id != device_id and caller_id != self.admin_device_id:
                raise ContractExecutionError(
                    "DeviceRegistry: caller cannot register on behalf of another deviceId"
                )
            if device_id in self._devices_by_id:
                raise ContractExecutionError(
                    f"DeviceRegistry: deviceId {device_id} already registered"
                )
            if wallet_addr in self._device_id_by_wallet:
                raise ContractExecutionError(
                    "DeviceRegistry: walletAddress already bound"
                )
            if nizk_fp in self._used_pk_fingerprints:
                raise ContractExecutionError(
                    "DeviceRegistry: NIZK public key fingerprint already registered"
                )

            unique_id_hash = (
                "0x"
                + hashlib.sha256(
                    f"{device_id}|{wallet_addr}|{nizk_fp}".encode("utf-8")
                ).hexdigest()
            )

            record = {
                "deviceId": device_id,
                "deviceName": device_name,
                "deviceDescription": device_desc,
                "walletAddress": wallet_addr,
                "nizkPkFingerprint": nizk_fp,
                "hePublicKeyHash": he_pk_hash,
                "uniqueIdHash": unique_id_hash,
                "registeredAt": now,
                "reputationScore": 75.0,
                "state": "ACTIVE",
            }
            self._devices_by_id[device_id] = record
            self._device_id_by_wallet[wallet_addr] = device_id
            self._used_pk_fingerprints.add(nizk_fp)
            events.append(
                {
                    "event": "DeviceRegistered",
                    "deviceId": device_id,
                    "uniqueIdHash": unique_id_hash,
                }
            )
            return {"uniqueIdHash": unique_id_hash, "record": record}, 68400

        if method == "verifyDeviceFingerprint":
            device_id = str(args.get("deviceId", ""))
            candidate_fp = str(args.get("candidateFingerprint", ""))
            rec = self._devices_by_id.get(device_id)
            if rec is None or rec["state"] not in ("ACTIVE", "MONITOR"):
                return {"verified": False}, 21200
            return {"verified": rec["nizkPkFingerprint"] == candidate_fp}, 21800

        if method == "updateDeviceReputationAndState":
            if caller_id != self.admin_device_id:
                raise ContractExecutionError(
                    "DeviceRegistry: caller is not governance admin"
                )
            device_id = str(args.get("deviceId", ""))
            if device_id not in self._devices_by_id:
                raise ContractExecutionError("DeviceRegistry: unknown device")
            rec = self._devices_by_id[device_id]
            old_state = rec["state"]
            rec["reputationScore"] = float(
                args.get("newReputationScore", rec["reputationScore"])
            )
            rec["state"] = str(args.get("newState", old_state))
            events.append(
                {
                    "event": "DeviceStateUpdated",
                    "deviceId": device_id,
                    "oldState": old_state,
                    "newState": rec["state"],
                    "reputationScore": rec["reputationScore"],
                }
            )
            return {"updated": True, "record": rec}, 34500

        if method == "getDevice":
            device_id = str(args.get("deviceId", ""))
            if device_id not in self._devices_by_id:
                raise ContractExecutionError("DeviceRegistry: device not found")
            return {"record": dict(self._devices_by_id[device_id])}, 18400

        raise ContractExecutionError(f"DeviceRegistry: unsupported method {method}")

    def _exec_security_manager(
        self,
        method: str,
        caller_id: str,
        caller_addr: str,
        args: Dict[str, object],
        now: float,
        events: List[Dict[str, object]],
    ) -> Tuple[Dict[str, object], int]:
        if method == "authorizeEdgeNode":
            if caller_id != self.admin_device_id:
                raise ContractExecutionError(
                    "SecurityManager: unauthorized caller for authorizeEdgeNode"
                )
            edge_id = str(args.get("edgeNodeId", "")).strip()
            token_hash = str(args.get("publicTokenHash", "")).strip()
            if not edge_id or not token_hash:
                raise ContractExecutionError(
                    "SecurityManager: empty edgeNodeId or tokenHash"
                )
            self._authorized_edge_nodes[edge_id] = {
                "edgeNodeId": edge_id,
                "publicTokenHash": token_hash,
                "authorized": True,
                "registeredAt": now,
            }
            events.append({"event": "EdgeNodeAuthorized", "edgeNodeId": edge_id})
            return {"authorized": True}, 42000

        if method == "recordNIZKAuthentication":
            device_id = str(args.get("deviceId", ""))
            proof_hash = str(args.get("proofHash", ""))
            nonce_hash = str(args.get("nonceHash", ""))
            ttl_sec = float(args.get("ttlSeconds", 300.0))
            r1cs_verified = bool(
                args.get("nizkVerified", args.get("r1csVerified", False))
            )

            if device_id in self._blocked_devices:
                raise ContractExecutionError(
                    "SecurityManager: device blocked for anomaly"
                )
            if device_id not in self._devices_by_id:
                raise ContractExecutionError(
                    "SecurityManager: unregistered device cannot authenticate"
                )
            if self._devices_by_id[device_id]["state"] in ("ISOLATED", "REVOKED"):
                raise ContractExecutionError(
                    "SecurityManager: device isolated by DVRC reputation"
                )
            if nonce_hash in self._consumed_nonces:
                raise ContractExecutionError(
                    "SecurityManager: replay attack nonce detected"
                )
            if not r1cs_verified or not proof_hash:
                raise ContractExecutionError(
                    "SecurityManager: invalid NIZK proof constraint check"
                )

            win_start = self._window_start_by_device.get(device_id, 0.0)
            if now > win_start + self.window_duration_seconds:
                self._window_start_by_device[device_id] = now
                self._request_count_by_device[device_id] = 1
            else:
                self._request_count_by_device[device_id] = (
                    self._request_count_by_device.get(device_id, 0) + 1
                )
                if (
                    self._request_count_by_device[device_id]
                    > self.max_requests_per_window
                ):
                    self._blocked_devices.add(device_id)
                    events.append(
                        {
                            "event": "SecurityAnomalyDetected",
                            "deviceId": device_id,
                            "reason": "DDoS rate limit exceeded",
                        }
                    )
                    raise ContractExecutionError(
                        "SecurityManager: rate limit exceeded, device blocked"
                    )

            self._consumed_nonces.add(nonce_hash)
            expires_at = now + ttl_sec
            self._active_sessions[device_id] = {
                "deviceId": device_id,
                "proofHash": proof_hash,
                "nonceHash": nonce_hash,
                "authenticatedAt": now,
                "expiresAt": expires_at,
                "valid": True,
            }
            events.append(
                {
                    "event": "AuthenticationVerified",
                    "deviceId": device_id,
                    "expiresAt": expires_at,
                }
            )
            return {"authenticated": True, "expiresAt": expires_at}, 54200

        if method == "isDeviceAuthenticated":
            device_id = str(args.get("deviceId", ""))
            if device_id in self._blocked_devices:
                return {"authenticated": False}, 14500
            sess = self._active_sessions.get(device_id)
            valid = bool(sess and sess["valid"] and now <= float(sess["expiresAt"]))
            return {"authenticated": valid}, 16200

        if method == "isEdgeNodeAuthorized":
            edge_id = str(args.get("edgeNodeId", ""))
            info = self._authorized_edge_nodes.get(edge_id)
            return {"authorized": bool(info and info["authorized"])}, 15100

        raise ContractExecutionError(f"SecurityManager: unsupported method {method}")

    def _exec_task_management(
        self,
        method: str,
        caller_id: str,
        caller_addr: str,
        args: Dict[str, object],
        now: float,
        events: List[Dict[str, object]],
    ) -> Tuple[Dict[str, object], int]:
        if method == "createTask":
            task_id = str(args.get("taskId", "")).strip()
            device_id = str(args.get("deviceId", "")).strip()
            assigned_node = str(args.get("assignedNodeId", "")).strip()
            mode = str(args.get("mode", "LOCAL_SECURITY_MODE")).strip()
            input_hash = str(args.get("inputPayloadHash", "")).strip()

            if not task_id or not device_id or not input_hash:
                raise ContractExecutionError("TaskManagement: missing task parameters")
            if caller_id != device_id:
                raise ContractExecutionError(
                    "TaskManagement: caller must match task owner deviceId"
                )
            if device_id not in self._devices_by_id:
                raise ContractExecutionError("TaskManagement: unregistered device")
            sess = self._active_sessions.get(device_id)
            if not (sess and sess["valid"] and now <= float(sess["expiresAt"])):
                raise ContractExecutionError(
                    "TaskManagement: device does not hold an active NIZK-authenticated session"
                )
            if task_id in self._tasks_by_id:
                raise ContractExecutionError("TaskManagement: duplicate taskId")

            status = "CREATED" if mode == "LOCAL_SECURITY_MODE" else "OFFLOADED"
            rec = {
                "taskId": task_id,
                "deviceId": device_id,
                "assignedNodeId": assigned_node,
                "mode": mode,
                "status": status,
                "inputPayloadHash": input_hash,
                "resultPayloadHash": "",
                "edgeReceiptSignatureHash": "",
                "createdAt": now,
                "completedAt": 0.0,
            }
            self._tasks_by_id[task_id] = rec
            events.append({"event": "TaskCreated", "taskId": task_id, "mode": mode})
            return {"task": rec}, 58900

        if method == "submitTaskResult":
            task_id = str(args.get("taskId", "")).strip()
            executor_id = str(args.get("executorNodeId", "")).strip()
            result_hash = str(args.get("resultPayloadHash", "")).strip()
            sig_hash = str(args.get("edgeReceiptSignatureHash", "")).strip()

            if task_id not in self._tasks_by_id:
                raise ContractExecutionError("TaskManagement: task does not exist")
            rec = self._tasks_by_id[task_id]
            if rec["status"] not in ("CREATED", "OFFLOADED"):
                raise ContractExecutionError("TaskManagement: task already finalized")
            if not result_hash:
                raise ContractExecutionError("TaskManagement: empty resultPayloadHash")
            if rec["assignedNodeId"] != executor_id:
                raise ContractExecutionError("TaskManagement: executorNodeId mismatch")
            if rec["mode"] != "LOCAL_SECURITY_MODE":
                edge_info = self._authorized_edge_nodes.get(executor_id)
                if not (edge_info and edge_info["authorized"]):
                    raise ContractExecutionError(
                        "TaskManagement: executor edge node is not authorized on-chain"
                    )

            rec["resultPayloadHash"] = result_hash
            rec["edgeReceiptSignatureHash"] = sig_hash
            rec["status"] = "COMPLETED"
            rec["completedAt"] = now
            events.append(
                {
                    "event": "TaskResultSubmitted",
                    "taskId": task_id,
                    "executorNodeId": executor_id,
                    "resultPayloadHash": result_hash,
                }
            )
            return {"task": rec}, 49300

        if method == "verifyRetrievedResult":
            task_id = str(args.get("taskId", "")).strip()
            candidate_hash = str(args.get("candidateResultHash", "")).strip()
            if task_id not in self._tasks_by_id:
                raise ContractExecutionError("TaskManagement: task not found")
            rec = self._tasks_by_id[task_id]
            if rec["status"] not in ("COMPLETED", "VERIFIED"):
                raise ContractExecutionError("TaskManagement: result not yet submitted")

            if rec["resultPayloadHash"] == candidate_hash and candidate_hash != "":
                rec["status"] = "VERIFIED"
                events.append(
                    {"event": "TaskResultVerified", "taskId": task_id, "verified": True}
                )
                return {"verified": True, "status": "VERIFIED"}, 26400
            rec["status"] = "REJECTED"
            events.append(
                {"event": "TaskResultVerified", "taskId": task_id, "verified": False}
            )
            return {"verified": False, "status": "REJECTED"}, 26400

        if method == "getTask":
            task_id = str(args.get("taskId", "")).strip()
            if task_id not in self._tasks_by_id:
                raise ContractExecutionError("TaskManagement: task not found")
            return {"task": dict(self._tasks_by_id[task_id])}, 16800

        raise ContractExecutionError(f"TaskManagement: unsupported method {method}")

    @staticmethod
    def generate_embedded_c_interface_header(contract_name: str) -> str:
        return (
            f"#ifndef AEALSF_{contract_name.upper()}_H\n"
            f"#define AEALSF_{contract_name.upper()}_H\n"
            f"#include <stdint.h>\n"
            f"int aealsf_invoke_{contract_name.lower()}(const char* method, const uint8_t* rlp_args, uint32_t len);\n"
            f"#endif\n"
        )
