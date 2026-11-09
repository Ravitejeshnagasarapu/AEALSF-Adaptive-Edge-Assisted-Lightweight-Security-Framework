from __future__ import annotations
import json
import os
import re
from typing import Dict, List


SOLIDITY_TO_C_TYPE = {
    "string": "const char*",
    "address": "const char*",
    "bytes32": "const uint8_t*",
    "uint256": "uint64_t",
    "bool": "uint8_t",
    "ExecutionMode": "uint8_t",
    "DeviceState": "uint8_t",
}


def extract_solidity_abi(sol_path: str) -> List[Dict[str, object]]:
    with open(sol_path, "r", encoding="utf-8") as f:
        source = f.read()

    pattern = re.compile(
        r"function\s+(\w+)\s*\(([^)]*)\)\s*external(?:\s+view)?(?:\s+onlyAdmin)?(?:\s+returns\s*\(([^)]*)\))?",
        re.MULTILINE,
    )
    abi_entries: List[Dict[str, object]] = []
    for match in pattern.finditer(source):
        fn_name = match.group(1)
        raw_params = match.group(2).strip()
        raw_returns = (match.group(3) or "").strip()

        inputs = []
        if raw_params:
            for part in raw_params.split(","):
                tokens = part.strip().split()
                if len(tokens) >= 2:
                    sol_type = tokens[0]
                    param_name = tokens[-1]
                    inputs.append({"name": param_name, "type": sol_type})

        outputs = []
        if raw_returns:
            for part in raw_returns.split(","):
                tokens = part.strip().split()
                if tokens:
                    outputs.append(
                        {
                            "type": tokens[0],
                            "name": tokens[-1] if len(tokens) > 1 else "result",
                        }
                    )

        import hashlib

        sig_str = f"{fn_name}({','.join(i['type'] for i in inputs)})"
        selector = "0x" + hashlib.sha256(sig_str.encode("utf-8")).hexdigest()[:8]

        abi_entries.append(
            {
                "name": fn_name,
                "type": "function",
                "selector": selector,
                "signature": sig_str,
                "inputs": inputs,
                "outputs": outputs,
            }
        )
    return abi_entries


def generate_c_sdk_for_contract(
    contract_name: str, sol_path: str, output_dir: str
) -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    abi = extract_solidity_abi(sol_path)
    snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", contract_name).lower()

    abi_path = os.path.join(output_dir, f"{contract_name}.abi.json")
    with open(abi_path, "w", encoding="utf-8") as f:
        json.dump(abi, f, indent=2)

    guard = f"AEALSF_EMBEDDED_{snake_name.upper()}_H"
    header_lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
        "typedef struct {",
        "    const char* node_rpc_url;",
        "    uint16_t node_rpc_port;",
        "    const char* contract_address;",
        "    const char* wallet_account_address;",
        "} aealsf_rpc_context_t;",
        "",
    ]

    source_lines = [
        f'#include "aealsf_{snake_name}.h"',
        "#include <string.h>",
        "#include <stdio.h>",
        "",
        "int aealsf_support_rlp_rpc_send(",
        "    const aealsf_rpc_context_t* ctx,",
        "    const char* method_selector,",
        "    const char* json_payload,",
        "    char* response_buf,",
        "    size_t response_buf_len",
        ");",
        "",
    ]

    for entry in abi:
        fn_name = str(entry["name"])
        selector = str(entry["selector"])
        inputs: List[Dict[str, str]] = entry["inputs"]

        c_params = ["const aealsf_rpc_context_t* ctx"]
        for inp in inputs:
            c_type = SOLIDITY_TO_C_TYPE.get(inp["type"], "const char*")
            c_params.append(f"{c_type} {inp['name']}")
        c_params.extend(["char* out_tx_hash", "size_t out_len"])
        param_sig = ", ".join(c_params)

        c_fn_name = f"aealsf_{snake_name}_{fn_name}"
        header_lines.append(f"int {c_fn_name}({param_sig});")
        header_lines.append("")

        source_lines.append(f"int {c_fn_name}({param_sig}) {{")
        source_lines.append(
            "    if (!ctx || !out_tx_hash || out_len == 0) { return -1; }"
        )
        source_lines.append("    char payload[512];")
        source_lines.append(
            f'    snprintf(payload, sizeof(payload), "{{\\"contract\\":\\"{contract_name}\\",\\"method\\":\\"{fn_name}\\",\\"selector\\":\\"{selector}\\"}}");'
        )
        source_lines.append(
            f'    return aealsf_support_rlp_rpc_send(ctx, "{selector}", payload, out_tx_hash, out_len);'
        )
        source_lines.append("}")
        source_lines.append("")

    header_lines.extend(
        [
            "#ifdef __cplusplus",
            "}",
            "#endif",
            f"#endif",
            "",
        ]
    )

    h_path = os.path.join(output_dir, f"aealsf_{snake_name}.h")
    c_path = os.path.join(output_dir, f"aealsf_{snake_name}.c")
    with open(h_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header_lines))
    with open(c_path, "w", encoding="utf-8") as f:
        f.write("\n".join(source_lines))

    return {"abi_json": abi_path, "header": h_path, "source": c_path}


def generate_all_embedded_c_sdks(
    contracts_dir: str = "smart_contracts",
    output_dir: str = "smart_contracts/generated_c_sdk",
) -> Dict[str, Dict[str, str]]:
    results: Dict[str, Dict[str, str]] = {}
    for contract_name in ("DeviceRegistry", "SecurityManager", "TaskManagement"):
        sol_file = os.path.join(contracts_dir, f"{contract_name}.sol")
        if os.path.exists(sol_file):
            results[contract_name] = generate_c_sdk_for_contract(
                contract_name, sol_file, output_dir
            )
    return results


if __name__ == "__main__":
    generated = generate_all_embedded_c_sdks()
    print(json.dumps(generated, indent=2))
