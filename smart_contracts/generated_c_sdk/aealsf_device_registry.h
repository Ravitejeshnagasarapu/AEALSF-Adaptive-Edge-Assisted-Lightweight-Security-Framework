#ifndef AEALSF_EMBEDDED_DEVICE_REGISTRY_H
#define AEALSF_EMBEDDED_DEVICE_REGISTRY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char* node_rpc_url;
    uint16_t node_rpc_port;
    const char* contract_address;
    const char* wallet_account_address;
} aealsf_rpc_context_t;

int aealsf_device_registry_registerDevice(const aealsf_rpc_context_t* ctx, const char* deviceId, const char* deviceName, const char* deviceDescription, const char* walletAddress, const uint8_t* nizkPkFingerprint, const uint8_t* hePublicKeyHash, char* out_tx_hash, size_t out_len);

int aealsf_device_registry_verifyDeviceFingerprint(const aealsf_rpc_context_t* ctx, const char* deviceId, const uint8_t* candidateFingerprint, char* out_tx_hash, size_t out_len);

int aealsf_device_registry_updateDeviceReputationAndState(const aealsf_rpc_context_t* ctx, const char* deviceId, uint64_t newReputationScore, uint8_t newState, char* out_tx_hash, size_t out_len);

int aealsf_device_registry_getDevice(const aealsf_rpc_context_t* ctx, const char* deviceId, char* out_tx_hash, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
