#include "aealsf_device_registry.h"
#include <stdio.h>
#include <string.h>


int aealsf_support_rlp_rpc_send(const aealsf_rpc_context_t *ctx,
                                const char *method_selector,
                                const char *json_payload, char *response_buf,
                                size_t response_buf_len);

int aealsf_device_registry_registerDevice(
    const aealsf_rpc_context_t *ctx, const char *deviceId,
    const char *deviceName, const char *deviceDescription,
    const char *walletAddress, const uint8_t *nizkPkFingerprint,
    const uint8_t *hePublicKeyHash, char *out_tx_hash, size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"DeviceRegistry\",\"method\":\"registerDevice\","
           "\"selector\":\"0x28c5be3b\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x28c5be3b", payload, out_tx_hash,
                                     out_len);
}

int aealsf_device_registry_verifyDeviceFingerprint(
    const aealsf_rpc_context_t *ctx, const char *deviceId,
    const uint8_t *candidateFingerprint, char *out_tx_hash, size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"DeviceRegistry\",\"method\":"
           "\"verifyDeviceFingerprint\",\"selector\":\"0x8d295f7f\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x8d295f7f", payload, out_tx_hash,
                                     out_len);
}

int aealsf_device_registry_updateDeviceReputationAndState(
    const aealsf_rpc_context_t *ctx, const char *deviceId,
    uint64_t newReputationScore, uint8_t newState, char *out_tx_hash,
    size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"DeviceRegistry\",\"method\":"
           "\"updateDeviceReputationAndState\",\"selector\":\"0x5a844a1e\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x5a844a1e", payload, out_tx_hash,
                                     out_len);
}

int aealsf_device_registry_getDevice(const aealsf_rpc_context_t *ctx,
                                     const char *deviceId, char *out_tx_hash,
                                     size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"DeviceRegistry\",\"method\":\"getDevice\","
           "\"selector\":\"0x4ce4935e\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x4ce4935e", payload, out_tx_hash,
                                     out_len);
}
