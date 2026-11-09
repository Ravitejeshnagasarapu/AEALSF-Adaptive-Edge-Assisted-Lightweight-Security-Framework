#include "aealsf_security_manager.h"
#include <stdio.h>
#include <string.h>


int aealsf_support_rlp_rpc_send(const aealsf_rpc_context_t *ctx,
                                const char *method_selector,
                                const char *json_payload, char *response_buf,
                                size_t response_buf_len);

int aealsf_security_manager_authorizeEdgeNode(const aealsf_rpc_context_t *ctx,
                                              const char *edgeNodeId,
                                              const uint8_t *publicTokenHash,
                                              char *out_tx_hash,
                                              size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"SecurityManager\",\"method\":\"authorizeEdgeNode\","
           "\"selector\":\"0x8abf5f4c\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x8abf5f4c", payload, out_tx_hash,
                                     out_len);
}

int aealsf_security_manager_recordNIZKAuthentication(
    const aealsf_rpc_context_t *ctx, const char *deviceId,
    const uint8_t *proofHash, const uint8_t *nonceHash, uint64_t ttlSeconds,
    uint8_t r1csVerified, char *out_tx_hash, size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"SecurityManager\",\"method\":"
           "\"recordNIZKAuthentication\",\"selector\":\"0x3016f787\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x3016f787", payload, out_tx_hash,
                                     out_len);
}

int aealsf_security_manager_isDeviceAuthenticated(
    const aealsf_rpc_context_t *ctx, const char *deviceId, char *out_tx_hash,
    size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"SecurityManager\",\"method\":"
           "\"isDeviceAuthenticated\",\"selector\":\"0x3657b730\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x3657b730", payload, out_tx_hash,
                                     out_len);
}
