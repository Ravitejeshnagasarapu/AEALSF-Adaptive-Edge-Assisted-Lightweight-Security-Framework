#ifndef AEALSF_EMBEDDED_SECURITY_MANAGER_H
#define AEALSF_EMBEDDED_SECURITY_MANAGER_H

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const char *node_rpc_url;
  uint16_t node_rpc_port;
  const char *contract_address;
  const char *wallet_account_address;
} aealsf_rpc_context_t;

int aealsf_security_manager_authorizeEdgeNode(const aealsf_rpc_context_t *ctx,
                                              const char *edgeNodeId,
                                              const uint8_t *publicTokenHash,
                                              char *out_tx_hash,
                                              size_t out_len);

int aealsf_security_manager_recordNIZKAuthentication(
    const aealsf_rpc_context_t *ctx, const char *deviceId,
    const uint8_t *proofHash, const uint8_t *nonceHash, uint64_t ttlSeconds,
    uint8_t r1csVerified, char *out_tx_hash, size_t out_len);

int aealsf_security_manager_isDeviceAuthenticated(
    const aealsf_rpc_context_t *ctx, const char *deviceId, char *out_tx_hash,
    size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
