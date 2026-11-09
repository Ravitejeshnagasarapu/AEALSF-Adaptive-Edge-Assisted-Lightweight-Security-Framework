#ifndef AEALSF_EMBEDDED_TASK_MANAGEMENT_H
#define AEALSF_EMBEDDED_TASK_MANAGEMENT_H

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

int aealsf_task_management_createTask(const aealsf_rpc_context_t *ctx,
                                      const char *taskId, const char *deviceId,
                                      const char *assignedNodeId, uint8_t mode,
                                      const uint8_t *inputPayloadHash,
                                      char *out_tx_hash, size_t out_len);

int aealsf_task_management_submitTaskResult(
    const aealsf_rpc_context_t *ctx, const char *taskId,
    const char *executorNodeId, const uint8_t *resultPayloadHash,
    const uint8_t *edgeReceiptSignatureHash, char *out_tx_hash, size_t out_len);

int aealsf_task_management_verifyRetrievedResult(
    const aealsf_rpc_context_t *ctx, const char *taskId,
    const uint8_t *candidateResultHash, char *out_tx_hash, size_t out_len);

int aealsf_task_management_getTask(const aealsf_rpc_context_t *ctx,
                                   const char *taskId, char *out_tx_hash,
                                   size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
