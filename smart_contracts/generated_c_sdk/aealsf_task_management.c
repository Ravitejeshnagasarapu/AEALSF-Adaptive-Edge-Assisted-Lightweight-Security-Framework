#include "aealsf_task_management.h"
#include <stdio.h>
#include <string.h>


int aealsf_support_rlp_rpc_send(const aealsf_rpc_context_t *ctx,
                                const char *method_selector,
                                const char *json_payload, char *response_buf,
                                size_t response_buf_len);

int aealsf_task_management_createTask(const aealsf_rpc_context_t *ctx,
                                      const char *taskId, const char *deviceId,
                                      const char *assignedNodeId, uint8_t mode,
                                      const uint8_t *inputPayloadHash,
                                      char *out_tx_hash, size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"TaskManagement\",\"method\":\"createTask\","
           "\"selector\":\"0x137dcceb\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x137dcceb", payload, out_tx_hash,
                                     out_len);
}

int aealsf_task_management_submitTaskResult(
    const aealsf_rpc_context_t *ctx, const char *taskId,
    const char *executorNodeId, const uint8_t *resultPayloadHash,
    const uint8_t *edgeReceiptSignatureHash, char *out_tx_hash,
    size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"TaskManagement\",\"method\":\"submitTaskResult\","
           "\"selector\":\"0x0435cbf3\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0x0435cbf3", payload, out_tx_hash,
                                     out_len);
}

int aealsf_task_management_verifyRetrievedResult(
    const aealsf_rpc_context_t *ctx, const char *taskId,
    const uint8_t *candidateResultHash, char *out_tx_hash, size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"TaskManagement\",\"method\":"
           "\"verifyRetrievedResult\",\"selector\":\"0xfd53b628\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0xfd53b628", payload, out_tx_hash,
                                     out_len);
}

int aealsf_task_management_getTask(const aealsf_rpc_context_t *ctx,
                                   const char *taskId, char *out_tx_hash,
                                   size_t out_len) {
  if (!ctx || !out_tx_hash || out_len == 0) {
    return -1;
  }
  char payload[512];
  snprintf(payload, sizeof(payload),
           "{\"contract\":\"TaskManagement\",\"method\":\"getTask\","
           "\"selector\":\"0xe1b08a5c\"}");
  return aealsf_support_rlp_rpc_send(ctx, "0xe1b08a5c", payload, out_tx_hash,
                                     out_len);
}
