from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from api.schemas.models import TaskExecuteRequest

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.post("/execute")
def execute_task(req: TaskExecuteRequest, request: Request):
    rt = request.app.state.runtime
    dev = rt.device_manager.get_device(req.device_id)
    if dev is None:
        raise HTTPException(
            status_code=404, detail=f"Device {req.device_id} not registered."
        )

    raw_bytes = req.payload_text.encode("utf-8")
    if len(raw_bytes) < 512:
        raw_bytes = raw_bytes.ljust(512, b"X")

    try:
        res = dev.task_manager.execute_telemetry_and_compression_task(
            telemetry_values=req.telemetry_values,
            raw_packet_bytes=raw_bytes,
            adaptive_enabled=req.adaptive_enabled,
            priority=req.priority,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "task_id": res.task_id,
        "device_id": res.device_id,
        "selected_mode": res.selected_mode,
        "executed_on_node": res.executed_on_node,
        "decrypted_aggregate_value": res.decrypted_aggregate_value,
        "compressed_size_bytes": res.compressed_size_bytes,
        "onchain_result_hash": res.onchain_result_hash,
        "offchain_integrity_verified": res.offchain_integrity_verified,
        "used_local_fallback": res.used_local_fallback,
        "performance": res.performance_sample.to_dict(),
        "decision": res.decision_record.to_dict() if res.decision_record else None,
    }


@router.get("/decisions")
def list_decisions(request: Request):
    rt = request.app.state.runtime
    return {
        "mode_distribution": rt.decision_engine.get_mode_distribution_summary(),
        "recent_decisions": [
            d.to_dict() for d in rt.decision_engine.decision_history[-50:]
        ],
    }
