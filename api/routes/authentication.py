from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from api.schemas.models import AuthenticateDeviceRequest

router = APIRouter(prefix="/authentication", tags=["authentication"])


@router.post("/nizk")
def authenticate_device(req: AuthenticateDeviceRequest, request: Request):
    rt = request.app.state.runtime
    dev = rt.device_manager.get_device(req.device_id)
    if dev is None:
        rt.metrics_collector.record_security_event(
            "UNREGISTERED_AUTH_ATTEMPT", req.device_id, True, "Unknown device_id"
        )
        raise HTTPException(
            status_code=404, detail=f"Device {req.device_id} is not registered."
        )

    ok, latency_ms, prove_ms, verify_ms, auth_bytes, msg = (
        dev.task_manager.authenticate_device_on_chain(
            allow_session_reuse=req.allow_session_reuse
        )
    )
    if not ok:
        rt.metrics_collector.record_security_event(
            "NIZK_AUTH_FAILURE", req.device_id, True, msg
        )
        raise HTTPException(status_code=401, detail=msg)

    return {
        "authenticated": True,
        "device_id": req.device_id,
        "auth_latency_ms": round(latency_ms, 3),
        "nizk_prove_ms": round(prove_ms, 3),
        "nizk_verify_ms": round(verify_ms, 3),
        "auth_wire_bytes": auth_bytes,
        "session_token_id": (
            dev.wallet.active_session_token.token_id
            if dev.wallet.active_session_token
            else None
        ),
        "message": msg,
    }
