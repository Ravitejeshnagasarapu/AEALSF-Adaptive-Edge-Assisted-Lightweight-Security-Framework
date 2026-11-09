from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from api.schemas.models import DeviceRegisterRequest, DeviceTelemetryUpdateRequest

router = APIRouter(prefix="/devices", tags=["devices"])


@router.post("/register")
def register_device(req: DeviceRegisterRequest, request: Request):
    rt = request.app.state.runtime
    try:
        dev = rt.device_manager.register_new_device(
            device_id=req.device_id,
            device_name=req.device_name,
            device_description=req.device_description,
            hardware_model=req.hardware_model,
            initial_cpu_percent=req.initial_cpu_percent,
            initial_free_ram_kb=req.initial_free_ram_kb,
            initial_battery_percent=req.initial_battery_percent,
            initial_latency_ms=req.initial_latency_ms,
            initial_bandwidth_mbps=req.initial_bandwidth_mbps,
        )
    except Exception as exc:
        rt.metrics_collector.record_security_event(
            "DEVICE_REGISTRATION_REJECTED", req.device_id, True, str(exc)
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    pub = dev.wallet.get_public_identity()
    return {
        "status": "registered",
        "device_id": dev.device_id,
        "wallet_address": pub.blockchain_address,
        "onchain_unique_id_hash": dev.wallet.onchain_unique_id_hash,
        "nizk_pk_fingerprint": pub.nizk_pk_fingerprint,
        "telemetry": dev.resource_monitor.capture_snapshot().to_dict(),
    }


@router.get("")
def list_devices(request: Request):
    rt = request.app.state.runtime
    items = []
    for dev_id, dev in rt.device_manager.devices.items():
        rep = rt.blockchain_client.dvrc.profiles.get(dev_id)
        items.append(
            {
                "device_id": dev_id,
                "device_name": dev.wallet.device_name,
                "hardware_model": dev.wallet.hardware_model,
                "wallet_address": dev.wallet.wallet_address,
                "onchain_unique_id_hash": dev.wallet.onchain_unique_id_hash,
                "telemetry": dev.resource_monitor.capture_snapshot().to_dict(),
                "reputation_score": round(rep.reputation_score, 2) if rep else 75.0,
                "trust_state": rep.trust_state if rep else "ACTIVE",
            }
        )
    return {"count": len(items), "devices": items}


@router.put("/{device_id}/telemetry")
def update_device_telemetry(
    device_id: str, req: DeviceTelemetryUpdateRequest, request: Request
):
    rt = request.app.state.runtime
    dev = rt.device_manager.get_device(device_id)
    if dev is None:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")
    mon = dev.resource_monitor
    mon.cpu_utilization_percent = req.cpu_utilization_percent
    mon.available_ram_kb = req.available_ram_kb
    mon.battery_percent = req.battery_percent
    mon.network_latency_ms = req.network_latency_ms
    mon.available_bandwidth_mbps = req.available_bandwidth_mbps
    return {"status": "updated", "telemetry": mon.capture_snapshot().to_dict()}
