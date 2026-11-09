from __future__ import annotations
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=64)
    device_name: str = Field(default="ML307A Module", min_length=1, max_length=128)
    device_description: str = Field(default="IoT Cat.1 Embedded Module", max_length=256)
    hardware_model: str = Field(default="L610-CN")
    initial_cpu_percent: float = Field(default=34.0, ge=0.0, le=100.0)
    initial_free_ram_kb: float = Field(default=1150.0, gt=0.0, le=2048.0)
    initial_battery_percent: float = Field(default=84.0, ge=1.0, le=100.0)
    initial_latency_ms: float = Field(default=38.64, ge=1.0, le=2000.0)
    initial_bandwidth_mbps: float = Field(default=94.12, gt=0.1, le=1000.0)


class DeviceTelemetryUpdateRequest(BaseModel):
    cpu_utilization_percent: float = Field(..., ge=0.0, le=100.0)
    available_ram_kb: float = Field(..., gt=0.0, le=2048.0)
    battery_percent: float = Field(..., ge=0.0, le=100.0)
    network_latency_ms: float = Field(..., ge=0.5, le=2000.0)
    available_bandwidth_mbps: float = Field(..., gt=0.1, le=1000.0)


class AuthenticateDeviceRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    allow_session_reuse: bool = Field(default=True)


class TaskExecuteRequest(BaseModel):
    device_id: str = Field(..., min_length=1)
    telemetry_values: List[int] = Field(..., min_items=1, max_items=64)
    payload_text: str = Field(default="SENSOR_PACKET_STREAM_512B")
    adaptive_enabled: bool = Field(default=True)
    priority: str = Field(default="NORMAL")


class EdgeStatusUpdateRequest(BaseModel):
    edge_node_id: str = Field(..., min_length=1)
    online: bool = Field(...)
    cpu_utilization_percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)
