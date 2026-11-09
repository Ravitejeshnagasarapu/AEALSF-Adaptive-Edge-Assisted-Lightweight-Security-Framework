from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from api.schemas.models import EdgeStatusUpdateRequest

router = APIRouter(prefix="/edge", tags=["edge"])


@router.get("/nodes")
def get_edge_nodes(request: Request):
    rt = request.app.state.runtime
    return {
        "nodes": [tel.to_dict() for tel in rt.edge_cluster.monitor.nodes.values()],
        "failover_events": rt.edge_cluster.failover_manager.failover_events,
    }


@router.put("/nodes/status")
def update_edge_node_status(req: EdgeStatusUpdateRequest, request: Request):
    rt = request.app.state.runtime
    if req.edge_node_id not in rt.edge_cluster.monitor.nodes:
        raise HTTPException(
            status_code=404, detail=f"Unknown edge node {req.edge_node_id}"
        )
    rt.edge_cluster.monitor.set_node_availability(req.edge_node_id, req.online)
    if req.cpu_utilization_percent is not None:
        rt.edge_cluster.monitor.nodes[req.edge_node_id].cpu_utilization_percent = (
            req.cpu_utilization_percent
        )
    return {
        "status": "updated",
        "node": rt.edge_cluster.monitor.nodes[req.edge_node_id].to_dict(),
    }
