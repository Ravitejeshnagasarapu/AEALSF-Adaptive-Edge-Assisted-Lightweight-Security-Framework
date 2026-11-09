from __future__ import annotations
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@router.get("/summary")
def get_monitoring_summary(request: Request):
    rt = request.app.state.runtime
    samples = rt.perf_monitor.samples
    baseline_samples = [s for s in samples if s.configuration == "BASELINE"]
    proposed_samples = [s for s in samples if s.configuration == "PROPOSED_AEALSF"]

    return {
        "total_samples": len(samples),
        "overall": rt.metrics_collector.summarize_samples(samples),
        "baseline": rt.metrics_collector.summarize_samples(baseline_samples),
        "proposed_aealsf": rt.metrics_collector.summarize_samples(proposed_samples),
        "security_events": rt.metrics_collector.security_events,
    }


@router.get("/metrics", response_class=PlainTextResponse)
def get_prometheus_metrics(request: Request):
    rt = request.app.state.runtime
    return rt.metrics_collector.export_prometheus_metrics()
