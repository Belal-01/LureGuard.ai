"""
GET /metrics — Prometheus metrics endpoint.
"""
from fastapi import APIRouter, Response
from prometheus_client import (
    Counter, Histogram, Gauge, Info,
    generate_latest, CONTENT_TYPE_LATEST,
)

router = APIRouter(tags=["metrics"])

# ── Metrics definitions ──────────────────────────────────
events_total = Counter(
    "lureguard_events_total", "Total events ingested", ["source"]
)
decisions_total = Counter(
    "lureguard_decisions_total", "Total decisions made", ["decision"]
)
infer_latency = Histogram(
    "lureguard_infer_latency_seconds", "ML inference latency",
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1],
)
dnat_active = Gauge(
    "lureguard_enforcer_rules_active", "Active DNAT rules"
)
model_info = Info("lureguard_model", "Active ML model metadata")


@router.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
