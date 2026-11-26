"""Prometheus metrics (process-local registry so tests can create many apps)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        self.http_requests = Counter(
            "vaultgate_http_requests_total",
            "HTTP requests by route template and status",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.http_latency = Histogram(
            "vaultgate_http_request_duration_seconds",
            "HTTP request latency by route template",
            ["method", "route"],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=self.registry,
        )
        self.logins = Counter(
            "vaultgate_auth_logins_total",
            "Login attempts by outcome",
            ["outcome"],
            registry=self.registry,
        )
        self.refresh_reuse = Counter(
            "vaultgate_auth_refresh_reuse_total",
            "Refresh-token reuse detections (likely token theft)",
            registry=self.registry,
        )
        self.rate_limited = Counter(
            "vaultgate_rate_limited_total",
            "Requests rejected by the rate limiter",
            ["bucket"],
            registry=self.registry,
        )
        self.secret_ops = Counter(
            "vaultgate_secret_operations_total",
            "Secret operations",
            ["op"],
            registry=self.registry,
        )
