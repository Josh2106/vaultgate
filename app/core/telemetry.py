"""OpenTelemetry tracing (opt-in via ``VG_OTEL_ENABLED``)."""

from __future__ import annotations

from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.core.config import Settings


def setup_tracing(
    app: FastAPI, settings: Settings, *, processor: SpanProcessor | None = None
) -> TracerProvider | None:
    if not settings.otel_enabled:
        return None
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": settings.otel_service_name,
                "deployment.environment": settings.environment.value,
            }
        )
    )
    if processor is None:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = (
            OTLPSpanExporter(endpoint=settings.otel_exporter_endpoint)
            if settings.otel_exporter_endpoint
            else OTLPSpanExporter()
        )
        processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)
    FastAPIInstrumentor.instrument_app(
        app, tracer_provider=provider, excluded_urls="healthz,readyz,metrics"
    )
    trace.set_tracer_provider(provider)
    return provider
