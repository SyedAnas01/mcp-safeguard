"""OpenTelemetry tracing for mcp-safeguard scan operations."""

from __future__ import annotations

import functools
from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from mcp_shield import __version__

_tracer: trace.Tracer | None = None


def setup_tracing(
    service_name: str = "mcp-safeguard",
    otlp_endpoint: str | None = None,
) -> None:
    """
    Initialize OpenTelemetry tracing.

    Args:
        service_name: Service name for traces.
        otlp_endpoint: OTLP exporter endpoint, or None for console.
    """
    global _tracer

    resource = Resource.create({"service.name": service_name, "service.version": __version__})
    provider = TracerProvider(resource=resource)

    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except Exception:
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        # In production without OTLP, use no-op exporter to avoid console noise
        pass

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(service_name)


def get_tracer() -> trace.Tracer:
    """Return the configured tracer, initializing with defaults if needed."""
    global _tracer
    if _tracer is None:
        setup_tracing()
    return _tracer  # type: ignore[return-value]


@contextmanager
def scan_span(
    operation: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[trace.Span, None, None]:
    """
    Context manager that wraps a scan operation in an OTel span.

    Args:
        operation: Span name (e.g., "scan.prompt_injection").
        attributes: Optional span attributes.

    Yields:
        The active span.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(operation) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, str(value))
        yield span


def trace_scan_operation(operation_name: str) -> Callable:
    """
    Decorator that wraps an async function in a tracing span.

    Args:
        operation_name: Name for the trace span.

    Returns:
        Decorator function.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer()
            with tracer.start_as_current_span(operation_name) as span:
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("outcome", "success")
                    return result
                except Exception as e:
                    span.set_attribute("outcome", "error")
                    span.set_attribute("error.message", str(e))
                    raise

        return wrapper

    return decorator
