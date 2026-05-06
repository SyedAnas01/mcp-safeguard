# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir build && \
    python -m build --wheel && \
    pip install --no-cache-dir dist/*.whl

# Stage 2: Runtime image
FROM python:3.12-slim AS runtime

WORKDIR /app

# Non-root user for security
RUN groupadd -r mcpshield && useradd -r -g mcpshield -d /app -s /bin/false mcpshield

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source
COPY --from=builder /app/src ./src

# Report directory
RUN mkdir -p /tmp/mcp-shield-reports && chown mcpshield:mcpshield /tmp/mcp-shield-reports

COPY .env.example .env.example

USER mcpshield

ENV MCP_SHIELD_HOST=0.0.0.0
ENV MCP_SHIELD_PORT=8000
ENV MCP_SHIELD_REPORT_DIR=/tmp/mcp-shield-reports
ENV PYTHONPATH=/app/src

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=5)"

CMD ["python", "-m", "fastmcp", "run", "src/mcp_shield/server.py", "--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
