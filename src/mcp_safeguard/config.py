"""Configuration management via environment variables."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MCP_SAFEGUARD_",
        case_sensitive=False,
    )

    # Server
    host: str = Field(default="0.0.0.0", description="Server bind host")
    port: int = Field(default=8000, description="Server bind port")
    debug: bool = Field(default=False, description="Enable debug mode")

    # Security
    api_key: str | None = Field(default=None, description="API key for authentication")
    allowed_origins: list[str] = Field(default=["*"], description="Allowed CORS origins")
    max_scan_timeout: int = Field(default=30, description="Maximum scan timeout in seconds")

    # Rate limiting
    rate_limit_requests: int = Field(default=100, description="Max requests per window")
    rate_limit_window: int = Field(default=60, description="Rate limit window in seconds")

    # Storage
    scan_history_max: int = Field(default=1000, description="Max scan results to retain in memory")
    report_dir: str = Field(
        default="/tmp/mcp-safeguard-reports", description="Directory for report files"
    )

    # Observability
    otlp_endpoint: str | None = Field(default=None, description="OpenTelemetry OTLP endpoint")
    prometheus_enabled: bool = Field(default=True, description="Enable Prometheus metrics endpoint")
    log_level: str = Field(default="INFO", description="Log level")

    # Scanning
    enable_network_scan: bool = Field(default=True, description="Enable network/endpoint scanning")
    ssrf_allowlist: list[str] = Field(
        default=["localhost", "127.0.0.1", "::1"],
        description="Allowed scan targets (SSRF protection)",
    )
    max_tool_descriptions_length: int = Field(
        default=50_000,
        description="Max characters to accept in tool JSON input",
    )


settings = Settings()
