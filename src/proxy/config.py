"""Configuration settings for the Agentic API Security Proxy.

Configures upstream base URL, timeouts, and server binding via environment variables
with safe default values for local operation.
"""
import os
from pydantic import BaseModel, Field


class ProxyConfig(BaseModel):
    """Runtime configuration for the security proxy."""
    upstream_base_url: str = Field(
        default_factory=lambda: os.getenv("UPSTREAM_BASE_URL", "http://127.0.0.1:8001"),
        description="Base URL of the protected upstream mock backend.",
    )
    connect_timeout_sec: float = Field(
        default_factory=lambda: float(os.getenv("UPSTREAM_CONNECT_TIMEOUT_SEC", "2.0")),
        description="Maximum seconds to wait for initial TCP connection to upstream.",
    )
    read_timeout_sec: float = Field(
        default_factory=lambda: float(os.getenv("UPSTREAM_READ_TIMEOUT_SEC", "5.0")),
        description="Maximum seconds to wait for complete response from upstream.",
    )
    proxy_host: str = Field(
        default_factory=lambda: os.getenv("PROXY_HOST", "127.0.0.1"),
        description="Local host address to bind the proxy server.",
    )
    proxy_port: int = Field(
        default_factory=lambda: int(os.getenv("PROXY_PORT", "8000")),
        description="Port for the proxy server.",
    )
    internal_service_key: str = Field(
        default_factory=lambda: os.getenv("INTERNAL_SERVICE_KEY", "dev-proxy-internal-service-key-998877"),
        description="Shared demonstration internal key for authenticating proxy-to-upstream communication.",
    )



# Global configuration instance
config = ProxyConfig()
