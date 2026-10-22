"""Asynchronous HTTPX forwarding client for upstream communication.

SECURITY ARCHITECTURE NOTE:
- Never accepts arbitrary destination URLs or hostnames from client requests.
- All outbound paths and HTTP methods are deterministically hardcoded.
- Injects internal service credentials and verified tenant context into upstream requests.
- Handles upstream connection drops, timeouts, and auth errors safely without leaking internals.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional
import httpx

from src.proxy.config import config


@dataclass
class UpstreamResult:
    """Normalized response container from upstream interactions."""
    status_code: int
    data: Optional[Any] = None
    error_code: Optional[str] = None
    detail: Optional[str] = None


class UpstreamClient:
    """Dedicated async client for communicating with the mock upstream backend."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        internal_service_key: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.base_url = (base_url or config.upstream_base_url).rstrip("/")
        self.connect_timeout = connect_timeout or config.connect_timeout_sec
        self.read_timeout = read_timeout or config.read_timeout_sec
        self.internal_service_key = internal_service_key or config.internal_service_key
        self._external_client = client
        self._internal_client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._external_client is not None:
            return self._external_client
        if self._internal_client is None or self._internal_client.is_closed:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
            timeouts = httpx.Timeout(
                connect=self.connect_timeout,
                read=self.read_timeout,
                write=self.connect_timeout,
                pool=self.connect_timeout,
            )
            self._internal_client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=timeouts,
                limits=limits,
            )
        return self._internal_client

    async def close(self) -> None:
        """Close internally managed HTTP client sessions."""
        if self._internal_client and not self._internal_client.is_closed:
            await self._internal_client.aclose()
            self._internal_client = None

    def _build_internal_headers(self, tenant_id: str) -> Dict[str, str]:
        """Construct server-to-server headers with internal key and verified tenant context."""
        return {
            "X-Internal-Service-Key": self.internal_service_key,
            "X-Tenant-ID": tenant_id,
        }

    async def get_order_details(self, resource_id: str, tenant_id: str) -> UpstreamResult:
        """Forward a get_order_details action to GET /api/v1/orders/{resource_id} with tenant context."""
        client = self._get_client()
        target_path = f"/api/v1/orders/{resource_id}"
        headers = self._build_internal_headers(tenant_id)

        try:
            response = await client.get(target_path, headers=headers)
            try:
                body = response.json()
            except Exception:
                body = response.text

            if response.status_code == 200:
                return UpstreamResult(status_code=200, data=body)
            elif response.status_code == 403:
                return UpstreamResult(
                    status_code=403,
                    error_code="ERR_BOLA_VIOLATION",
                    detail="Access denied: Resource belongs to a different tenant.",
                    data=body if isinstance(body, dict) else None,
                )
            elif response.status_code == 404:
                return UpstreamResult(
                    status_code=404,
                    error_code="ORDER_NOT_FOUND",
                    detail=f"Resource '{resource_id}' was not found in upstream.",
                    data=body if isinstance(body, dict) else None,
                )
            elif response.status_code == 401:
                return UpstreamResult(
                    status_code=502,
                    error_code="UPSTREAM_AUTH_FAILURE",
                    detail="Upstream rejected internal proxy service credentials.",
                    data=None,
                )
            else:
                return UpstreamResult(
                    status_code=response.status_code,
                    error_code="UPSTREAM_NON_200",
                    detail=f"Upstream returned HTTP {response.status_code}.",
                    data=body if isinstance(body, dict) else None,
                )

        except httpx.ConnectTimeout:
            return UpstreamResult(
                status_code=504,
                error_code="UPSTREAM_CONNECT_TIMEOUT",
                detail="Connection to backend service timed out.",
            )
        except httpx.ReadTimeout:
            return UpstreamResult(
                status_code=504,
                error_code="UPSTREAM_READ_TIMEOUT",
                detail="Upstream service took too long to respond.",
            )
        except httpx.ConnectError:
            return UpstreamResult(
                status_code=502,
                error_code="UPSTREAM_UNAVAILABLE",
                detail="Upstream backend service is unreachable or offline.",
            )
        except Exception:
            return UpstreamResult(
                status_code=502,
                error_code="UPSTREAM_COMMUNICATION_ERROR",
                detail="An error occurred while communicating with the upstream service.",
            )

    async def create_order(self, order_parameters: Dict[str, Any], tenant_id: str) -> UpstreamResult:
        """Forward a create_order action to POST /api/v1/orders with verified tenant context."""
        client = self._get_client()
        target_path = "/api/v1/orders"
        headers = self._build_internal_headers(tenant_id)

        try:
            response = await client.post(target_path, json=order_parameters, headers=headers)
            try:
                body = response.json()
            except Exception:
                body = response.text

            if response.status_code in (200, 201):
                return UpstreamResult(status_code=response.status_code, data=body)
            elif response.status_code == 422:
                return UpstreamResult(
                    status_code=422,
                    error_code="UPSTREAM_VALIDATION_ERROR",
                    detail="Upstream rejected order parameters as invalid.",
                    data=body if isinstance(body, dict) else None,
                )
            elif response.status_code == 401:
                return UpstreamResult(
                    status_code=502,
                    error_code="UPSTREAM_AUTH_FAILURE",
                    detail="Upstream rejected internal proxy service credentials.",
                    data=None,
                )
            else:
                return UpstreamResult(
                    status_code=response.status_code,
                    error_code="UPSTREAM_NON_200",
                    detail=f"Upstream returned HTTP {response.status_code}.",
                    data=body if isinstance(body, dict) else None,
                )

        except httpx.ConnectTimeout:
            return UpstreamResult(
                status_code=504,
                error_code="UPSTREAM_CONNECT_TIMEOUT",
                detail="Connection to backend service timed out.",
            )
        except httpx.ReadTimeout:
            return UpstreamResult(
                status_code=504,
                error_code="UPSTREAM_READ_TIMEOUT",
                detail="Upstream service took too long to respond.",
            )
        except httpx.ConnectError:
            return UpstreamResult(
                status_code=502,
                error_code="UPSTREAM_UNAVAILABLE",
                detail="Upstream backend service is unreachable or offline.",
            )
        except Exception:
            return UpstreamResult(
                status_code=502,
                error_code="UPSTREAM_COMMUNICATION_ERROR",
                detail="An error occurred while communicating with the upstream service.",
            )
