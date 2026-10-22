"""Tests for upstream network failures, timeouts, and safe error masking."""
import pytest
import httpx
from httpx import ASGITransport

from src.proxy.app import app as proxy_app, get_upstream_client
from src.proxy.client import UpstreamClient

AUTH_HEADER = {"Authorization": "Bearer demo-token-support-alpha"}


class FaultyTransport(httpx.AsyncBaseTransport):
    """Mock transport that simulates network faults for testing error resilience."""

    def __init__(self, fault_type: str) -> None:
        self.fault_type = fault_type

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.fault_type == "connect_error":
            raise httpx.ConnectError("Simulated TCP connection failure", request=request)
        elif self.fault_type == "read_timeout":
            raise httpx.ReadTimeout("Simulated socket read timeout", request=request)
        elif self.fault_type == "connect_timeout":
            raise httpx.ConnectTimeout("Simulated connection timeout", request=request)
        raise RuntimeError("Unknown fault type")


@pytest.mark.asyncio
async def test_upstream_connection_failure_handled_cleanly() -> None:
    """Verify that upstream connection failures return 502 without stack traces."""
    faulty_client = httpx.AsyncClient(
        transport=FaultyTransport("connect_error"),
        base_url="http://127.0.0.1:8001",
    )
    mocked_forwarder = UpstreamClient(client=faulty_client)
    proxy_app.dependency_overrides[get_upstream_client] = lambda: mocked_forwarder

    try:
        transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            payload = {
                "request_id": "req-fault-conn",
                "action": "get_order_details",
                "resource_id": "ORD-1001",
            }
            response = await client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
            assert response.status_code == 502

            body = response.json()
            assert body["request_id"] == "req-fault-conn"
            assert body["status"] == "ERROR"
            assert body["error"] == "UPSTREAM_UNAVAILABLE"
            assert "traceback" not in response.text.lower()
            assert "exception" not in response.text.lower()
            assert body["detail"] == "Upstream backend service is unreachable or offline."
    finally:
        proxy_app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_upstream_read_timeout_handled_cleanly() -> None:
    """Verify that upstream read timeouts return 504 without stack traces."""
    faulty_client = httpx.AsyncClient(
        transport=FaultyTransport("read_timeout"),
        base_url="http://127.0.0.1:8001",
    )
    mocked_forwarder = UpstreamClient(client=faulty_client)
    proxy_app.dependency_overrides[get_upstream_client] = lambda: mocked_forwarder

    try:
        transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            payload = {
                "request_id": "req-fault-timeout",
                "action": "get_order_details",
                "resource_id": "ORD-1001",
            }
            response = await client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
            assert response.status_code == 504

            body = response.json()
            assert body["request_id"] == "req-fault-timeout"
            assert body["status"] == "ERROR"
            assert body["error"] == "UPSTREAM_READ_TIMEOUT"
            assert "traceback" not in response.text.lower()
            assert "exception" not in response.text.lower()
            assert body["detail"] == "Upstream service took too long to respond."
    finally:
        proxy_app.dependency_overrides.clear()
