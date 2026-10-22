"""Tests for the Proxy-to-Upstream Internal Boundary and Security Controls.

Covers mandatory acceptance criteria:
13. A request without the internal service credential cannot access protected upstream operations.
14. The proxy passes trusted tenant context only after successful authentication and authorization.
15. Authorization failures do not call the upstream service.
"""
from typing import List
import pytest
import httpx
from httpx import ASGITransport

from src.upstream.app import app as upstream_app
from src.proxy.app import app as proxy_app, get_upstream_client
from src.proxy.client import UpstreamClient


@pytest.mark.asyncio
async def test_direct_upstream_access_without_service_credential_rejected(
    direct_upstream_client: httpx.AsyncClient,
) -> None:
    """Criterion 13: Direct caller requests to upstream without internal service key return 401."""
    # 1. Missing internal service key on GET
    resp_no_key = await direct_upstream_client.get(
        "/api/v1/orders/ORD-1001",
        headers={"X-Tenant-ID": "tenant-alpha"},
    )
    assert resp_no_key.status_code == 401
    assert "Direct or unauthorized access" in resp_no_key.text

    # 2. Invalid internal service key on GET
    resp_bad_key = await direct_upstream_client.get(
        "/api/v1/orders/ORD-1001",
        headers={
            "X-Tenant-ID": "tenant-alpha",
            "X-Internal-Service-Key": "attacker-fake-service-key",
        },
    )
    assert resp_bad_key.status_code == 401

    # 3. Missing internal service key on POST
    resp_post_no_key = await direct_upstream_client.post(
        "/api/v1/orders",
        json={
            "customer_name": "Direct Attacker",
            "item": "Bypassed Proxy Order",
            "quantity": 1,
            "total_price": 50.0,
        },
        headers={"X-Tenant-ID": "tenant-alpha"},
    )
    assert resp_post_no_key.status_code == 401


@pytest.mark.asyncio
async def test_proxy_passes_trusted_tenant_context_to_upstream() -> None:
    """Criterion 14: Verify that proxy injects verified tenant_id and internal service key."""
    captured_requests: List[httpx.Request] = []

    class InspectingTransport(httpx.AsyncBaseTransport):
        def __init__(self, inner_app: object) -> None:
            self.inner_transport = ASGITransport(app=inner_app)  # type: ignore[arg-type]

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return await self.inner_transport.handle_async_request(request)

    custom_transport = InspectingTransport(upstream_app)
    raw_client = httpx.AsyncClient(transport=custom_transport, base_url="http://127.0.0.1:8001")
    forwarder = UpstreamClient(client=raw_client)
    proxy_app.dependency_overrides[get_upstream_client] = lambda: forwarder

    try:
        transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            headers = {"Authorization": "Bearer demo-token-support-beta"}
            payload = {
                "request_id": "req-verify-headers",
                "action": "get_order_details",
                "resource_id": "ORD-1003",
            }
            resp = await client.post("/proxy/v1/action", json=payload, headers=headers)
            assert resp.status_code == 200

            # Inspect captured upstream request
            assert len(captured_requests) == 1
            up_req = captured_requests[0]
            assert up_req.headers.get("X-Tenant-ID") == "tenant-beta"
            assert up_req.headers.get("X-Internal-Service-Key") is not None
            assert len(up_req.headers.get("X-Internal-Service-Key", "")) > 10
    finally:
        proxy_app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_authorization_failure_does_not_call_upstream() -> None:
    """Criterion 15: Verify that unauthorized requests (RBAC blocked) never contact upstream."""
    calls_received: List[str] = []

    class CallTrackingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            calls_received.append(str(request.url))
            return httpx.Response(status_code=200, json={})

    tracking_client = httpx.AsyncClient(transport=CallTrackingTransport(), base_url="http://127.0.0.1:8001")
    forwarder = UpstreamClient(client=tracking_client)
    proxy_app.dependency_overrides[get_upstream_client] = lambda: forwarder

    try:
        transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            # Authenticated as readonly_analyst trying to create an order
            headers = {"Authorization": "Bearer demo-token-analyst-alpha"}
            payload = {
                "request_id": "req-blocked-rbac",
                "action": "create_order",
                "parameters": {
                    "customer_name": "Blocked Caller",
                    "item": "Unreached Item",
                    "quantity": 1,
                    "total_price": 100.0,
                },
            }
            response = await client.post("/proxy/v1/action", json=payload, headers=headers)
            assert response.status_code == 403

            # CRITICAL CHECK: Upstream must have ZERO requests!
            assert len(calls_received) == 0, "Upstream service was contacted when it should have been short-circuited!"
    finally:
        proxy_app.dependency_overrides.clear()
