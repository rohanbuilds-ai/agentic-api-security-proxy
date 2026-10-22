"""Tests for request forwarding, order lookup, order creation, and missing resources."""
import pytest
import httpx

AUTH_HEADER = {"Authorization": "Bearer demo-token-support-alpha"}


@pytest.mark.asyncio
async def test_get_order_details_forwarding_success(proxy_test_client: httpx.AsyncClient) -> None:
    """Verify that a valid get_order_details action is forwarded and returns 200 OK."""
    payload = {
        "request_id": "req-trace-101",
        "action": "get_order_details",
        "resource_id": "ORD-1001",
        "agent_id": "demo-bot-1",
        "role": "untrusted-role-label",
        "tenant_id": "untrusted-tenant-label",
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
    assert response.status_code == 200

    body = response.json()
    assert body["request_id"] == "req-trace-101"
    assert body["action"] == "get_order_details"
    assert body["status"] == "SUCCESS"
    assert body["upstream_status"] == 200
    assert body["data"]["order_id"] == "ORD-1001"
    assert body["data"]["customer_name"] == "Alice Smith"
    assert body["data"]["item"] == "Security Audit Handbook"
    assert body["data"]["tenant_id"] == "tenant-alpha"
    assert body["error"] is None


@pytest.mark.asyncio
async def test_create_order_forwarding_success(proxy_test_client: httpx.AsyncClient) -> None:
    """Verify that a valid create_order action is forwarded and creates an order on upstream."""
    payload = {
        "request_id": "req-trace-102",
        "action": "create_order",
        "parameters": {
            "customer_name": "Diana Prince",
            "item": "Threat Modeling Workshop Ticket",
            "quantity": 2,
            "total_price": 450.00,
            "notes": "Urgent registration",
        },
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
    assert response.status_code == 200

    body = response.json()
    assert body["request_id"] == "req-trace-102"
    assert body["action"] == "create_order"
    assert body["status"] == "SUCCESS"
    assert body["upstream_status"] == 201
    assert body["data"]["customer_name"] == "Diana Prince"
    assert body["data"]["item"] == "Threat Modeling Workshop Ticket"
    assert body["data"]["tenant_id"] == "tenant-alpha"
    assert body["data"]["order_id"].startswith("ORD-")
    assert body["data"]["status"] == "PENDING"


@pytest.mark.asyncio
async def test_get_nonexistent_order_returns_404(proxy_test_client: httpx.AsyncClient) -> None:
    """Verify that querying an order that does not exist anywhere returns a standardized 404 response."""
    payload = {
        "request_id": "req-trace-103",
        "action": "get_order_details",
        "resource_id": "ORD-9999",
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
    assert response.status_code == 404

    body = response.json()
    assert body["request_id"] == "req-trace-103"
    assert body["status"] == "ERROR"
    assert body["upstream_status"] == 404
    assert body["error"] == "ORDER_NOT_FOUND"
    assert "ORD-9999" in body["detail"]
