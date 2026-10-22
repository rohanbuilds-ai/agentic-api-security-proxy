"""Tests for Tenant Boundary Isolation and Broken Object Level Authorization (BOLA) Prevention.

Covers mandatory acceptance criteria:
9. An authenticated caller can read an order belonging to its own tenant.
10. A caller from tenant-alpha cannot read an order belonging to tenant-beta (403 Forbidden).
11. A caller from one tenant cannot create an order for another tenant by manipulating request fields.
12. Data-access queries consistently enforce tenant scoping.
"""
import pytest
import httpx
from src.schemas.order import OrderCreate
from src.upstream.store import order_store


# =========================================================================
# Tenant Isolation & BOLA Tests (Criteria 9-12)
# =========================================================================

@pytest.mark.asyncio
async def test_caller_can_read_order_in_own_tenant(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 9: Verify that agents can successfully access records within their own tenant."""
    # 1. Tenant Alpha accessing Tenant Alpha record (ORD-1001)
    alpha_headers = {"Authorization": "Bearer demo-token-support-alpha"}
    alpha_payload = {
        "request_id": "req-alpha-own",
        "action": "get_order_details",
        "resource_id": "ORD-1001",
    }
    alpha_resp = await proxy_test_client.post("/proxy/v1/action", json=alpha_payload, headers=alpha_headers)
    assert alpha_resp.status_code == 200
    alpha_body = alpha_resp.json()
    assert alpha_body["status"] == "SUCCESS"
    assert alpha_body["data"]["order_id"] == "ORD-1001"
    assert alpha_body["data"]["tenant_id"] == "tenant-alpha"

    # 2. Tenant Beta accessing Tenant Beta record (ORD-1003)
    beta_headers = {"Authorization": "Bearer demo-token-support-beta"}
    beta_payload = {
        "request_id": "req-beta-own",
        "action": "get_order_details",
        "resource_id": "ORD-1003",
    }
    beta_resp = await proxy_test_client.post("/proxy/v1/action", json=beta_payload, headers=beta_headers)
    assert beta_resp.status_code == 200
    beta_body = beta_resp.json()
    assert beta_body["status"] == "SUCCESS"
    assert beta_body["data"]["order_id"] == "ORD-1003"
    assert beta_body["data"]["tenant_id"] == "tenant-beta"


@pytest.mark.asyncio
async def test_cross_tenant_access_blocked_with_403(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 10: Verify that cross-tenant read access (BOLA/IDOR) is blocked with 403 Forbidden.

    ORD-1003 belongs to tenant-beta.
    A caller with demo-token-support-alpha (tenant-alpha) attempts to read ORD-1003.
    The proxy must reject the access with 403 Forbidden and NOT disclose tenant-beta data.
    """
    alpha_headers = {"Authorization": "Bearer demo-token-support-alpha"}
    cross_tenant_payload = {
        "request_id": "req-cross-tenant-read",
        "action": "get_order_details",
        "resource_id": "ORD-1003",  # Belongs to tenant-beta!
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=cross_tenant_payload, headers=alpha_headers)

    # Must fail with 403 Forbidden
    assert response.status_code == 403
    body = response.json()
    assert body["status"] == "ERROR"
    assert body["error"] == "ERR_BOLA_VIOLATION"
    assert "different tenant" in body["detail"] or "Cross-tenant" in body["detail"]
    # Verify no record data leaked
    assert body["data"] is None or "item" not in body["data"]


@pytest.mark.asyncio
async def test_client_cannot_create_order_for_another_tenant(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 11: Verify that client cannot create an order assigned to another tenant.

    An agent authenticated under tenant-alpha attempts to inject tenant_id='tenant-beta' in parameters.
    The upstream must ignore the parameter and bind the order strictly to tenant-alpha.
    """
    alpha_headers = {"Authorization": "Bearer demo-token-support-alpha"}
    payload = {
        "request_id": "req-cross-tenant-create",
        "action": "create_order",
        "tenant_id": "tenant-beta",  # Injected in action request
        "parameters": {
            "customer_name": "Injected Tenant Order",
            "item": "Cross Tenant Exploit",
            "quantity": 1,
            "total_price": 100.00,
            "tenant_id": "tenant-beta",  # Injected in order parameters
        },
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=alpha_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "SUCCESS"
    created_order = body["data"]

    # The order must be assigned to tenant-alpha, completely ignoring the injected tenant-beta
    assert created_order["tenant_id"] == "tenant-alpha"
    assert created_order["tenant_id"] != "tenant-beta"


def test_sqlite_data_access_consistently_enforces_tenant_scoping() -> None:
    """Criterion 12: Verify that direct database queries strictly enforce tenant scoping.

    Ensures that get_order with mismatched tenant returns None, while correct tenant returns the record.
    """
    # ORD-1001 is tenant-alpha
    assert order_store.get_order("ORD-1001", "tenant-alpha") is not None
    assert order_store.get_order("ORD-1001", "tenant-beta") is None

    # ORD-1003 is tenant-beta
    assert order_store.get_order("ORD-1003", "tenant-beta") is not None
    assert order_store.get_order("ORD-1003", "tenant-alpha") is None

    # Order creation sets tenant explicitly
    new_record = order_store.create_order(
        OrderCreate(customer_name="Direct DB User", item="DB Item", quantity=1, total_price=10.0),
        tenant_id="tenant-alpha",
    )
    assert new_record.tenant_id == "tenant-alpha"
    assert order_store.get_order(new_record.order_id, "tenant-alpha") is not None
    assert order_store.get_order(new_record.order_id, "tenant-beta") is None
