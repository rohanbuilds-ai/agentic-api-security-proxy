"""Tests for Authentication, Identity Resolution, and Role-Based Access Control (RBAC).

Covers mandatory acceptance criteria:
1. Missing token returns 401.
2. Invalid token returns 401.
3. Valid demonstration token resolves to the correct server-side identity.
4. Supplying a different role or tenant in the request body cannot elevate privileges.
5. readonly_analyst can successfully read an authorized order.
6. readonly_analyst cannot create an order (403 Forbidden).
7. A role cannot invoke an unsupported action even if attempting to bypass validation.
8. Unknown roles and missing policy entries fail closed.
"""
import pytest
import httpx
from src.security.identity import resolve_identity_from_header, AuthenticationError
from src.security.policy import PolicyEngine


# =========================================================================
# Authentication Tests (Criteria 1-4)
# =========================================================================

@pytest.mark.asyncio
async def test_missing_token_returns_401(proxy_test_client: httpx.AsyncClient) -> None:
    """Criterion 1: Verify that missing Authorization header fails closed with HTTP 401."""
    payload = {
        "request_id": "req-no-auth",
        "action": "get_order_details",
        "resource_id": "ORD-1001",
    }
    # No Authorization header provided
    response = await proxy_test_client.post("/proxy/v1/action", json=payload)
    assert response.status_code == 401
    body = response.json()
    assert body["status"] == "ERROR"
    assert body["error"] == "ERR_MISSING_CREDENTIALS"
    assert "Authorization header missing" in body["detail"]


@pytest.mark.asyncio
async def test_invalid_token_returns_401(proxy_test_client: httpx.AsyncClient) -> None:
    """Criterion 2: Verify that an invalid or unverified token fails closed with HTTP 401."""
    payload = {
        "request_id": "req-invalid-auth",
        "action": "get_order_details",
        "resource_id": "ORD-1001",
    }
    invalid_headers = [
        {"Authorization": "Bearer totally-fake-token-12345"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer "},
        {"Authorization": "InvalidScheme token"},
    ]
    for headers in invalid_headers:
        response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=headers)
        assert response.status_code == 401
        body = response.json()
        assert body["status"] == "ERROR"
        assert body["error"] in ("ERR_INVALID_CREDENTIALS", "ERR_MALFORMED_HEADER")


def test_valid_token_resolves_correct_identity() -> None:
    """Criterion 3: Verify that valid demonstration tokens resolve to expected server-side identities."""
    analyst_identity = resolve_identity_from_header("Bearer demo-token-analyst-alpha")
    assert analyst_identity.agent_id == "agent-analyst-alpha"
    assert analyst_identity.role == "readonly_analyst"
    assert analyst_identity.tenant_id == "tenant-alpha"

    support_beta = resolve_identity_from_header("Bearer demo-token-support-beta")
    assert support_beta.agent_id == "agent-support-beta"
    assert support_beta.role == "support_rep"
    assert support_beta.tenant_id == "tenant-beta"


@pytest.mark.asyncio
async def test_body_supplied_role_or_tenant_cannot_elevate_privileges(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 4: Verify that client-supplied body fields cannot override server-resolved identity.

    A readonly_analyst attempts to claim role='admin_agent' and tenant_id='tenant-beta' in body
    while trying to create an order. The proxy must use the authenticated role (readonly_analyst)
    and reject the create_order request with 403 Forbidden.
    """
    payload = {
        "request_id": "req-spoof-attempt",
        "action": "create_order",
        "agent_id": "attacker-agent",
        "role": "admin_agent",          # Attacker attempts role spoofing
        "tenant_id": "tenant-beta",      # Attacker attempts tenant spoofing
        "parameters": {
            "customer_name": "Spoofed User",
            "item": "Privilege Escalation Exploit",
            "quantity": 1,
            "total_price": 500.00,
        },
    }
    # Authenticated as readonly_analyst
    headers = {"Authorization": "Bearer demo-token-analyst-alpha"}
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=headers)

    # Must be rejected because the server-resolved role is readonly_analyst, NOT admin_agent
    assert response.status_code == 403
    body = response.json()
    assert body["status"] == "ERROR"
    assert body["error"] == "ERR_RBAC_FORBIDDEN"
    assert "readonly_analyst" in body["detail"]


# =========================================================================
# RBAC Tests (Criteria 5-8)
# =========================================================================

@pytest.mark.asyncio
async def test_readonly_analyst_can_read_authorized_order(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 5: Verify that readonly_analyst can read an order within its tenant."""
    headers = {"Authorization": "Bearer demo-token-analyst-alpha"}
    payload = {
        "request_id": "req-analyst-read",
        "action": "get_order_details",
        "resource_id": "ORD-1001",
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "SUCCESS"
    assert body["data"]["order_id"] == "ORD-1001"
    assert body["data"]["tenant_id"] == "tenant-alpha"


@pytest.mark.asyncio
async def test_readonly_analyst_cannot_create_order(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 6: Verify that readonly_analyst cannot create an order (403 Forbidden)."""
    headers = {"Authorization": "Bearer demo-token-analyst-alpha"}
    payload = {
        "request_id": "req-analyst-create",
        "action": "create_order",
        "parameters": {
            "customer_name": "Analyst Order",
            "item": "Unauthorized Data Book",
            "quantity": 1,
            "total_price": 25.00,
        },
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=headers)
    assert response.status_code == 403
    body = response.json()
    assert body["status"] == "ERROR"
    assert body["error"] == "ERR_RBAC_FORBIDDEN"
    assert "Role 'readonly_analyst' is not authorized to execute action 'create_order'" in body["detail"]


@pytest.mark.asyncio
async def test_role_cannot_invoke_unsupported_action(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Criterion 7: Verify that a client cannot invoke an unsupported action."""
    headers = {"Authorization": "Bearer demo-token-admin-alpha"}
    payload = {
        "request_id": "req-admin-unsupported",
        "action": "drop_database_all",
        "resource_id": "ORD-1001",
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=headers)
    # Schema layer rejects unknown actions before policy evaluation
    assert response.status_code == 422


def test_unknown_role_and_missing_policy_fail_closed() -> None:
    """Criterion 8: Verify that unknown roles and missing policies fail closed (deny-by-default)."""
    engine = PolicyEngine()

    # Unknown role
    assert engine.is_action_permitted("ghost_role", "get_order_details") is False
    assert engine.is_action_permitted("ghost_role", "create_order") is False

    # Known role, unlisted action
    assert engine.is_action_permitted("support_rep", "delete_everything") is False
    assert engine.is_action_permitted("admin_agent", "arbitrary_sql_execute") is False

    # Empty inputs
    assert engine.is_action_permitted("", "get_order_details") is False
    assert engine.is_action_permitted("support_rep", "") is False
