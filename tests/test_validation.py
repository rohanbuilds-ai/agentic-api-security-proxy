"""Tests for request schema validation, unsupported actions, and SSRF/path-traversal rejection."""
import pytest
import httpx

AUTH_HEADER = {"Authorization": "Bearer demo-token-support-alpha"}


@pytest.mark.asyncio
async def test_malformed_request_missing_required_fields(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Verify that a request missing required schema fields is rejected with 422."""
    # Completely empty body
    response = await proxy_test_client.post("/proxy/v1/action", json={}, headers=AUTH_HEADER)
    assert response.status_code == 422

    # Missing action field
    response = await proxy_test_client.post(
        "/proxy/v1/action",
        json={"request_id": "req-missing-action"},
        headers=AUTH_HEADER,
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_order_details_missing_resource_id_rejected(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Verify that get_order_details without a resource_id is rejected by validator."""
    payload = {
        "request_id": "req-no-res-id",
        "action": "get_order_details",
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
    assert response.status_code == 422
    assert "resource_id" in response.text


@pytest.mark.asyncio
async def test_create_order_missing_parameters_rejected(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Verify that create_order without parameters is rejected by validator."""
    payload = {
        "request_id": "req-no-params",
        "action": "create_order",
    }
    response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
    assert response.status_code == 422
    assert "parameters" in response.text


@pytest.mark.asyncio
async def test_unsupported_action_rejected_at_gateway_boundary(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Verify that unsupported/dangerous actions are rejected without reaching upstream."""
    unsupported_actions = [
        "delete_database",
        "execute_sql",
        "export_all_users",
        "admin_shell",
        "drop_table",
    ]
    for action in unsupported_actions:
        payload = {
            "request_id": f"req-unsupported-{action}",
            "action": action,
            "resource_id": "ORD-1001",
        }
        response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
        assert response.status_code == 422, f"Action '{action}' was not rejected as expected."


@pytest.mark.asyncio
async def test_path_traversal_in_resource_id_rejected(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Verify that directory traversal sequences in resource_id are rejected at the schema level."""
    traversal_payloads = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "ORD-1001/../../admin",
        "ORD-1001\x00extra",
        "ORD 1001 with spaces",
        "ORD-1001; DROP TABLE orders;--",
    ]
    for bad_id in traversal_payloads:
        payload = {
            "request_id": "req-traversal-attempt",
            "action": "get_order_details",
            "resource_id": bad_id,
        }
        response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
        assert response.status_code == 422, f"Payload '{bad_id}' should have been rejected."


@pytest.mark.asyncio
async def test_arbitrary_destination_url_cannot_be_selected(
    proxy_test_client: httpx.AsyncClient,
) -> None:
    """Verify that client inputs attempting SSRF or arbitrary URL forwarding are rejected."""
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "https://evil-attacker.com/leak",
        "http://localhost:22",
    ]
    for target_url in ssrf_payloads:
        payload = {
            "request_id": "req-ssrf-attempt",
            "action": "get_order_details",
            "resource_id": target_url,
        }
        response = await proxy_test_client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
        assert response.status_code == 422, f"SSRF target '{target_url}' should have been rejected."
