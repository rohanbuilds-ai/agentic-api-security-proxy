"""Test health endpoints for both the Proxy and Mock Upstream services."""
import pytest
import httpx


@pytest.mark.asyncio
async def test_upstream_health_endpoint(direct_upstream_client: httpx.AsyncClient) -> None:
    """Verify that the mock upstream service health endpoint responds with 200 OK."""
    response = await direct_upstream_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "mock-upstream"


@pytest.mark.asyncio
async def test_proxy_health_endpoint(proxy_test_client: httpx.AsyncClient) -> None:
    """Verify that the proxy gateway health endpoint responds with 200 OK."""
    response = await proxy_test_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "agentic-security-proxy"
