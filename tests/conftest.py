"""Shared test fixtures for the Agentic API Security Proxy test suite."""
import tempfile
import uuid
from pathlib import Path
from typing import AsyncGenerator, Generator
import pytest
import pytest_asyncio
import httpx
from httpx import ASGITransport

from src.upstream.app import app as upstream_app
from src.upstream.store import order_store
from src.proxy.app import app as proxy_app, get_upstream_client, get_audit
from src.proxy.client import UpstreamClient
from src.security.audit import AuditLogger


@pytest.fixture(scope="session", autouse=True)
def isolate_test_upstream_db() -> Generator[None, None, None]:
    """Isolate upstream database to a temporary SQLite file for the test session."""
    temp_dir = Path(tempfile.gettempdir())
    test_db = temp_dir / f"pytest_upstream_{uuid.uuid4().hex[:8]}.db"
    orig_path = order_store.db_path
    order_store.db_path = test_db
    order_store.reset()

    yield

    order_store.db_path = orig_path
    if test_db.exists():
        try:
            test_db.unlink()
        except OSError:
            pass


@pytest.fixture(autouse=True)
def reset_store_state() -> None:
    """Ensure in-memory synthetic orders are reset to seeds before each test."""
    order_store.reset()


@pytest_asyncio.fixture
async def direct_upstream_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Direct HTTP test client pointing to the upstream service without the proxy."""
    transport = ASGITransport(app=upstream_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8001") as client:
        yield client


@pytest_asyncio.fixture
async def proxy_test_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Test client pointing to the proxy with its upstream client and audit logger bound to isolated test instances."""
    temp_dir = Path(tempfile.gettempdir())
    test_audit_db = temp_dir / f"pytest_audit_{uuid.uuid4().hex[:8]}.db"
    test_audit_logger = AuditLogger(test_audit_db)

    upstream_transport = ASGITransport(app=upstream_app)
    async with httpx.AsyncClient(
        transport=upstream_transport, base_url="http://127.0.0.1:8001"
    ) as raw_upstream_client:
        mocked_forwarder = UpstreamClient(client=raw_upstream_client)

        # Wire the proxy app dependencies to route to the in-process upstream and isolated test audit logger
        proxy_app.dependency_overrides[get_upstream_client] = lambda: mocked_forwarder
        proxy_app.dependency_overrides[get_audit] = lambda: test_audit_logger

        proxy_transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(
            transport=proxy_transport, base_url="http://127.0.0.1:8000"
        ) as client:
            yield client

        # Cleanup overrides after test completes
        proxy_app.dependency_overrides.clear()

    if test_audit_db.exists():
        try:
            test_audit_db.unlink()
        except OSError:
            pass
