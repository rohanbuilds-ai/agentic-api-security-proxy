"""Tests for Outbound Data Loss Prevention (DLP) and Sensitive Data Redaction.

Covers mandatory acceptance criteria:
9. Synthetic SSN is redacted ([REDACTED_SSN]).
10. Synthetic Credit Card is redacted ([REDACTED_CREDIT_CARD]).
11. Synthetic API key / Bearer token is redacted ([REDACTED_API_KEY]).
12. Sensitive values inside nested JSON objects and arrays are recursively redacted.
13. Response without sensitive data remains unchanged.
14. Multiple sensitive values are all redacted and counted correctly.
15. Original sensitive values never appear in returned error messages or diagnostics.
16. If DLP inspection encounters an error, the proxy fails closed (502, payload withheld).
"""
import pytest
import httpx
from httpx import ASGITransport

from src.proxy.app import app as proxy_app, get_upstream_client, get_dlp
from src.proxy.client import UpstreamClient
from src.security.dlp import DataLossPreventionEngine, DLPInspectionError

AUTH_HEADER = {"Authorization": "Bearer demo-token-support-alpha"}


# =========================================================================
# Unit Level Engine Tests
# =========================================================================

def test_dlp_redacts_synthetic_ssn() -> None:
    """Criterion 9: Verify synthetic SSN is detected and masked."""
    dlp = DataLossPreventionEngine()
    raw = {"customer": "Alice", "ssn": "987-65-4321"}
    sanitized, meta = dlp.inspect_and_redact(raw)

    assert sanitized["ssn"] == "[REDACTED_SSN]"
    assert "987-65-4321" not in str(sanitized)
    assert meta is not None
    assert meta["count"] == 1
    assert "SSN" in meta["categories"]


def test_dlp_redacts_synthetic_credit_card() -> None:
    """Criterion 10: Verify Luhn-valid credit card number is detected and masked."""
    dlp = DataLossPreventionEngine()
    # 4111-1111-1111-1111 is a classic Luhn-valid test number
    raw = {"payment": "Charged to 4111-1111-1111-1111 successfully."}
    sanitized, meta = dlp.inspect_and_redact(raw)

    assert sanitized["payment"] == "Charged to [REDACTED_CREDIT_CARD] successfully."
    assert "4111-1111-1111-1111" not in str(sanitized)
    assert meta is not None
    assert meta["count"] == 1
    assert "CREDIT_CARD" in meta["categories"]


def test_dlp_redacts_synthetic_api_key_and_tokens() -> None:
    """Criterion 11: Verify API keys and bearer tokens are detected and masked."""
    dlp = DataLossPreventionEngine()
    raw = {
        "service": "telemetry",
        "openai_key": "sk-1234567890abcdef1234567890abcdef",
        "github_key": "ghp_123456789012345678901234567890123456",
    }
    sanitized, meta = dlp.inspect_and_redact(raw)

    assert sanitized["openai_key"] == "[REDACTED_API_KEY]"
    assert sanitized["github_key"] == "[REDACTED_API_KEY]"
    assert meta is not None
    assert meta["count"] == 2
    assert "API_KEY" in meta["categories"]


def test_dlp_nested_structures_recursively_redacted() -> None:
    """Criterion 12: Verify deeply nested dictionaries and lists are sanitized recursively."""
    dlp = DataLossPreventionEngine()
    nested_payload = {
        "company": "Acme",
        "departments": [
            {
                "name": "Finance",
                "employees": [
                    {"name": "Carol", "gov_id": "123-45-6789"},
                    {"name": "Dave", "notes": ["Card on file: 4111-1111-1111-1111"]},
                ],
            }
        ],
    }
    sanitized, meta = dlp.inspect_and_redact(nested_payload)

    # Check that structural integrity is preserved
    carol_record = sanitized["departments"][0]["employees"][0]
    dave_record = sanitized["departments"][0]["employees"][1]

    assert carol_record["gov_id"] == "[REDACTED_SSN]"
    assert dave_record["notes"][0] == "Card on file: [REDACTED_CREDIT_CARD]"
    assert meta["count"] == 2
    assert sorted(meta["categories"]) == ["CREDIT_CARD", "SSN"]


def test_dlp_clean_response_remains_unchanged() -> None:
    """Criterion 13: Verify payload with ordinary business data is untouched and meta is None."""
    dlp = DataLossPreventionEngine()
    clean_payload = {
        "order_id": "ORD-1001",
        "customer": "Alice Smith",
        "item": "Security Book",
        "quantity": 1,
        "total_price": 49.99,
        "notes": "Delivered to warehouse dock 4.",
    }
    sanitized, meta = dlp.inspect_and_redact(clean_payload)
    assert sanitized == clean_payload
    assert meta is None


def test_dlp_multiple_sensitive_values_all_redacted_and_counted() -> None:
    """Criterion 14: Verify multiple distinct sensitive items in one string/object are all counted."""
    dlp = DataLossPreventionEngine()
    mixed = {
        "summary": "Customer SSN is 111-22-3333 and token is sk-abcdef1234567890abcdef123456",
        "backup_secret": "SYNTHETIC_SECRET_TOKEN_999",
    }
    sanitized, meta = dlp.inspect_and_redact(mixed)

    assert "[REDACTED_SSN]" in sanitized["summary"]
    assert "[REDACTED_API_KEY]" in sanitized["summary"]
    assert sanitized["backup_secret"] == "[REDACTED_SECRET]"
    assert meta["count"] == 3
    assert sorted(meta["categories"]) == ["API_KEY", "SSN", "SYNTHETIC_SECRET"]


# =========================================================================
# Integration Level Proxy Tests
# =========================================================================

@pytest.mark.asyncio
async def test_proxy_end_to_end_redacts_upstream_sensitive_data() -> None:
    """Criterion 9-14 (E2E): Create order with synthetic SSN in notes; proxy redacts on retrieval."""
    class SensitiveUpstreamTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            # Simulate upstream returning sensitive customer data
            return httpx.Response(
                200,
                json={
                    "order_id": "ORD-SECRET-01",
                    "customer_name": "Test User",
                    "synthetic_ssn": "999-12-3456",
                    "card": "4111-1111-1111-1111",
                    "status": "COMPLETED",
                },
            )

    sensitive_client = httpx.AsyncClient(transport=SensitiveUpstreamTransport(), base_url="http://127.0.0.1:8001")
    forwarder = UpstreamClient(client=sensitive_client)
    proxy_app.dependency_overrides[get_upstream_client] = lambda: forwarder

    try:
        transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            payload = {
                "request_id": "req-dlp-e2e",
                "action": "get_order_details",
                "resource_id": "ORD-SECRET-01",
            }
            resp = await client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)
            assert resp.status_code == 200
            body = resp.json()

            # Verifications: Sensitive data masked
            data = body["data"]
            assert data["synthetic_ssn"] == "[REDACTED_SSN]"
            assert data["card"] == "[REDACTED_CREDIT_CARD]"
            assert "999-12-3456" not in resp.text
            assert "4111-1111-1111-1111" not in resp.text

            # Redaction metadata reported
            assert body["redactions"]["count"] == 2
            assert sorted(body["redactions"]["categories"]) == ["CREDIT_CARD", "SSN"]
    finally:
        proxy_app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_dlp_failure_fails_closed_without_leaking_raw_payload() -> None:
    """Criterion 16: If DLP engine raises an error, the proxy fails closed (502, raw payload withheld)."""
    raw_sensitive_payload = {
        "secret_token": "sk-unredacted-secret-1234567890abcdef",
        "ssn": "999-99-9999",
    }

    class MockUpstreamTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=raw_sensitive_payload)

    # Broken DLP engine that throws an exception during inspection
    class BrokenDLPEngine(DataLossPreventionEngine):
        def inspect_and_redact(self, payload: object) -> tuple:
            raise DLPInspectionError("Simulated internal DLP engine fault.")

    mock_client = httpx.AsyncClient(transport=MockUpstreamTransport(), base_url="http://127.0.0.1:8001")
    proxy_app.dependency_overrides[get_upstream_client] = lambda: UpstreamClient(client=mock_client)
    proxy_app.dependency_overrides[get_dlp] = lambda: BrokenDLPEngine()

    try:
        transport = ASGITransport(app=proxy_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            payload = {
                "request_id": "req-dlp-fail-closed",
                "action": "get_order_details",
                "resource_id": "ORD-1001",
            }
            resp = await client.post("/proxy/v1/action", json=payload, headers=AUTH_HEADER)

            # Must return 502 Bad Gateway
            assert resp.status_code == 502
            body = resp.json()
            assert body["status"] == "ERROR"
            assert body["error"] == "ERR_DLP_FAILURE"
            assert body["data"] is None

            # CRITICAL CHECK: Raw sensitive payload must NOT appear anywhere in the response text
            assert "sk-unredacted-secret" not in resp.text
            assert "999-99-9999" not in resp.text
    finally:
        proxy_app.dependency_overrides.clear()
