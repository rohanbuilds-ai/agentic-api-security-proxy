"""FastAPI application for the Mock Upstream Backend service.

SECURITY ARCHITECTURE NOTE:
- Protected operations require an internal service credential (X-Internal-Service-Key).
- Direct caller access without this credential is rejected (401 Unauthorized).
- Operations require a verified tenant context (X-Tenant-ID) injected strictly by the proxy gateway.
- Enforces BOLA protection at data-access layer: cross-tenant access attempts return 403 Forbidden
  without disclosing the protected record's data.
"""
import os
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Path, status
from src.schemas.order import OrderCreate, OrderRecord
from src.upstream.store import order_store

INTERNAL_SERVICE_KEY = os.getenv("INTERNAL_SERVICE_KEY", "dev-proxy-internal-service-key-998877")

app = FastAPI(
    title="Mock Upstream Service",
    description="Simulated multi-tenant backend service with internal service-key protection.",
    version="0.2.0",
)


def verify_internal_service_credentials(
    x_internal_service_key: Optional[str] = Header(None, alias="X-Internal-Service-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> str:
    """Validate that the request originates from the trusted proxy and carries valid tenant context."""
    if not x_internal_service_key or x_internal_service_key != INTERNAL_SERVICE_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Direct or unauthorized access to upstream is prohibited. Valid internal service key required.",
        )
    if not x_tenant_id or not x_tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required tenant context in X-Tenant-ID header.",
        )
    return x_tenant_id.strip()


@app.get("/health", tags=["System"])
async def health_check() -> dict:
    """Public health check endpoint indicating service availability."""
    return {"status": "ok", "service": "mock-upstream"}


@app.get(
    "/api/v1/orders/{order_id}",
    response_model=OrderRecord,
    status_code=status.HTTP_200_OK,
    tags=["Orders"],
)
async def get_order(
    order_id: str = Path(
        ...,
        pattern=r"^[A-Z0-9_-]{3,32}$",
        description="Alphanumeric identifier of the order to retrieve.",
    ),
    internal_key: Optional[str] = Header(None, alias="X-Internal-Service-Key"),
    tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> OrderRecord:
    """Retrieve details for a specific order scoped strictly to the requesting tenant."""
    # 1. Validate internal service credential
    if not internal_key or internal_key != INTERNAL_SERVICE_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Direct or unauthorized access to upstream is prohibited. Valid internal service key required.",
        )

    # 2. Validate tenant context
    if not tenant_id or not tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required tenant context in X-Tenant-ID header.",
        )

    # 3. Query with tenant scoping
    record = order_store.get_order(order_id, tenant_id)
    if record:
        return record

    # 4. Check for BOLA / cross-tenant attempt
    cross_tenant_record = order_store.get_order_any_tenant(order_id)
    if cross_tenant_record is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Resource belongs to a different tenant.",
        )

    # 5. Resource does not exist anywhere: 404
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Order '{order_id}' was not found.",
    )


@app.post(
    "/api/v1/orders",
    response_model=OrderRecord,
    status_code=status.HTTP_201_CREATED,
    tags=["Orders"],
)
async def create_order(
    order_data: OrderCreate,
    internal_key: Optional[str] = Header(None, alias="X-Internal-Service-Key"),
    tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> OrderRecord:
    """Create a new order bound strictly to the authenticated tenant."""
    # 1. Validate internal service credential
    if not internal_key or internal_key != INTERNAL_SERVICE_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Direct or unauthorized access to upstream is prohibited. Valid internal service key required.",
        )

    # 2. Validate tenant context
    if not tenant_id or not tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required tenant context in X-Tenant-ID header.",
        )

    # 3. Persist order with server-verified tenant_id
    return order_store.create_order(order_data, tenant_id)



UPSTREAM_HOST = os.getenv("UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "8001"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.upstream.app:app", host=UPSTREAM_HOST, port=UPSTREAM_PORT, reload=False)
