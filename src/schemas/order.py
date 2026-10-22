"""Synthetic order schemas for the mock upstream service."""
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class OrderCreate(BaseModel):
    """Payload schema required to create an order."""
    customer_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Name of the customer placing the order.",
    )
    item: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Catalog item name.",
    )
    quantity: int = Field(
        ...,
        gt=0,
        le=1000,
        description="Quantity ordered (must be positive integer up to 1000).",
    )
    total_price: float = Field(
        ...,
        gt=0.0,
        le=100000.0,
        description="Total order price in USD (must be positive, capped at 100,000.00).",
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional non-sensitive order notes.",
    )


class OrderRecord(OrderCreate):
    """Stored order record with generated identifiers, tenant binding, and timestamps."""
    order_id: str = Field(
        ...,
        pattern=r"^[A-Z0-9_-]{3,32}$",
        description="Unique order identifier (e.g., ORD-1001).",
    )
    tenant_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Tenant identifier that owns this order record.",
    )
    status: str = Field(
        default="PENDING",
        description="Order fulfillment status (PENDING, PROCESSING, COMPLETED, CANCELLED).",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC creation timestamp.",
    )
