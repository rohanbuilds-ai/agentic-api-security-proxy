"""Action request and response schemas for the Agentic API Security Proxy.

IMPORTANT SECURITY NOTICE (Phase 1):
Fields such as `agent_id`, `role`, and `tenant_id` supplied in request bodies
are strictly UNTRUSTED client demonstration inputs during Phase 1. They are NOT
used for authorization decisions until Phase 2 implements cryptographic authentication,
session binding, and deterministic RBAC/BOLA policy checks.
"""
import re
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, model_validator


# Strictly constrain resource_id characters to prevent path traversal (../),
# URL manipulation, or control character injection into forwarder paths.
RESOURCE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


class ActionType(str, Enum):
    """Explicitly supported agent actions in Phase 1.

    Any action not listed here is rejected at the schema boundary
    and will NEVER be forwarded to upstream services.
    """
    GET_ORDER_DETAILS = "get_order_details"
    CREATE_ORDER = "create_order"


class AgentActionRequest(BaseModel):
    """Schema for incoming agent action requests submitted to POST /proxy/v1/action."""
    request_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.:]+$",
        description="Client-supplied trace or request identifier for tracking and correlation.",
    )
    action: ActionType = Field(
        ...,
        description="The strictly constrained action to execute. Must match an allowed ActionType enum value.",
    )
    resource_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Target resource identifier. Must be alphanumeric (underscores/hyphens allowed).",
    )
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Action-specific parameters (e.g., order creation fields).",
    )

    # Untrusted demonstration fields (Clearly labeled per AppSec guidelines)
    agent_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="UNTRUSTED demonstration field. Not used for security decisions in Phase 1.",
    )
    role: Optional[str] = Field(
        default=None,
        max_length=64,
        description="UNTRUSTED demonstration field. Not used for security decisions in Phase 1.",
    )
    tenant_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="UNTRUSTED demonstration field. Not used for security decisions in Phase 1.",
    )

    @model_validator(mode="after")
    def validate_action_constraints(self) -> "AgentActionRequest":
        """Enforce per-action parameter requirements and validate resource identifiers."""
        # 1. Resource ID format check (prevents path traversal like ../../etc/passwd)
        if self.resource_id is not None:
            if not RESOURCE_ID_REGEX.match(self.resource_id):
                raise ValueError(
                    f"resource_id '{self.resource_id}' contains invalid characters. "
                    "Only alphanumeric characters, hyphens, and underscores (1-64 chars) are permitted."
                )

        # 2. Per-action validation
        if self.action == ActionType.GET_ORDER_DETAILS:
            if not self.resource_id:
                raise ValueError("Action 'get_order_details' requires a valid 'resource_id'.")

        elif self.action == ActionType.CREATE_ORDER:
            if not self.parameters:
                raise ValueError("Action 'create_order' requires 'parameters' containing order fields.")

        return self


class ProxyActionResponse(BaseModel):
    """Predictable response envelope returned by the proxy to the caller."""
    request_id: str = Field(
        ...,
        description="Echoes the request_id for end-to-end trace correlation.",
    )
    action: str = Field(
        ...,
        description="The action that was processed or attempted.",
    )
    status: str = Field(
        ...,
        description="Overall processing status: 'SUCCESS' or 'ERROR'.",
    )
    upstream_status: Optional[int] = Field(
        default=None,
        description="HTTP status code received from the upstream service (if reached).",
    )
    data: Optional[Any] = Field(
        default=None,
        description="Payload returned by the upstream service on successful responses.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Standardized machine-readable error code if processing failed.",
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Identifier of the specific security rule triggered upon blocking.",
    )
    detail: Optional[str] = Field(
        default=None,
        description="Sanitized human-readable explanation of an error or block.",
    )
    redactions: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Metadata on sensitive data redacted by egress DLP (e.g. count, categories).",
    )
