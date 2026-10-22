"""Trusted agent identity resolution and demonstration credential registry.

SECURITY NOTICE:
This module enforces server-side identity resolution using demonstration Bearer tokens.
- The client NEVER defines its own role, privileges, or tenant in request bodies.
- Tokens are resolved against a trusted server-side registry.
- Missing, unrecognized, or malformed tokens fail closed with HTTP 401.
- These tokens are synthetic demonstration credentials for local university research
  and development; they are NOT production credentials.
"""
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class AgentIdentity:
    """Immutable server-resolved identity for an authenticated agent."""
    agent_id: str
    role: str
    tenant_id: str
    description: str


class AuthenticationError(Exception):
    """Raised when authentication fails due to missing, invalid, or malformed credentials."""
    def __init__(self, error_code: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = 401
        self.error_code = error_code
        self.detail = detail


# Server-side registry of synthetic demonstration tokens
# Maps Bearer tokens to strictly bound server-side agent identities.
DEMO_CREDENTIAL_REGISTRY: Dict[str, AgentIdentity] = {
    # Tenant Alpha Credentials
    "demo-token-analyst-alpha": AgentIdentity(
        agent_id="agent-analyst-alpha",
        role="readonly_analyst",
        tenant_id="tenant-alpha",
        description="Read-only analyst agent bound to tenant-alpha",
    ),
    "demo-token-support-alpha": AgentIdentity(
        agent_id="agent-support-alpha",
        role="support_rep",
        tenant_id="tenant-alpha",
        description="Customer support agent bound to tenant-alpha",
    ),
    "demo-token-billing-alpha": AgentIdentity(
        agent_id="agent-billing-alpha",
        role="billing_agent",
        tenant_id="tenant-alpha",
        description="Billing agent bound to tenant-alpha",
    ),
    "demo-token-admin-alpha": AgentIdentity(
        agent_id="agent-admin-alpha",
        role="admin_agent",
        tenant_id="tenant-alpha",
        description="Administrative agent bound to tenant-alpha",
    ),

    # Tenant Beta Credentials
    "demo-token-analyst-beta": AgentIdentity(
        agent_id="agent-analyst-beta",
        role="readonly_analyst",
        tenant_id="tenant-beta",
        description="Read-only analyst agent bound to tenant-beta",
    ),
    "demo-token-support-beta": AgentIdentity(
        agent_id="agent-support-beta",
        role="support_rep",
        tenant_id="tenant-beta",
        description="Customer support agent bound to tenant-beta",
    ),
    "demo-token-billing-beta": AgentIdentity(
        agent_id="agent-billing-beta",
        role="billing_agent",
        tenant_id="tenant-beta",
        description="Billing agent bound to tenant-beta",
    ),
    "demo-token-admin-beta": AgentIdentity(
        agent_id="agent-admin-beta",
        role="admin_agent",
        tenant_id="tenant-beta",
        description="Administrative agent bound to tenant-beta",
    ),
}


def resolve_identity_from_header(auth_header: Optional[str]) -> AgentIdentity:
    """Validate Authorization header and resolve to a trusted server-side AgentIdentity.

    Fails closed (HTTP 401) on:
    - Missing header
    - Malformed format (not 'Bearer <token>')
    - Unknown or unverified token
    """
    if not auth_header or not auth_header.strip():
        raise AuthenticationError(
            error_code="ERR_MISSING_CREDENTIALS",
            detail="Authorization header missing. Expected 'Authorization: Bearer <token>'.",
        )

    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthenticationError(
            error_code="ERR_MALFORMED_HEADER",
            detail="Authorization header format invalid. Expected 'Authorization: Bearer <token>'.",
        )

    token = parts[1].strip()
    identity = DEMO_CREDENTIAL_REGISTRY.get(token)
    if not identity:
        raise AuthenticationError(
            error_code="ERR_INVALID_CREDENTIALS",
            detail="Invalid or unrecognized demonstration bearer token.",
        )

    return identity
