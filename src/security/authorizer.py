"""Deterministic Authorization & BOLA Prevention Module.

SECURITY RESPONSIBILITIES:
1. Enforces Role-Based Access Control (RBAC) via the PolicyEngine.
2. Enforces Tenant Boundary Isolation (BOLA / Broken Object Level Authorization prevention).
3. Fails closed with HTTP 403 Forbidden on any permission or tenant mismatch.
4. Generates consistent, sanitized error codes without disclosing cross-tenant data.
"""
from typing import Optional
from src.security.identity import AgentIdentity
from src.security.policy import PolicyEngine, policy_engine


class AuthorizationError(Exception):
    """Raised when an authenticated caller is forbidden from performing an action or accessing a resource."""
    def __init__(self, error_code: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = 403
        self.error_code = error_code
        self.detail = detail


class SecurityAuthorizer:
    """Enforces deterministic authorization decisions prior to upstream request forwarding."""

    def __init__(self, engine: Optional[PolicyEngine] = None) -> None:
        self.policy_engine = engine or policy_engine

    def authorize_action(self, identity: AgentIdentity, action: str) -> None:
        """Validate that the caller's role is permitted to perform the requested action."""
        if not self.policy_engine.is_action_permitted(identity.role, action):
            raise AuthorizationError(
                error_code="ERR_RBAC_FORBIDDEN",
                detail=f"Role '{identity.role}' is not authorized to execute action '{action}'.",
            )

    def authorize_tenant_access(
        self,
        identity: AgentIdentity,
        resource_tenant_id: Optional[str],
    ) -> None:
        """Validate that target resource tenant matches the authenticated agent's tenant context."""
        if resource_tenant_id and identity.tenant_id != resource_tenant_id:
            raise AuthorizationError(
                error_code="ERR_BOLA_VIOLATION",
                detail="Access denied: Cross-tenant resource access is forbidden.",
            )


# Global singleton authorizer instance
authorizer = SecurityAuthorizer()
