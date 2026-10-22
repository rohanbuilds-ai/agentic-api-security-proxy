"""FastAPI application for the Agentic API Security Proxy service.

PHASE 4 COMPLETE MULTI-STAGE SECURITY PIPELINE:
1. Ingress Size & Schema Validation: Clamps payload size (max 64KB) and parses strictly typed Pydantic models.
2. Trusted Identity Resolution: Authenticates Bearer token against server registry (401 on failure).
3. Identity Claim Isolation: Prevents client body fields from overriding server-resolved role/tenant.
4. Deterministic RBAC: Enforces role permissions against policies.yaml (403 on failure).
5. Adversarial Input Inspection: Scans free-text fields for high-confidence injection/bypass patterns (403 on block; upstream is not contacted).
6. Parameter Boundary Verification: Enforces numeric ranges and length limits on parameters (400 on failure).
7. Tenant-Scoped Forwarding: Injects verified tenant_id and internal service key into upstream requests.
8. Outbound Data Loss Prevention (DLP): Scans and redacts synthetic SSNs, credit cards, API keys, and test secrets.
9. DLP Fail-Closed Strategy: Withholds response and returns 502 if egress inspection encounters errors.
10. Tamper-Evident Audit Logging: Atomically records decision, reason code, and latency in a cryptographically chained append-only audit trail.
"""
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
from fastapi import FastAPI, Depends, Header, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler as default_val_handler
from fastapi.responses import JSONResponse


from src.schemas.action import ActionType, AgentActionRequest, ProxyActionResponse
from src.proxy.client import UpstreamClient
from src.security.identity import AgentIdentity, AuthenticationError, resolve_identity_from_header
from src.security.authorizer import AuthorizationError, SecurityAuthorizer, authorizer
from src.security.sanitizer import (
    AdversarialInputError,
    InputValidationError,
    RequestSanitizer,
    request_sanitizer,
)
from src.security.dlp import (
    DataLossPreventionEngine,
    DLPInspectionError,
    dlp_engine,
)
from src.security.audit import AuditDecision, AuditLogger, audit_logger


# Shared default upstream client instance
_default_upstream_client: UpstreamClient = UpstreamClient()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and clean teardown of network clients."""
    yield
    await _default_upstream_client.close()


app = FastAPI(
    title="Agentic API Security Proxy",
    description="Runtime security proxy mediating actions proposed by AI agents.",
    version="0.4.0",
    lifespan=lifespan,
)


def get_upstream_client() -> UpstreamClient:
    """Dependency provider for the upstream client."""
    return _default_upstream_client


def get_security_authorizer() -> SecurityAuthorizer:
    """Dependency provider for the security authorizer."""
    return authorizer


def get_sanitizer() -> RequestSanitizer:
    """Dependency provider for ingress request sanitizer."""
    return request_sanitizer


def get_dlp() -> DataLossPreventionEngine:
    """Dependency provider for egress DLP engine."""
    return dlp_engine


def get_audit() -> AuditLogger:
    """Dependency provider for the audit logger."""
    return audit_logger


HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Audit schema/parameter parsing failures and return standardized error response."""
    current_audit = app.dependency_overrides.get(get_audit, lambda: audit_logger)()
    try:
        current_audit.log_event(
            request_id="req-schema-validation-error",
            decision=AuditDecision.DENIED,
            reason_code="ERR_SCHEMA_VALIDATION",
            http_status=HTTP_422_STATUS,
            latency_ms=0.5,
        )
    except Exception:
        pass

    clean_errors = []
    for err in exc.errors():
        err_dict = dict(err)
        if "ctx" in err_dict and isinstance(err_dict["ctx"], dict):
            err_dict["ctx"] = {k: str(v) if isinstance(v, Exception) else v for k, v in err_dict["ctx"].items()}
        clean_errors.append(err_dict)

    return JSONResponse(status_code=HTTP_422_STATUS, content={"detail": clean_errors})



@app.get("/health", tags=["System"])
async def health_check() -> dict:
    """Proxy health check endpoint indicating gateway availability."""
    return {"status": "ok", "service": "agentic-security-proxy"}


@app.post(
    "/proxy/v1/action",
    response_model=ProxyActionResponse,
    tags=["Proxy Actions"],
    summary="Execute a constrained, inspected, authorized, and audited agent action",
)
async def dispatch_action(
    request: AgentActionRequest,
    raw_request: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    client: UpstreamClient = Depends(get_upstream_client),
    authz: SecurityAuthorizer = Depends(get_security_authorizer),
    sanitizer: RequestSanitizer = Depends(get_sanitizer),
    dlp: DataLossPreventionEngine = Depends(get_dlp),
    audit: AuditLogger = Depends(get_audit),
) -> JSONResponse:
    """Dispatch an agent action through the multi-stage security pipeline."""
    start_time = time.perf_counter()

    def calc_latency_ms() -> float:
        return (time.perf_counter() - start_time) * 1000.0

    # ---------------------------------------------------------
    # STAGE 1: Trusted Identity Resolution (Authentication)
    # ---------------------------------------------------------
    try:
        identity: AgentIdentity = resolve_identity_from_header(authorization)
    except AuthenticationError as auth_err:
        latency = calc_latency_ms()
        try:
            audit.log_event(
                request_id=request.request_id,
                action=request.action.value if hasattr(request.action, "value") else str(request.action),
                decision=AuditDecision.DENIED,
                reason_code=auth_err.error_code,
                http_status=auth_err.status_code,
                latency_ms=latency,
            )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status": "ERROR", "error": "ERR_AUDIT_FAILURE", "detail": "Critical audit logging failure."},
            )

        error_resp = ProxyActionResponse(
            request_id=request.request_id,
            action=str(request.action.value if hasattr(request.action, "value") else request.action),
            status="ERROR",
            error=auth_err.error_code,
            detail=auth_err.detail,
        )
        return JSONResponse(
            status_code=auth_err.status_code,
            content=error_resp.model_dump(),
        )

    # ---------------------------------------------------------
    # STAGE 2: Client Body Identity Override Prevention
    # ---------------------------------------------------------
    # Body claims for agent_id, role, or tenant_id are completely disregarded.
    # Server-resolved `identity` is used exclusively.

    # ---------------------------------------------------------
    # STAGE 3: Deterministic RBAC Authorization
    # ---------------------------------------------------------
    try:
        authz.authorize_action(identity, request.action.value)
    except AuthorizationError as authz_err:
        latency = calc_latency_ms()
        try:
            audit.log_event(
                request_id=request.request_id,
                agent_id=identity.agent_id,
                role=identity.role,
                tenant_id=identity.tenant_id,
                action=request.action.value,
                decision=AuditDecision.DENIED,
                reason_code=authz_err.error_code,
                http_status=authz_err.status_code,
                latency_ms=latency,
            )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status": "ERROR", "error": "ERR_AUDIT_FAILURE", "detail": "Critical audit logging failure."},
            )

        error_resp = ProxyActionResponse(
            request_id=request.request_id,
            action=request.action.value,
            status="ERROR",
            error=authz_err.error_code,
            detail=authz_err.detail,
        )
        return JSONResponse(
            status_code=authz_err.status_code,
            content=error_resp.model_dump(),
        )

    # ---------------------------------------------------------
    # STAGE 4: Request Inspection & Adversarial Detection
    # ---------------------------------------------------------
    content_length_header = raw_request.headers.get("content-length")
    raw_size = int(content_length_header) if content_length_header and content_length_header.isdigit() else None

    try:
        sanitizer.inspect_request(request, payload_bytes=raw_size)
    except AdversarialInputError as adv_err:
        latency = calc_latency_ms()
        try:
            audit.log_event(
                request_id=request.request_id,
                agent_id=identity.agent_id,
                role=identity.role,
                tenant_id=identity.tenant_id,
                action=request.action.value,
                decision=AuditDecision.BLOCKED,
                reason_code=adv_err.error_code,
                rule_id=adv_err.rule_id,
                http_status=status.HTTP_403_FORBIDDEN,
                latency_ms=latency,
            )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status": "ERROR", "error": "ERR_AUDIT_FAILURE", "detail": "Critical audit logging failure."},
            )

        blocked_resp = ProxyActionResponse(
            request_id=request.request_id,
            action=request.action.value,
            status="BLOCKED",
            error=adv_err.error_code,
            rule_id=adv_err.rule_id,
            detail=adv_err.detail,
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=blocked_resp.model_dump(),
        )
    except InputValidationError as val_err:
        latency = calc_latency_ms()
        try:
            audit.log_event(
                request_id=request.request_id,
                agent_id=identity.agent_id,
                role=identity.role,
                tenant_id=identity.tenant_id,
                action=request.action.value,
                decision=AuditDecision.DENIED,
                reason_code=val_err.error_code,
                http_status=status.HTTP_400_BAD_REQUEST,
                latency_ms=latency,
            )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status": "ERROR", "error": "ERR_AUDIT_FAILURE", "detail": "Critical audit logging failure."},
            )

        val_resp = ProxyActionResponse(
            request_id=request.request_id,
            action=request.action.value,
            status="ERROR",
            error=val_err.error_code,
            detail=val_err.detail,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=val_resp.model_dump(),
        )

    # ---------------------------------------------------------
    # STAGE 5: Deterministic Action Dispatching with Tenant Scoping
    # ---------------------------------------------------------
    if request.action == ActionType.GET_ORDER_DETAILS:
        result = await client.get_order_details(
            resource_id=request.resource_id,  # type: ignore[arg-type]
            tenant_id=identity.tenant_id,
        )

    elif request.action == ActionType.CREATE_ORDER:
        result = await client.create_order(
            order_parameters=request.parameters,  # type: ignore[arg-type]
            tenant_id=identity.tenant_id,
        )

    else:
        latency = calc_latency_ms()
        try:
            audit.log_event(
                request_id=request.request_id,
                agent_id=identity.agent_id,
                role=identity.role,
                tenant_id=identity.tenant_id,
                action=str(request.action),
                decision=AuditDecision.DENIED,
                reason_code="UNSUPPORTED_ACTION",
                http_status=status.HTTP_400_BAD_REQUEST,
                latency_ms=latency,
            )
        except Exception:
            pass

        error_resp = ProxyActionResponse(
            request_id=request.request_id,
            action=str(request.action),
            status="ERROR",
            error="UNSUPPORTED_ACTION",
            detail=f"Action '{request.action}' is not permitted by this proxy gateway.",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_resp.model_dump(),
        )

    # ---------------------------------------------------------
    # STAGE 6: Outbound Sensitive Data Inspection (DLP)
    # ---------------------------------------------------------
    sanitized_data = result.data
    redaction_metadata = None

    if result.data is not None:
        try:
            sanitized_data, redaction_metadata = dlp.inspect_and_redact(result.data)
        except DLPInspectionError as dlp_err:
            latency = calc_latency_ms()
            try:
                audit.log_event(
                    request_id=request.request_id,
                    agent_id=identity.agent_id,
                    role=identity.role,
                    tenant_id=identity.tenant_id,
                    action=request.action.value,
                    decision=AuditDecision.ERROR,
                    reason_code=dlp_err.error_code,
                    http_status=status.HTTP_502_BAD_GATEWAY,
                    upstream_status=result.status_code,
                    latency_ms=latency,
                )
            except Exception:
                pass

            dlp_fail_resp = ProxyActionResponse(
                request_id=request.request_id,
                action=request.action.value,
                status="ERROR",
                upstream_status=result.status_code,
                data=None,
                error=dlp_err.error_code,
                detail=dlp_err.detail,
            )
            return JSONResponse(
                status_code=status.HTTP_502_BAD_GATEWAY,
                content=dlp_fail_resp.model_dump(),
            )

    # ---------------------------------------------------------
    # STAGE 7: Translate Upstream Result & Emit Final Audit Event
    # ---------------------------------------------------------
    latency = calc_latency_ms()

    if result.status_code in (status.HTTP_200_OK, status.HTTP_201_CREATED):
        decision = AuditDecision.SANITIZED if redaction_metadata else AuditDecision.ALLOWED
        reason_code = "DLP_REDACTED" if redaction_metadata else "ACTION_SUCCESS"
        redact_count = redaction_metadata["count"] if redaction_metadata else 0
        redact_cats = redaction_metadata["categories"] if redaction_metadata else None

        try:
            audit.log_event(
                request_id=request.request_id,
                agent_id=identity.agent_id,
                role=identity.role,
                tenant_id=identity.tenant_id,
                action=request.action.value,
                decision=decision,
                reason_code=reason_code,
                http_status=status.HTTP_200_OK,
                upstream_status=result.status_code,
                latency_ms=latency,
                redaction_count=redact_count,
                redaction_categories=redact_cats,
            )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"status": "ERROR", "error": "ERR_AUDIT_FAILURE", "detail": "Critical audit logging failure."},
            )

        response_body = ProxyActionResponse(
            request_id=request.request_id,
            action=request.action.value,
            status="SUCCESS",
            upstream_status=result.status_code,
            data=sanitized_data,
            redactions=redaction_metadata,
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=response_body.model_dump(),
        )

    # Upstream Errors: BOLA (403), Not Found (404), Auth Failure (502), Unreachable (502), Timeout (504)
    decision = AuditDecision.DENIED if result.status_code in (403, 404, 422) else AuditDecision.ERROR
    reason_code = result.error_code or "UPSTREAM_ERROR"

    try:
        audit.log_event(
            request_id=request.request_id,
            agent_id=identity.agent_id,
            role=identity.role,
            tenant_id=identity.tenant_id,
            action=request.action.value,
            decision=decision,
            reason_code=reason_code,
            http_status=result.status_code,
            upstream_status=result.status_code,
            latency_ms=latency,
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "ERROR", "error": "ERR_AUDIT_FAILURE", "detail": "Critical audit logging failure."},
        )

    response_body = ProxyActionResponse(
        request_id=request.request_id,
        action=request.action.value,
        status="ERROR",
        upstream_status=result.status_code,
        data=sanitized_data,
        error=reason_code,
        detail=result.detail or f"Upstream service returned HTTP {result.status_code}.",
        redactions=redaction_metadata,
    )
    return JSONResponse(
        status_code=result.status_code,
        content=response_body.model_dump(),
    )


if __name__ == "__main__":
    import uvicorn
    from src.proxy.config import config
    uvicorn.run("src.proxy.app:app", host=config.proxy_host, port=config.proxy_port, reload=False)
