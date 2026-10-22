"""Tamper-Evident Append-Only Security Decision Audit Trail.

SECURITY ARCHITECTURE NOTE:
- Immutable hash-chain sequencing: Each event records the SHA-256 hash of the preceding event.
- Enforces append-only semantics using parameterized SQL and SQLite database triggers
  preventing UPDATE and DELETE operations.
- NEVER logs passwords, bearer tokens, internal service keys, full raw request bodies,
  or unredacted sensitive response values.
- Fails closed: If an audit record cannot be committed at an enforcement boundary,
  the request is halted to prevent unaudited operations.
- Local SQLite Limitation: This local hash chain detects accidental tampering or unsophisticated
  modification; a privileged administrator with filesystem access could rewrite the database
  and recompute an unkeyed chain. It is not an alternative to remote, write-once, signed logging.
"""
import hashlib
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

INITIAL_HASH = "0" * 64  # 64-character genesis hash


class AuditDecision(str, Enum):
    """Documented categorical outcome of a security mediation decision."""
    ALLOWED = "ALLOWED"      # Request authorized and forwarded with clean response
    DENIED = "DENIED"        # Denied by authentication, RBAC, or BOLA policy
    BLOCKED = "BLOCKED"      # Blocked by ingress inspection / adversarial detector
    SANITIZED = "SANITIZED"  # Allowed, but outbound response was redacted by DLP
    ERROR = "ERROR"          # Upstream fault, timeout, or DLP inspection failure


@dataclass(frozen=True)
class AuditEvent:
    """Immutable structured audit event record."""
    event_id: str
    timestamp_utc: str
    request_id: str
    agent_id: Optional[str]
    role: Optional[str]
    tenant_id: Optional[str]
    action: Optional[str]
    decision: str
    reason_code: str
    rule_id: Optional[str]
    http_status: int
    upstream_status: Optional[int]
    latency_ms: float
    redaction_count: int
    redaction_categories: Optional[str]
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class AuditVerificationResult:
    """Outcome of an audit hash chain verification check."""
    is_valid: bool
    total_events: int
    tampered_event_id: Optional[str] = None
    tampered_index: Optional[int] = None
    error_message: Optional[str] = None


def compute_canonical_event_hash(
    event_id: str,
    timestamp_utc: str,
    request_id: str,
    agent_id: Optional[str],
    role: Optional[str],
    tenant_id: Optional[str],
    action: Optional[str],
    decision: str,
    reason_code: str,
    rule_id: Optional[str],
    http_status: int,
    upstream_status: Optional[int],
    latency_ms: float,
    redaction_count: int,
    redaction_categories: Optional[str],
    previous_hash: str,
) -> str:
    """Deterministically compute SHA-256 hash using sorted canonical serialization."""
    canonical_payload: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp_utc": timestamp_utc,
        "request_id": request_id,
        "agent_id": agent_id,
        "role": role,
        "tenant_id": tenant_id,
        "action": action,
        "decision": decision,
        "reason_code": reason_code,
        "rule_id": rule_id,
        "http_status": http_status,
        "upstream_status": upstream_status,
        "latency_ms": round(latency_ms, 2),
        "redaction_count": redaction_count,
        "redaction_categories": redaction_categories,
        "previous_hash": previous_hash,
    }
    canonical_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ClosingConnection(sqlite3.Connection):
    """Custom SQLite connection that commits and closes itself when used in a with block."""
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


class AuditLogger:
    """Append-only audit store with tamper-evident hash chaining."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path is None:
            env_path = os.getenv("AUDIT_DB_PATH")
            if env_path:
                self.db_path = Path(env_path)
            else:
                project_root = Path(__file__).resolve().parent.parent.parent
                self.db_path = project_root / "audit_log.db"
        else:
            self.db_path = Path(db_path)

        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize database schema, indexes, and immutability triggers."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        timestamp_utc TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        agent_id TEXT,
                        role TEXT,
                        tenant_id TEXT,
                        action TEXT,
                        decision TEXT NOT NULL,
                        reason_code TEXT NOT NULL,
                        rule_id TEXT,
                        http_status INTEGER NOT NULL,
                        upstream_status INTEGER,
                        latency_ms REAL NOT NULL,
                        redaction_count INTEGER NOT NULL DEFAULT 0,
                        redaction_categories TEXT,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL
                    )
                    """
                )
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_req ON audit_events (request_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events (decision)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_reason ON audit_events (reason_code)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events (tenant_id)")

                # SQLite Database Triggers to enforce append-only immutability
                cursor.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_audit_prevent_update
                    BEFORE UPDATE ON audit_events
                    BEGIN
                        SELECT RAISE(FAIL, 'Audit records are append-only and cannot be updated.');
                    END;
                    """
                )
                cursor.execute(
                    """
                    CREATE TRIGGER IF NOT EXISTS trg_audit_prevent_delete
                    BEFORE DELETE ON audit_events
                    BEGIN
                        SELECT RAISE(FAIL, 'Audit records are append-only and cannot be deleted.');
                    END;
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def log_event(
        self,
        request_id: str,
        decision: AuditDecision,
        reason_code: str,
        http_status: int,
        latency_ms: float,
        agent_id: Optional[str] = None,
        role: Optional[str] = None,
        tenant_id: Optional[str] = None,
        action: Optional[str] = None,
        rule_id: Optional[str] = None,
        upstream_status: Optional[int] = None,
        redaction_count: int = 0,
        redaction_categories: Optional[List[str]] = None,
    ) -> AuditEvent:
        """Atomically record an audit event and link it to the preceding event hash."""
        now_utc = datetime.now(timezone.utc).isoformat()
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        cat_str = ",".join(sorted(redaction_categories)) if redaction_categories else None

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                # Query the latest event hash to maintain the chain
                cursor.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                previous_hash = row["event_hash"] if row else INITIAL_HASH

                event_hash = compute_canonical_event_hash(
                    event_id=event_id,
                    timestamp_utc=now_utc,
                    request_id=request_id,
                    agent_id=agent_id,
                    role=role,
                    tenant_id=tenant_id,
                    action=action,
                    decision=decision.value,
                    reason_code=reason_code,
                    rule_id=rule_id,
                    http_status=http_status,
                    upstream_status=upstream_status,
                    latency_ms=latency_ms,
                    redaction_count=redaction_count,
                    redaction_categories=cat_str,
                    previous_hash=previous_hash,
                )

                cursor.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp_utc, request_id, agent_id, role, tenant_id,
                        action, decision, reason_code, rule_id, http_status, upstream_status,
                        latency_ms, redaction_count, redaction_categories, previous_hash, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        now_utc,
                        request_id,
                        agent_id,
                        role,
                        tenant_id,
                        action,
                        decision.value,
                        reason_code,
                        rule_id,
                        http_status,
                        upstream_status,
                        latency_ms,
                        redaction_count,
                        cat_str,
                        previous_hash,
                        event_hash,
                    ),
                )
                conn.commit()

                return AuditEvent(
                    event_id=event_id,
                    timestamp_utc=now_utc,
                    request_id=request_id,
                    agent_id=agent_id,
                    role=role,
                    tenant_id=tenant_id,
                    action=action,
                    decision=decision.value,
                    reason_code=reason_code,
                    rule_id=rule_id,
                    http_status=http_status,
                    upstream_status=upstream_status,
                    latency_ms=latency_ms,
                    redaction_count=redaction_count,
                    redaction_categories=cat_str,
                    previous_hash=previous_hash,
                    event_hash=event_hash,
                )
            finally:
                conn.close()

    def query_events(
        self,
        limit: int = 50,
        decision: Optional[str] = None,
        reason_code: Optional[str] = None,
        request_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Query bounded audit events with optional filtering."""
        query = "SELECT * FROM audit_events WHERE 1=1"
        params: List[Any] = []

        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if reason_code:
            query += " AND reason_code = ?"
            params.append(reason_code)
        if request_id:
            query += " AND request_id = ?"
            params.append(request_id)
        if action:
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            events: List[AuditEvent] = []
            for r in rows:
                events.append(
                    AuditEvent(
                        event_id=r["event_id"],
                        timestamp_utc=r["timestamp_utc"],
                        request_id=r["request_id"],
                        agent_id=r["agent_id"],
                        role=r["role"],
                        tenant_id=r["tenant_id"],
                        action=r["action"],
                        decision=r["decision"],
                        reason_code=r["reason_code"],
                        rule_id=r["rule_id"],
                        http_status=r["http_status"],
                        upstream_status=r["upstream_status"],
                        latency_ms=r["latency_ms"],
                        redaction_count=r["redaction_count"],
                        redaction_categories=r["redaction_categories"],
                        previous_hash=r["previous_hash"],
                        event_hash=r["event_hash"],
                    )
                )
            return events
        finally:
            conn.close()

    def get_summary_stats(self) -> Dict[str, Any]:
        """Return total event counts, counts by decision, and top reason codes directly via SQL."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM audit_events")
            row = cursor.fetchone()
            total = row[0] if row else 0

            cursor.execute("SELECT decision, COUNT(*) as cnt FROM audit_events GROUP BY decision")
            decisions = {r["decision"]: r["cnt"] for r in cursor.fetchall()}

            cursor.execute(
                "SELECT reason_code, COUNT(*) as cnt FROM audit_events GROUP BY reason_code ORDER BY cnt DESC LIMIT 5"
            )
            top_reasons = {r["reason_code"]: r["cnt"] for r in cursor.fetchall()}

            return {
                "total_events": total,
                "decisions": decisions,
                "top_reasons": top_reasons,
            }
        finally:
            conn.close()

    def verify_chain(self) -> AuditVerificationResult:
        """Traverse the entire audit trail and verify cryptographic hash chain integrity."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_events ORDER BY id ASC")
                rows = cursor.fetchall()

                if not rows:
                    return AuditVerificationResult(is_valid=True, total_events=0)

                expected_prev = INITIAL_HASH
                for idx, r in enumerate(rows):
                    # 1. Verify previous_hash linkage
                    if r["previous_hash"] != expected_prev:
                        return AuditVerificationResult(
                            is_valid=False,
                            total_events=len(rows),
                            tampered_event_id=r["event_id"],
                            tampered_index=idx,
                            error_message=(
                                f"Hash chain broken at event {r['event_id']} (row {idx}): "
                                f"expected previous_hash '{expected_prev}', got '{r['previous_hash']}'"
                            ),
                        )

                    # 2. Recompute canonical hash from stored event attributes
                    computed_hash = compute_canonical_event_hash(
                        event_id=r["event_id"],
                        timestamp_utc=r["timestamp_utc"],
                        request_id=r["request_id"],
                        agent_id=r["agent_id"],
                        role=r["role"],
                        tenant_id=r["tenant_id"],
                        action=r["action"],
                        decision=r["decision"],
                        reason_code=r["reason_code"],
                        rule_id=r["rule_id"],
                        http_status=r["http_status"],
                        upstream_status=r["upstream_status"],
                        latency_ms=r["latency_ms"],
                        redaction_count=r["redaction_count"],
                        redaction_categories=r["redaction_categories"],
                        previous_hash=r["previous_hash"],
                    )

                    if computed_hash != r["event_hash"]:
                        return AuditVerificationResult(
                            is_valid=False,
                            total_events=len(rows),
                            tampered_event_id=r["event_id"],
                            tampered_index=idx,
                            error_message=(
                                f"Content tampering detected at event {r['event_id']} (row {idx}): "
                                f"recomputed hash '{computed_hash}' does not match stored hash '{r['event_hash']}'"
                            ),
                        )

                    expected_prev = r["event_hash"]

                return AuditVerificationResult(is_valid=True, total_events=len(rows))
            finally:
                conn.close()


# Global singleton audit logger
audit_logger = AuditLogger()
