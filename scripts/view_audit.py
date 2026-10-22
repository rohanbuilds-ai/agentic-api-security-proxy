"""Audit Event Log Viewer and Filter CLI.

Usage:
    python scripts/view_audit.py [--limit 20] [--decision ALLOWED] [--reason ACTION_SUCCESS]
                                [--request-id REQ_ID] [--action get_order_details] [--db PATH]
"""
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.security.audit import AuditLogger, audit_logger



def format_table_row(cols: list[str], widths: list[int]) -> str:
    parts = []
    for col, width in zip(cols, widths):
        parts.append(str(col)[:width].ljust(width))
    return " | ".join(parts)


def view_audit_log(
    limit: int = 20,
    decision: str | None = None,
    reason: str | None = None,
    request_id: str | None = None,
    action: str | None = None,
    db_path: str | None = None,
) -> None:
    logger = AuditLogger(Path(db_path)) if db_path else audit_logger
    events = logger.query_events(
        limit=limit,
        decision=decision,
        reason_code=reason,
        request_id=request_id,
        action=action,
    )

    print("=" * 110)
    print(f"Agentic API Security Proxy - Audit Event Trail ({logger.db_path})")
    print("=" * 110)
    print(f"Filters applied: decision={decision}, reason={reason}, request_id={request_id}, action={action}, limit={limit}")
    print(f"Total matching records returned: {len(events)}\n")

    if not events:
        print("No audit events match the specified criteria.")
        print("=" * 110)
        return

    headers = ["Timestamp (UTC)", "Event ID", "Request ID", "Role", "Tenant", "Decision", "Reason", "HTTP", "Latency"]
    widths = [20, 16, 18, 16, 14, 10, 20, 5, 8]

    header_line = format_table_row(headers, widths)
    divider_line = "-+-".join("-" * w for w in widths)

    print(header_line)
    print(divider_line)

    for e in events:
        timestamp_short = e.timestamp_utc[:19].replace("T", " ")
        row = [
            timestamp_short,
            e.event_id,
            e.request_id,
            e.role or "-",
            e.tenant_id or "-",
            e.decision,
            e.reason_code,
            str(e.http_status),
            f"{e.latency_ms:.1f}ms",
        ]
        print(format_table_row(row, widths))

    print("=" * 110)


def main() -> None:
    parser = argparse.ArgumentParser(description="Query and view audit event logs.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of records to display (default: 20).")
    parser.add_argument("--decision", type=str, default=None, help="Filter by decision (ALLOWED, DENIED, BLOCKED, SANITIZED, ERROR).")
    parser.add_argument("--reason", type=str, default=None, help="Filter by reason code (e.g., ACTION_SUCCESS, ERR_INPUT_POLICY).")
    parser.add_argument("--request-id", type=str, default=None, help="Filter by exact request ID.")
    parser.add_argument("--action", type=str, default=None, help="Filter by action name.")
    parser.add_argument("--db", type=str, default=None, help="Optional path to custom audit SQLite DB.")
    args = parser.parse_args()

    view_audit_log(
        limit=args.limit,
        decision=args.decision,
        reason=args.reason,
        request_id=args.request_id,
        action=args.action,
        db_path=args.db,
    )


if __name__ == "__main__":
    main()
