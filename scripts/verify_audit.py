"""Audit Trail Hash Chain Integrity Verifier.

Usage:
    python scripts/verify_audit.py [--db PATH]
    python -m scripts.verify_audit [--db PATH]
"""
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.security.audit import AuditLogger, audit_logger



def verify_audit_trail(custom_db: str | None = None, min_events: int = 0) -> bool:
    logger = AuditLogger(Path(custom_db)) if custom_db else audit_logger
    print("=" * 70)
    print("Agentic API Security Proxy - Audit Chain Integrity Verifier")
    print("=" * 70)
    print(f"Target Database: {logger.db_path}")

    result = logger.verify_chain()

    if not result.is_valid:
        print("\n[CRITICAL FAILURE] Audit chain tampering or corruption detected!")
        print(f" -> Total events inspected: {result.total_events}")
        print(f" -> Tampered Event ID:      {result.tampered_event_id}")
        print(f" -> Row Index:              {result.tampered_index}")
        print(f" -> Detail:                 {result.error_message}")
        print("=" * 70)
        return False

    if result.total_events < min_events:
        print(f"\n[CRITICAL FAILURE] Audit chain has {result.total_events} events, expected at least {min_events}.")
        print("=" * 70)
        return False

    if result.total_events == 0:
        print("\n[NOTICE] Database contains 0 audit events (empty chain).")
        print("=" * 70)
        return True

    print(f"\n[INTEGRITY OK] Cryptographic hash chain is valid across all {result.total_events} events.")
    print(" -> All sequential hashes and canonical payloads match expected signatures.")
    print("=" * 70)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify tamper-evident audit trail hash chain.")
    parser.add_argument("--db", type=str, default=None, help="Optional path to custom audit SQLite DB.")
    parser.add_argument("--min-events", type=int, default=0, help="Minimum number of events expected in the chain.")
    args = parser.parse_args()

    success = verify_audit_trail(custom_db=args.db, min_events=args.min_events)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
