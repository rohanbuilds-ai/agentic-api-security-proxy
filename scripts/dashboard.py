"""Developer Terminal Dashboard for the Agentic API Security Proxy.

Displays service health, audit metrics, recent mediation decisions,
cryptographic hash-chain integrity, and security evaluation results.

Usage:
    python scripts/dashboard.py [--db PATH] [--eval-report PATH] [--watch SECONDS]
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.security.audit import AuditLogger, audit_logger


def check_http_service(url: str, timeout: float = 1.0) -> bool:
    """Probe an HTTP health endpoint without external dependencies."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def load_evaluation_report(report_path: Path) -> Optional[Dict[str, Any]]:
    """Load evaluation metrics JSON if available."""
    if not report_path.exists():
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def render_dashboard(
    logger: AuditLogger,
    eval_report_path: Path,
    proxy_url: str = "http://127.0.0.1:8000/health",
    upstream_url: str = "http://127.0.0.1:8001/health",
) -> None:
    """Render a clean, complete terminal dashboard."""
    # 1. Probe live services
    proxy_live = check_http_service(proxy_url)
    upstream_live = check_http_service(upstream_url)

    # 2. Query audit store
    events = logger.query_events(limit=8)
    summary_stats = logger.get_summary_stats()
    total_audited = summary_stats["total_events"]
    decision_counts = summary_stats["decisions"]
    top_reasons = summary_stats["top_reasons"]

    # 3. Verify hash chain
    chain_status = logger.verify_chain()

    # 4. Load evaluation report
    eval_data = load_evaluation_report(eval_report_path)

    # Clear terminal for fresh display if running in watch mode
    term_width = 100

    print("=" * term_width)
    print(" " * 28 + "AGENTIC API SECURITY PROXY — DASHBOARD")
    print("=" * term_width)

    # Service Health Row
    p_stat = "[ONLINE :8000]" if proxy_live else "[OFFLINE (Local daemon stopped)]"
    u_stat = "[ONLINE :8001]" if upstream_live else "[OFFLINE (Local daemon stopped)]"
    print(f" Proxy Gateway: {p_stat:<35} | Mock Upstream: {u_stat}")
    print(f" Audit Database: {str(logger.db_path):<34} | Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("-" * term_width)

    # Cryptographic Hash Chain Status
    if chain_status.is_valid:
        chain_msg = f"VALID / INTACT ({chain_status.total_events} sequential events verified)"
    else:
        chain_msg = f"TAMPERED / BROKEN at event {chain_status.tampered_event_id} (row {chain_status.tampered_index})"
    print(f" Audit Trail Cryptographic Hash Chain: {chain_msg}")
    print("-" * term_width)

    # Decision Metrics
    print(" AUDIT DECISION TOTALS (Historical Log):")
    print(
        f"   ALLOWED:   {decision_counts.get('ALLOWED', 0):<5} | "
        f"DENIED:    {decision_counts.get('DENIED', 0):<5} | "
        f"BLOCKED:   {decision_counts.get('BLOCKED', 0):<5} | "
        f"SANITIZED: {decision_counts.get('SANITIZED', 0):<5} | "
        f"ERROR:     {decision_counts.get('ERROR', 0):<5} | "
        f"TOTAL:     {total_audited}"
    )

    if top_reasons:
        reasons_str = " | ".join(f"{r}: {c}" for r, c in top_reasons.items())
        print(f"   Top Enforcement Reasons: {reasons_str}")
    print("-" * term_width)

    # Adversarial Evaluation Summary (if available)
    if eval_data and "summary_metrics" in eval_data:
        sm = eval_data["summary_metrics"]
        lm = eval_data.get("latency_metrics_ms", {})
        print(" REPRODUCIBLE ADVERSARIAL EVALUATION METRICS:")
        print(
            f"   Outcome Match Rate:   {sm.get('outcome_match_rate_pct', 0.0)}% ({sm.get('passed_scenarios')}/{sm.get('total_scenarios')} passed)"
            f" | Attack Block Rate:  {sm.get('attack_case_block_rate_pct', 0.0)}%"
        )
        print(
            f"   False Rejection Rate: {sm.get('benign_false_rejection_rate_pct', 0.0)}%"
            f"          | Mean Latency:       {lm.get('mean_latency_ms', 0.0)}ms (p95: {lm.get('p95_latency_ms', 0.0)}ms)"
        )
        print(f"   Evaluation Timestamp: {eval_data.get('evaluation_timestamp_utc')}")
    else:
        print(" REPRODUCIBLE ADVERSARIAL EVALUATION METRICS:")
        print("   No evaluation report found. Run: python scripts/evaluate_security.py")
    print("-" * term_width)

    # Recent Events Table
    print(" RECENT MEDIATION EVENTS (Most Recent 8):")
    headers = ["Time (UTC)", "Event ID", "Request ID", "Role", "Tenant", "Decision", "Reason", "HTTP", "Latency"]
    widths = [19, 14, 18, 15, 13, 9, 20, 5, 8]

    def fmt_row(c: list[str]) -> str:
        return " | ".join(str(val)[:w].ljust(w) for val, w in zip(c, widths))

    print(" " + fmt_row(headers))
    print(" " + "-+-".join("-" * w for w in widths))

    if not events:
        print("  (No recent audit events in target database)")
    else:
        for e in events:
            time_str = e.timestamp_utc[:19].replace("T", " ")
            row = [
                time_str,
                e.event_id,
                e.request_id,
                e.role or "-",
                e.tenant_id or "-",
                e.decision,
                e.reason_code,
                str(e.http_status),
                f"{e.latency_ms:.1f}ms",
            ]
            print(" " + fmt_row(row))

    print("=" * term_width)


def main() -> None:
    parser = argparse.ArgumentParser(description="Terminal dashboard for Agentic API Security Proxy.")
    parser.add_argument("--db", type=str, default=None, help="Custom audit SQLite database path.")
    parser.add_argument("--eval-report", type=str, default="evaluation_report.json", help="Path to evaluation report JSON.")
    parser.add_argument("--watch", type=int, default=0, help="Refresh interval in seconds (0 to run once).")
    args = parser.parse_args()

    target_logger = AuditLogger(Path(args.db)) if args.db else audit_logger
    report_file = Path(args.eval_report)

    if args.watch > 0:
        try:
            while True:
                # Clear terminal screen cleanly on Windows/Linux
                os.system("cls" if os.name == "nt" else "clear")
                render_dashboard(target_logger, report_file)
                print(f"\n[Dashboard refreshing every {args.watch}s. Press Ctrl+C to exit.]")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nExited dashboard watch mode.")
            sys.exit(0)
    else:
        render_dashboard(target_logger, report_file)


if __name__ == "__main__":
    main()
